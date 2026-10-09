// Package client is responsible for creating HTTP client and request.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// Transport is the interface that's used for sending/receiving HTTP requests.
type Transport interface {
	http.RoundTripper

	// Conn returns the last established connection using this transport.
	Conn() (conn net.Conn)
}

// transport is a wrapper over regular http.RoundTripper that is used to add
// additional logic on top of RoundTrip.
type transport struct {
	d    *clientDialer
	base http.RoundTripper
}

// type check
var _ Transport = (*transport)(nil)

// Conn returns the last established connection using this transport.
func (t *transport) Conn() (conn net.Conn) {
	return t.d.currentConn()
}

// RoundTrip implements the http.RoundTripper interface for *transport.
//
// TODO(ameshkov): dial explicitly here and then check negotiation proto.
// This approach will make it easier to handle protocols negotiation.
func (t *transport) RoundTrip(r *http.Request) (resp *http.Response, err error) {
	var requestConn *roundTripConnSlot
	r, requestConn = withRoundTripConnContext(r)
	strictProfileCheck := t.d.cfg.TLSProfileStrict
	var cancelProfileCheck context.CancelFunc
	r, cancelProfileCheck = withTLSProfileCheckContextMode(
		r, t.d.cfg.TLSProfileCheck || t.d.cfg.OutputJSON || strictProfileCheck,
		t.d.cfg.TLSProfileDocument, strictProfileCheck,
	)
	if cancelProfileCheck != nil {
		defer cancelProfileCheck()
	}
	r = r.WithContext(context.WithValue(r.Context(), connectionRequestContextKey{}, r.Context()))
	resp, err = t.base.RoundTrip(r)
	if strictProfileCheck && hasReusedTLSProfileCheck(r.Context(), "target", "gateway") {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, utlsengine.NewProfileCheckError("REUSED_CONNECTION", err)
	}
	if err != nil {
		return nil, err
	}
	if resp.Request == nil {
		resp.Request = r
	}

	// Make sure that resp.TLS field is set regardless of what protocol was
	// used.  This is important for ECH-enabled connections as crypto/tls is
	// not used there and the regular http.Transport will not set the TLS field.
	type tlsConnectionStater interface {
		ConnectionState() tls.ConnectionState
	}
	if c, ok := requestConn.get().(tlsConnectionStater); ok {
		state := c.ConnectionState()
		resp.TLS = &state
	}

	return resp, err
}

// NewTransport creates a new http.RoundTripper that will be used for making
// the request.
func NewTransport(cfg *config.Config, out *output.Output) (rt Transport, err error) {
	// If OHTTP is enabled, use the oblivious HTTP transport.
	if cfg.OHTTPGatewayURL != nil && cfg.OHTTPKeysURL != nil {
		return newObliviousHTTPTransport(cfg, out)
	}

	hostname := cfg.RequestURL.Hostname()
	d, err := newDialer(hostname, cfg, out)
	if err != nil {
		return nil, err
	}

	bt, err := createHTTPTransport(d, cfg)
	if err != nil {
		return nil, err
	}

	return &transport{d: d, base: bt}, nil
}

// createHTTPTransport creates http.RoundTripper that will be used by the
// *http.Client. Depending on the configuration it may create an H1, H2 or H3
// transport.
func createHTTPTransport(
	d *clientDialer,
	cfg *config.Config,
) (rt http.RoundTripper, err error) {
	if cfg.ForceHTTP3 {
		return createH3Transport(d)
	}

	if cfg.ForceHTTP2 {
		return createH2Transport(d)
	}

	return createH12Transport(d)
}

// createH3Transport creates an http.RoundTripper to be used in HTTP/3 client.
func createH3Transport(d *clientDialer) (rt http.RoundTripper, err error) {
	parameters := d.cfg.QUICTransport
	var quicConfig *quic.Config
	if parameters != (config.QUICTransport{}) || len(d.cfg.QUICTransportParameterOrder) != 0 {
		quicConfig = &quic.Config{
			InitialStreamReceiveWindow:        parameters.InitialStreamReceiveWindow,
			InitialMaxStreamDataBidiLocal:     parameters.InitialMaxStreamDataBidiLocal,
			InitialMaxStreamDataBidiLocalSet:  parameters.InitialMaxStreamDataBidiLocalSet,
			InitialMaxStreamDataBidiRemote:    parameters.InitialMaxStreamDataBidiRemote,
			InitialMaxStreamDataBidiRemoteSet: parameters.InitialMaxStreamDataBidiRemoteSet,
			InitialMaxStreamDataUni:           parameters.InitialMaxStreamDataUni,
			InitialMaxStreamDataUniSet:        parameters.InitialMaxStreamDataUniSet,
			InitialConnectionReceiveWindow:    parameters.InitialConnectionReceiveWindow,
			MaxIdleTimeout:                    parameters.MaxIdleTimeout,
			MaxIncomingStreams:                parameters.MaxIncomingStreams,
			MaxIncomingUniStreams:             parameters.MaxIncomingUniStreams,
			EnableDatagrams:                   d.cfg.HTTP3Datagrams,
			InitialPacketSize:                 parameters.InitialPacketSize,
			ActiveConnectionIDLimit:           parameters.ActiveConnectionIDLimit,
			AckDelayExponent:                  parameters.AckDelayExponent,
			AckDelayExponentSet:               parameters.AckDelayExponentSet,
			MaxAckDelay:                       parameters.MaxAckDelay,
			MaxAckDelaySet:                    parameters.MaxAckDelaySet,
			MaxUDPPayloadSize:                 parameters.MaxUDPPayloadSize,
			EnableStreamResetPartialDelivery:  parameters.EnableResetStreamAt,
			DisableActiveMigration:            parameters.DisableActiveMigration,
			TransportParameterOrder:           d.cfg.QUICTransportParameterOrder,
		}
		switch parameters.Version {
		case "1":
			quicConfig.Versions = []quic.Version{quic.Version1}
		case "2":
			quicConfig.Versions = []quic.Version{quic.Version2}
		}
	}
	return &http3.Transport{
		DisableCompression: true,
		Dial:               d.DialQUIC,
		AdditionalSettings: d.cfg.HTTP3AdditionalSettings,
		EnableDatagrams:    d.cfg.HTTP3Datagrams,
		QUICConfig:         quicConfig,
	}, nil
}

// h2Transport is an http.RoundTripper implementation that forcibly use
// http2.Transport.
type h2Transport struct {
	d *clientDialer
}

// type check
var _ http.RoundTripper = (*h2Transport)(nil)

// RoundTrip implements the http.RoundTripper for *h2Transport.
func (t *h2Transport) RoundTrip(r *http.Request) (resp *http.Response, err error) {
	r = withTLSProfileCheckContext(
		r,
		t.d.cfg.TLSProfileCheck || t.d.cfg.TLSProfileStrict || t.d.cfg.OutputJSON,
		t.d.cfg.TLSProfileDocument,
	)
	if (len(t.d.cfg.HTTP2PseudoOrder) != 0 || len(t.d.cfg.HTTP2HeaderOrder) != 0) &&
		(r.Method == http.MethodConnect || len(r.Trailer) != 0) {
		return nil, fmt.Errorf("HTTP/2 header ordering does not support CONNECT or request trailers")
	}
	port := r.URL.Port()
	if port == "" {
		switch r.URL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	addr := net.JoinHostPort(r.URL.Hostname(), port)
	conn, err := t.d.DialTLSContext(r.Context(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("HTTP/2 requires TLS ALPN %q: %w", "h2", err)
	}
	setRoundTripConn(r.Context(), conn)
	stateful, ok := conn.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("HTTP/2 requires a TLS connection with ALPN h2 support")
	}
	if protocol := stateful.ConnectionState().NegotiatedProtocol; protocol != "h2" {
		_ = conn.Close()
		return nil, fmt.Errorf("HTTP/2 requires negotiated ALPN %q, got %q", "h2", protocol)
	}
	conn = applyHTTP2ConnectionProfile(conn, t.d.cfg)

	settings := t.d.cfg.HTTP2Settings
	tr := &http2.Transport{
		DisableCompression:        true,
		MaxDecoderHeaderTableSize: settings.HeaderTableSize,
		MaxReadFrameSize:          settings.MaxFrameSize,
		MaxHeaderListSize:         settings.MaxHeaderListSize,
	}
	clientConn, err := tr.NewClientConn(conn)
	if err != nil {
		return nil, err
	}

	resp, err = clientConn.RoundTrip(r)
	if err == nil && resp.Request == nil {
		resp.Request = r
	}
	return resp, err
}

type (
	reuseTraceContextKey    struct{}
	tlsLegContextKey        struct{}
	roundTripConnContextKey struct{}
)

type roundTripConnSlot struct {
	mu   sync.RWMutex
	conn net.Conn
}

func (s *roundTripConnSlot) set(conn net.Conn) {
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
}

func (s *roundTripConnSlot) get() net.Conn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.conn
}

func withRoundTripConnContext(r *http.Request) (*http.Request, *roundTripConnSlot) {
	slot := &roundTripConnSlot{}
	ctx := context.WithValue(r.Context(), roundTripConnContextKey{}, slot)
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		slot.set(info.Conn)
	}}
	ctx = httptrace.WithClientTrace(ctx, trace)
	return r.Clone(ctx), slot
}

func setRoundTripConn(ctx context.Context, conn net.Conn) {
	if slot, ok := ctx.Value(roundTripConnContextKey{}).(*roundTripConnSlot); ok {
		slot.set(conn)
	}
}

func withTLSLegContext(ctx context.Context, leg string) context.Context {
	return context.WithValue(ctx, tlsLegContextKey{}, leg)
}

func tlsLegFromContext(ctx context.Context) string {
	if leg, ok := ctx.Value(tlsLegContextKey{}).(string); ok && leg != "" {
		return leg
	}
	return "target"
}

func withTLSProfileCheckContext(r *http.Request, enabled bool, profile *utlsengine.ClientProfile) *http.Request {
	request, _ := withTLSProfileCheckContextMode(r, enabled, profile, false)
	return request
}

func withTLSProfileCheckContextMode(
	r *http.Request,
	enabled bool,
	profile *utlsengine.ClientProfile,
	strict bool,
) (*http.Request, context.CancelFunc) {
	if !enabled {
		return r, nil
	}
	ctx := r.Context()
	var cancel context.CancelFunc
	if strict {
		ctx, cancel = context.WithCancel(ctx)
	}
	if _, ok := utlsengine.ProfileCheckReports(ctx); !ok {
		ctx, _ = utlsengine.NewProfileCheckContext(ctx)
	}
	if ctx.Value(reuseTraceContextKey{}) == nil {
		ctx = context.WithValue(ctx, reuseTraceContextKey{}, true)
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			if !info.Reused {
				return
			}
			connectionID, attempt, helloIndex := "", 1, 1
			if reported, ok := info.Conn.(interface {
				reportMetadata() (string, int, int)
			}); ok {
				connectionID, attempt, helloIndex = reported.reportMetadata()
			}
			clientProfile := utlsengine.ClientProfile{}
			if profile != nil {
				clientProfile = *profile
			}
			check := utlsengine.ProfileCheckResult{Status: "REUSED_CONNECTION"}
			report := utlsengine.NewConnectionReportForLeg(
				clientProfile, check, connectionID, tlsLegFromContext(ctx), attempt, helloIndex,
			)
			utlsengine.RecordProfileCheck(ctx, report)
		}}
		ctx = httptrace.WithClientTrace(ctx, trace)
	}
	if cancel != nil {
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			if info.Reused {
				cancel()
			}
		}})
	}
	return r.Clone(ctx), cancel
}

func hasReusedTLSProfileCheck(ctx context.Context, legs ...string) bool {
	reports, ok := utlsengine.ProfileCheckReports(ctx)
	if !ok {
		return false
	}
	for _, report := range reports {
		if report.CaptureStatus != "REUSED_CONNECTION" {
			continue
		}
		for _, leg := range legs {
			if report.Leg == leg {
				return true
			}
		}
	}
	return false
}

// createH2Transport creates a http.RoundTripper to be used specifically with
// HTTP/2.  This option is required when using --ech option as in this case
// we don't use *tls.Conn and it does not work well with the regular transport.
func createH2Transport(d *clientDialer) (rt http.RoundTripper, err error) {
	return &h2Transport{d: d}, nil
}

// createH12Transport creates a http.RoundTripper to be used in HTTP/1.1 or
// HTTP/2 client.
func createH12Transport(d *clientDialer) (rt http.RoundTripper, err error) {
	tr := &http.Transport{
		DisableCompression: true,
		DisableKeepAlives:  true,
		DialContext:        d.DialContext,
		DialTLSContext:     d.DialTLSContext,
	}
	if d.cfg.ForceHTTP11 && (len(d.cfg.OrderedHeaders) > 0 || d.cfg.RequestTarget != "") {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, dialErr := d.DialContext(ctx, network, addr)
			if dialErr != nil {
				return nil, dialErr
			}
			return &orderedHeaderConn{
				Conn:          conn,
				headers:       d.cfg.OrderedHeaders,
				requestTarget: d.cfg.RequestTarget,
			}, nil
		}
		tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, dialErr := d.DialTLSContext(ctx, network, addr)
			if dialErr != nil {
				return nil, dialErr
			}
			return &orderedHeaderConn{
				Conn:          conn,
				headers:       d.cfg.OrderedHeaders,
				requestTarget: d.cfg.RequestTarget,
			}, nil
		}
	}

	// Enable HTTP/2 support explicitly.
	_ = http2.ConfigureTransport(tr)

	return tr, nil
}

// orderedHeaderConn delays only the initial request headers so they can be
// written in the exact user-specified order. The request body is forwarded
// without buffering.
type orderedHeaderConn struct {
	net.Conn
	headers       []string
	requestTarget string
	pending       []byte
	done          bool
}

func (c *orderedHeaderConn) Write(p []byte) (int, error) {
	if bytes.HasPrefix(p, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
		return 0, fmt.Errorf("ordered request headers require HTTP/1.1; HTTP/2 was selected")
	}
	if stateful, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok &&
		stateful.ConnectionState().NegotiatedProtocol == "h2" {
		return 0, fmt.Errorf("ordered request headers require HTTP/1.1; server negotiated HTTP/2")
	}
	if c.done {
		return c.Conn.Write(p)
	}
	separator := []byte("\r\n\r\n")
	index := bytes.Index(p, separator)
	if index >= 0 {
		header := make([]byte, 0, len(c.pending)+index+len(separator))
		header = append(header, c.pending...)
		header = append(header, p[:index+len(separator)]...)
		rewritten, rewriteErr := rewriteHTTP11HeaderBlock(header, c.headers, c.requestTarget)
		if rewriteErr != nil {
			return 0, rewriteErr
		}
		if err := writeConnAll(c.Conn, rewritten); err != nil {
			c.pending = nil
			return 0, err
		}
		if err := writeConnAll(c.Conn, p[index+len(separator):]); err != nil {
			c.pending = nil
			return 0, err
		}
		c.pending = nil
		c.done = true
		return len(p), nil
	}
	lookahead := len(separator) - 1
	if len(p) < lookahead {
		lookahead = len(p)
	}
	combined := make([]byte, 0, len(c.pending)+lookahead)
	combined = append(combined, c.pending...)
	combined = append(combined, p[:lookahead]...)
	index = bytes.Index(combined, separator)
	if index < 0 {
		c.pending = append(c.pending, p...)
		return len(p), nil
	}
	end := index + len(separator)
	headerBytes := end - len(c.pending)
	header := make([]byte, 0, end)
	header = append(header, c.pending...)
	header = append(header, p[:headerBytes]...)
	rewritten, rewriteErr := rewriteHTTP11HeaderBlock(header, c.headers, c.requestTarget)
	if rewriteErr != nil {
		return 0, rewriteErr
	}
	if err := writeConnAll(c.Conn, rewritten); err != nil {
		c.pending = nil
		return 0, err
	}
	if err := writeConnAll(c.Conn, p[headerBytes:]); err != nil {
		c.pending = nil
		return 0, err
	}
	c.pending = nil
	c.done = true
	return len(p), nil
}

func rewriteHTTP11HeaderBlock(block []byte, ordered []string, target string) ([]byte, error) {
	block = reorderRequestHeaderBlock(block, ordered)
	if target == "" {
		return block, nil
	}
	lineEnd := bytes.Index(block, []byte("\r\n"))
	if lineEnd < 0 {
		return nil, fmt.Errorf("invalid HTTP/1.1 request line")
	}
	methodEnd := bytes.IndexByte(block[:lineEnd], ' ')
	versionStart := bytes.LastIndex(block[:lineEnd], []byte(" HTTP/1.1"))
	if methodEnd < 0 || versionStart <= methodEnd {
		return nil, fmt.Errorf("invalid HTTP/1.1 request line")
	}
	rewritten := make([]byte, 0, len(block)+len(target)-(versionStart-methodEnd-1))
	rewritten = append(rewritten, block[:methodEnd+1]...)
	rewritten = append(rewritten, target...)
	rewritten = append(rewritten, block[versionStart:]...)
	return rewritten, nil
}

func reorderRequestHeaderBlock(block []byte, ordered []string) []byte {
	lines := bytes.Split(block[:len(block)-4], []byte("\r\n"))
	if len(lines) < 1 {
		return block
	}
	fields := lines[1:]
	used := make([]bool, len(fields))
	out := make([]byte, 0, len(block))
	out = append(out, lines[0]...)
	out = append(out, '\r', '\n')
	for _, requested := range ordered {
		colon := strings.IndexByte(requested, ':')
		if colon <= 0 {
			continue
		}
		name := requested[:colon]
		value := strings.TrimSpace(requested[colon+1:])
		for i, field := range fields {
			if used[i] {
				continue
			}
			fieldColon := bytes.IndexByte(field, ':')
			if fieldColon <= 0 || !strings.EqualFold(string(field[:fieldColon]), name) ||
				strings.TrimSpace(string(field[fieldColon+1:])) != value {
				continue
			}
			out = append(out, name...)
			out = append(out, field[fieldColon:]...)
			out = append(out, '\r', '\n')
			used[i] = true
			break
		}
	}
	for i, field := range fields {
		if !used[i] {
			out = append(out, field...)
			out = append(out, '\r', '\n')
		}
	}
	out = append(out, '\r', '\n')
	return out
}

func writeConnAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// getMethod returns HTTP method depending on the arguments.
func getMethod(cfg *config.Config) (method string) {
	if cfg.Method != "" {
		method = cfg.Method
	} else if cfg.Head {
		method = http.MethodHead
	} else if cfg.Data != "" || cfg.DataBinary != "" {
		method = http.MethodPost
	} else {
		method = http.MethodGet
	}

	return method
}
