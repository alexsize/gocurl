package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ameshkov/gocurl/internal/client/cfcrypto"
	"github.com/ameshkov/gocurl/internal/client/connectto"
	"github.com/ameshkov/gocurl/internal/client/dialer"
	"github.com/ameshkov/gocurl/internal/client/proxy"
	"github.com/ameshkov/gocurl/internal/client/splittls"
	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/ameshkov/gocurl/internal/client/websocket"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/ameshkov/gocurl/internal/resolve"
	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
)

// clientDialer is a structure that implements additional logic on top of the
// regular dial depending on the configuration. It can dial over a proxy,
// apply --connect-to logic or split TLS client hello when required.
type clientDialer struct {
	cfg         *config.Config
	out         *output.Output
	tlsConfig   *tls.Config
	tlsProfile  *utlsengine.Profile
	resolver    *resolve.Resolver
	dial        dialer.DialFunc
	dialContext dialer.ContextDialFunc

	connMu sync.RWMutex

	// conn is the last established connection via the dialer.  It can be a TLS
	// connection if DialTLSContext was used.
	//
	// TODO(ameshkov): handle QUIC connections.
	conn net.Conn
}

type quicPacketConnRecorder struct {
	net.PacketConn
	firstWrite chan struct{}
	writeOnce  sync.Once
}

func newQUICPacketConnRecorder(conn net.PacketConn) *quicPacketConnRecorder {
	return &quicPacketConnRecorder{PacketConn: conn, firstWrite: make(chan struct{})}
}

func (c *quicPacketConnRecorder) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if n == len(p) && err == nil {
		c.writeOnce.Do(func() { close(c.firstWrite) })
	}
	return n, err
}

func (c *quicPacketConnRecorder) SetReadBuffer(size int) error {
	conn, ok := c.PacketConn.(interface{ SetReadBuffer(int) error })
	if !ok {
		return fmt.Errorf("QUIC packet connection does not support setting the read buffer")
	}
	return conn.SetReadBuffer(size)
}

func (c *quicPacketConnRecorder) SetWriteBuffer(size int) error {
	conn, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error })
	if !ok {
		return fmt.Errorf("QUIC packet connection does not support setting the write buffer")
	}
	return conn.SetWriteBuffer(size)
}

// newDialer creates a new instance of the clientDialer.
func newDialer(hostname string, cfg *config.Config, out *output.Output) (d *clientDialer, err error) {
	for _, field := range cfg.TLSProfileUnsupported {
		out.Info("TLS profile field %q is UNSUPPORTED by this uTLS adapter", field)
	}
	resolver, err := resolve.NewResolver(cfg, out)
	if err != nil {
		return nil, err
	}

	dial, err := createDialFunc(resolver, cfg, out)
	if err != nil {
		return nil, err
	}

	return &clientDialer{
		cfg:         cfg,
		out:         out,
		tlsConfig:   createTLSConfig(hostname, cfg, out),
		tlsProfile:  cfg.TLSProfile,
		resolver:    resolver,
		dial:        dial.Dial,
		dialContext: dial,
	}, nil
}

// DialTLSContext establishes a new TLS connection to the specified address.
func (d *clientDialer) DialTLSContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	ctx, cancel := connectionPhaseContext(ctx, d.cfg.ConnectTimeout)
	defer cancel()
	d.out.Debug("Connecting to %s over TLS", addr)
	d.setConn(nil)
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	observation := d.newTLSObservation(ctx)
	reportingEnabled := observation.reportingEnabled
	conn, err := d.openConnection(ctx, network, addr)
	err = connectionPhaseError(ctx, err)
	if reportingEnabled && d.cfg.ProxyURL != nil && d.cfg.ProxyURL.Scheme == "https" {
		d.recordProxyTLSObservation(ctx, conn, err, observation.attempt)
	}
	if err != nil {
		return nil, d.reportTLSOpenFailure(ctx, conn, err, observation)
	}
	stopWatching := watchConnectionContext(ctx, conn)
	defer func() {
		stopWatching()
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			c = nil
			_ = conn.Close()
			d.setConn(nil)
		}
	}()

	tlsConn, helloCount, err := d.handshakeDialedTLS(ctx, conn, observation)
	if err == nil && reportingEnabled {
		tlsConn = &reportedConn{
			Conn:         tlsConn,
			connectionID: observation.connectionID,
			attempt:      observation.attempt,
			helloIndex:   helloCount,
		}
	}

	if err != nil {
		d.setConn(nil)
		return nil, err
	}
	d.setConn(tlsConn)
	return tlsConn, nil
}

func (d *clientDialer) setConn(conn net.Conn) {
	d.connMu.Lock()
	d.conn = conn
	d.connMu.Unlock()
}

func (d *clientDialer) currentConn() net.Conn {
	d.connMu.RLock()
	defer d.connMu.RUnlock()
	return d.conn
}

func (d *clientDialer) recordConnectionChecksForLeg(
	ctx context.Context,
	profile utlsengine.ClientProfile,
	checks []utlsengine.ProfileCheckResult,
	connectionID, leg string,
	attempt int,
	logChecks bool,
) (strictFailure string) {
	for i, check := range checks {
		utlsengine.RecordProfileCheck(
			ctx,
			utlsengine.NewConnectionReportForLeg(profile, check, connectionID, leg, attempt, i+1),
		)
		if logChecks {
			d.logProfileCheck(check)
		}
		if strictFailure == "" && check.Status != "MATCH" {
			strictFailure = check.Status
		}
	}
	return strictFailure
}

func rejectStrictProfileCheck(conn net.Conn, strict bool, status string) error {
	if !strict || status == "" || status == "MATCH" {
		return nil
	}
	if conn != nil {
		_ = conn.Close()
	}
	return utlsengine.NewProfileCheckError(status, nil)
}

func (d *clientDialer) recordProxyTLSObservation(ctx context.Context, conn net.Conn, dialErr error, attempt int) {
	type proxyObservationProvider interface {
		ProxyTLSObservations() []utlsengine.ProfileCheckResult
	}
	var checks []utlsengine.ProfileCheckResult
	if conn != nil {
		if provider, ok := conn.(proxyObservationProvider); ok {
			checks = provider.ProxyTLSObservations()
		}
	}
	if dialErr != nil {
		var provider proxyObservationProvider
		if errors.As(dialErr, &provider) {
			checks = provider.ProxyTLSObservations()
		}
	}
	if len(checks) == 0 {
		check := utlsengine.ProfileCheckResult{Status: "NOT_OBSERVED", Error: "HTTPS proxy TLS capture is unavailable"}
		if dialErr != nil {
			check.Error = dialErr.Error()
		}
		checks = []utlsengine.ProfileCheckResult{check}
	}
	if dialErr != nil {
		for i := range checks {
			if checks[i].Error == "" {
				checks[i].Error = dialErr.Error()
			}
		}
	}
	profile := utlsengine.ClientProfile{}
	if d.cfg != nil && d.cfg.ProxyTLSProfileDocument != nil {
		profile = *d.cfg.ProxyTLSProfileDocument
	}
	connectionID := utlsengine.NewConnectionID()
	if d.cfg != nil && (d.cfg.ProxyTLSProfileCheck || d.cfg.ProxyTLSProfileStrict) {
		for _, check := range checks {
			d.logProfileCheck(check)
		}
	}
	d.recordConnectionChecksForLeg(ctx, profile, checks, connectionID, "proxy", attempt, false)
}

func (d *clientDialer) logProfileCheck(check utlsengine.ProfileCheckResult) {
	encoded, err := json.Marshal(check)
	if err != nil {
		d.out.Info("TLS_PROFILE_CHECK status=%s error=%v", check.Status, err)
		return
	}
	d.out.Info("TLS_PROFILE_CHECK %s", encoded)
}

type reportedConn struct {
	net.Conn
	connectionID string
	attempt      int
	helloIndex   int
}

func (c *reportedConn) reportMetadata() (connectionID string, attempt, helloIndex int) {
	return c.connectionID, c.attempt, c.helloIndex
}

func (c *reportedConn) ConnectionState() tls.ConnectionState {
	switch conn := c.Conn.(type) {
	case interface{ ConnectionState() tls.ConnectionState }:
		return conn.ConnectionState()
	case interface{ ConnectionState() utls.ConnectionState }:
		state := conn.ConnectionState()
		return tls.ConnectionState{
			Version:                     state.Version,
			HandshakeComplete:           state.HandshakeComplete,
			DidResume:                   state.DidResume,
			CipherSuite:                 state.CipherSuite,
			NegotiatedProtocol:          state.NegotiatedProtocol,
			NegotiatedProtocolIsMutual:  true,
			ServerName:                  state.ServerName,
			PeerCertificates:            state.PeerCertificates,
			VerifiedChains:              state.VerifiedChains,
			SignedCertificateTimestamps: state.SignedCertificateTimestamps,
			OCSPResponse:                state.OCSPResponse,
			TLSUnique:                   state.TLSUnique,
			ECHAccepted:                 state.ECHAccepted,
		}
	}
	return tls.ConnectionState{}
}

// DialContext implements proxy.ContextDialer for *clientDialer.
func (d *clientDialer) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	ctx, cancel := connectionPhaseContext(ctx, d.cfg.ConnectTimeout)
	defer cancel()
	d.out.Debug("Connecting to %s", addr)

	conn, err := d.openConnection(ctx, network, addr)
	err = connectionPhaseError(ctx, err)
	if err != nil && conn != nil {
		_ = conn.Close()
		conn = nil
	}
	d.setConn(conn)
	return conn, err
}

// DialQUIC establishes a new QUIC connection and is supposed to be used by
// http3.Transport.
func (d *clientDialer) DialQUIC(
	ctx context.Context,
	addr string,
	_ *tls.Config,
	cfg *quic.Config,
) (c *quic.Conn, err error) {
	ctx, cancel := connectionPhaseContext(ctx, d.cfg.ConnectTimeout)
	defer cancel()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	observation := d.newQUICObservation(ctx)
	quicConfig, clientHelloCh := captureQUICClientHellos(cfg, observation.reportingEnabled)
	conn, err := d.openConnection(ctx, "udp", addr)
	err = connectionPhaseError(ctx, err)
	defer func() {
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			if c != nil {
				_ = c.CloseWithError(0, "connection establishment failed")
				c = nil
			}
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	if err != nil {
		d.recordQUICOpenFailure(ctx, err, observation)
		return nil, err
	}
	uConn, udpAddr, err := quicPacketConnection(conn, addr)
	if err != nil {
		d.recordQUICOpenFailure(ctx, err, observation)
		return nil, err
	}
	packetConn := newQUICPacketConnRecorder(uConn)
	quicConn, err := d.dialEarlyQUIC(ctx, packetConn, udpAddr, quicConfig)
	if quicConn != nil {
		go func() {
			<-quicConn.Context().Done()
			_ = conn.Close()
		}()
	}
	err = waitQUICHandshake(ctx, quicConn, err)
	if observation.reportingEnabled {
		hellos := drainQUICClientHellos(clientHelloCh)
		packetSent := len(hellos) > 0 && waitQUICFirstWrite(ctx, quicConn, packetConn.firstWrite)
		if strictErr := d.reportQUICHandshake(ctx, quicConn, hellos, packetSent, err, observation); strictErr != nil {
			return nil, strictErr
		}
	}
	return quicConn, err
}

func (d *clientDialer) recordQUICClientHello(
	ctx context.Context,
	profile utlsengine.ClientProfile,
	hello []byte,
	packetSent bool,
	connectionErr error,
	connectionID string,
	attempt int,
	helloIndex int,
	profileCheckEnabled bool,
	reportingEnabled bool,
) utlsengine.ProfileCheckResult {
	if !reportingEnabled {
		return utlsengine.ProfileCheckResult{}
	}
	check := utlsengine.ProfileCheckResult{Status: "NOT_OBSERVED", Expected: profile.Expected}
	if connectionErr != nil {
		check.Status = "CONNECTION_ERROR"
		check.Error = connectionErr.Error()
	} else if len(hello) == 0 {
		check.Status = "INCOMPLETE"
		check.Error = "QUIC ClientHello was not observed before the connection ended"
	} else if !packetSent {
		check.Status = "INCOMPLETE"
		check.Error = "QUIC Initial packet containing the ClientHello was not written"
	} else {
		actual, fingerprintErr := utlsengine.FingerprintClientHello(hello)
		if fingerprintErr != nil {
			check.Status = "INCOMPLETE"
			check.Error = fingerprintErr.Error()
		} else if profileCheckEnabled {
			if d.cfg.TLSProfileDocument == nil {
				check.Status = "UNSUPPORTED"
				check.Error = "QUIC TLS profile expectations are unavailable"
			} else {
				check = utlsengine.CheckClientProfile(profile, actual)
			}
		} else {
			check.Status = "OBSERVED"
			check.Actual = actual
		}
	}
	if profileCheckEnabled {
		d.logProfileCheck(check)
	}
	utlsengine.RecordProfileCheck(ctx, utlsengine.NewConnectionReportForLeg(
		profile, check, connectionID, tlsLegFromContext(ctx), attempt, helloIndex,
	))
	return check
}

// handshakeTLS attempts to establish a TLS connection.
func (d *clientDialer) handshakeTLS(conn net.Conn) (tlsConn net.Conn, err error) {
	tlsClient := tls.Client(conn, d.tlsConfig)
	err = tlsClient.Handshake()
	if err != nil {
		return nil, err
	}

	return tlsClient, nil
}

// handshakeCTLS attempts to establish a TLS connection using Cloudflare's fork
// of crypto/tls.  This is necessary to enable some features missing from the
// standard library like ECH or post-quantum cryptography.
func (d *clientDialer) handshakeCTLS(ctx context.Context, conn net.Conn) (tlsConn net.Conn, err error) {
	return cfcrypto.HandshakeContext(ctx, conn, d.tlsConfig, d.resolver, d.cfg, d.out)
}

// createDialFunc creates dialFunc that implements all the logic configured by
// cfg.
func createDialFunc(
	resolver *resolve.Resolver,
	cfg *config.Config,
	out *output.Output,
) (dial dialer.ContextDialFunc, err error) {
	// Convert ConnectTimeout to time.Duration
	connectTimeout := time.Duration(cfg.ConnectTimeout) * time.Second

	d := dialer.NewDirect(resolver, out, connectTimeout)
	dial = d.DialContext

	if cfg.ProxyURL != nil {
		for _, field := range cfg.ProxyTLSProfileUnsupported {
			out.Info("HTTPS proxy TLS profile field %q is UNSUPPORTED by this uTLS adapter", field)
		}
		var proxyDialer *proxy.Dialer
		proxyDialer, err = proxy.NewProxyDialer(cfg.ProxyURL, dial, out, connectTimeout, proxy.TLSProfileOptions{
			Profile:            cfg.ProxyTLSProfile,
			Document:           cfg.ProxyTLSProfileDocument,
			Check:              cfg.ProxyTLSProfileCheck,
			Strict:             cfg.ProxyTLSProfileStrict,
			HTTP2Connect:       cfg.ProxyHTTP2Connect,
			InsecureSkipVerify: cfg.ProxyInsecure,
		})
		if err != nil {
			return nil, err
		}

		dial = proxyDialer.DialContext
	}

	if len(cfg.ConnectTo) > 0 {
		dial = connectto.CreateContextDialFunc(cfg.ConnectTo, dial, out)
	}

	if cfg.TLSSplitChunkSize > 0 {
		dial = splittls.CreateContextDialFunc(cfg.TLSSplitChunkSize, cfg.TLSSplitDelay, dial, out)
	}

	return dial, nil
}

// tlsRandomReader is an io.Reader that returns the provided TLS random bytes,
// and then fallbacks to crypto/rand.Reader.
type tlsRandomReader struct {
	data []byte
	pos  int
}

// type check
var _ io.Reader = (*tlsRandomReader)(nil)

// Read implements io.Reader for *tlsRandomReader. It returns the provided TLS
// random bytes, and then fallbacks to crypto/rand.Reader.
func (r *tlsRandomReader) Read(p []byte) (n int, err error) {
	if r.pos < len(r.data) {
		toCopy := len(r.data) - r.pos
		if toCopy > len(p) {
			toCopy = len(p)
		}
		copy(p, r.data[r.pos:r.pos+toCopy])
		r.pos += toCopy
		if toCopy < len(p) {
			// Fill the rest from crypto/rand.Reader
			nn, err := io.ReadFull(rand.Reader, p[toCopy:])
			return toCopy + nn, err
		}

		return toCopy, nil
	}

	// All data consumed, fallback to crypto/rand.Reader
	return rand.Read(p)
}

// createTLSConfig creates TLS config based on the configuration.
func createTLSConfig(hostname string, cfg *config.Config, out *output.Output) (tlsConfig *tls.Config) {
	tlsConfig = &tls.Config{
		ServerName: hostname,
		MinVersion: cfg.TLSMinVersion,
		MaxVersion: cfg.TLSMaxVersion,
	}

	if cfg.TLSServerName != "" {
		out.Debug("Overriding the TLS server name: %s", cfg.TLSServerName)

		tlsConfig.ServerName = cfg.TLSServerName
	}

	if len(cfg.TLSCiphers) > 0 {
		tlsConfig.CipherSuites = cfg.TLSCiphers
	}

	if cfg.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	if len(cfg.TLSRandom) == 32 {
		out.Debug("Overriding TLS ClientHello random value")
		tlsConfig.Rand = &tlsRandomReader{data: cfg.TLSRandom}
	}

	if websocket.IsWebSocket(cfg.RequestURL) {
		out.Debug("Forcing ALPN http/1.1 as this is a WebSocket request")

		// TODO(ameshkov): Add H2 when it supports WebSocket: https://github.com/golang/go/issues/49918
		// TODO(ameshkov): Add H3 when it supports WebSocket
		tlsConfig.NextProtos = []string{"http/1.1"}
	} else if cfg.ForceHTTP11 {
		out.Debug("Forcing ALPN http/1.1")

		tlsConfig.NextProtos = []string{"http/1.1"}
	} else if cfg.ForceHTTP2 {
		out.Debug("Forcing ALPN h2")

		tlsConfig.NextProtos = []string{"h2"}
	} else if cfg.ForceHTTP3 {
		out.Debug("Forcing ALPN h3")

		tlsConfig.NextProtos = []string{"h3"}
	}

	if len(tlsConfig.NextProtos) == 0 {
		out.Debug("By default using ALPN h2, http/1.1")

		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}

	return tlsConfig
}
