package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/gocurl/internal/appversion"
	"github.com/ameshkov/gocurl/internal/client/dialer"
	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// httpProxyDialer implements proxy.Dialer for HTTP and HTTPS proxies.
type httpProxyDialer struct {
	proxyURL       *url.URL
	forward        proxy.Dialer
	tlsConfig      *tls.Config
	connectTimeout time.Duration
	tlsProfile     TLSProfileOptions
}

// type check
var _ proxy.Dialer = (*httpProxyDialer)(nil)

// Dial implements the proxy.Dialer interface for *httpProxyDialer.
func (d *httpProxyDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

// DialContext bounds proxy DNS, TLS, and CONNECT with the caller's context.
func (d *httpProxyDialer) DialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("HTTP proxy does not support %s", network)
	}

	// Use the forward dialer to connect to the proxy server
	proxyAddr := net.JoinHostPort(d.proxyURL.Hostname(), d.proxyURL.Port())
	timeout := d.connectTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	proxyConn, err := dialer.DialContext(ctx, d.forward, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}
	stop := dialer.WatchContext(ctx, proxyConn)
	defer func() {
		stop()
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			_ = proxyConn.Close()
			conn = nil
		}
	}()
	var proxyChecks []utlsengine.ProfileCheckResult
	wrapProxyError := func(err error) error {
		if d.proxyURL.Scheme != "https" {
			return err
		}
		return &tlsProxyObservationError{err: err, checks: proxyChecks}
	}

	if d.proxyURL.Scheme == "https" {
		tlsConn, checks, tlsErr := d.handshakeHTTPSProxy(ctx, proxyConn)
		if tlsErr != nil {
			return nil, tlsErr
		}
		proxyConn, proxyChecks = tlsConn, checks
	}
	if d.tlsProfile.HTTP2Connect {
		conn, dialErr := d.dialHTTP2Connect(proxyConn, addr)
		if dialErr != nil {
			log.OnCloserError(proxyConn, log.DEBUG)
			return nil, wrapProxyError(dialErr)
		}
		return conn, nil
	}

	conn, err = d.dialHTTP1Connect(proxyConn, addr)
	if err != nil {
		return nil, wrapProxyError(err)
	}
	return conn, nil
}

func negotiatedProtocol(conn net.Conn) string {
	if c, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return c.ConnectionState().NegotiatedProtocol
	}
	if c, ok := conn.(interface{ ConnectionState() utls.ConnectionState }); ok {
		return c.ConnectionState().NegotiatedProtocol
	}
	return ""
}

func (d *httpProxyDialer) dialHTTP2Connect(proxyConn net.Conn, addr string) (net.Conn, error) {
	client, err := (&http2.Transport{}).NewClientConn(proxyConn)
	if err != nil {
		return nil, fmt.Errorf("initialize HTTP/2 proxy connection: %w", err)
	}
	requestCtx, cancel := context.WithCancel(context.Background())
	reader, writer := io.Pipe()
	req := &http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Host: addr},
		Host:          addr,
		Header:        make(http.Header),
		Body:          reader,
		ContentLength: -1,
	}
	req = req.WithContext(requestCtx)
	req.Header.Set("User-Agent", fmt.Sprintf("gocurl/%s", appversion.Version()))
	if d.proxyURL.User != nil {
		username := d.proxyURL.User.Username()
		password, _ := d.proxyURL.User.Password()
		req.SetBasicAuth(username, password)
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
		req.Header.Del("Authorization")
	}

	timeout := d.connectTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	var timedOut atomic.Bool
	timeoutTimer := time.AfterFunc(timeout, func() {
		timedOut.Store(true)
		cancel()
	})
	resp, err := client.RoundTrip(req)
	timeoutTimer.Stop()
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
		cancel()
		_ = client.Close()
		if timedOut.Load() {
			return nil, fmt.Errorf("HTTP/2 CONNECT to proxy timed out")
		}
		return nil, fmt.Errorf("HTTP/2 CONNECT to proxy failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = reader.Close()
		_ = writer.Close()
		cancel()
		_ = client.Close()
		return nil, fmt.Errorf("HTTP/2 proxy CONNECT failed: %s", resp.Status)
	}
	if timedOut.Load() {
		_ = resp.Body.Close()
		_ = reader.Close()
		_ = writer.Close()
		cancel()
		_ = client.Close()
		return nil, fmt.Errorf("HTTP/2 CONNECT to proxy timed out")
	}

	return &h2TunnelConn{
		body:      resp.Body,
		writer:    writer,
		client:    client,
		proxyConn: proxyConn,
		cancel:    cancel,
	}, nil
}

type tlsProxyObservationConn struct {
	net.Conn
	checks []utlsengine.ProfileCheckResult
}

func (c *tlsProxyObservationConn) ProxyTLSObservations() []utlsengine.ProfileCheckResult {
	return append([]utlsengine.ProfileCheckResult(nil), c.checks...)
}

type tlsProxyObservationError struct {
	err    error
	checks []utlsengine.ProfileCheckResult
}

func (e *tlsProxyObservationError) Error() string { return e.err.Error() }
func (e *tlsProxyObservationError) Unwrap() error { return e.err }
func (e *tlsProxyObservationError) ProxyTLSObservations() []utlsengine.ProfileCheckResult {
	return append([]utlsengine.ProfileCheckResult(nil), e.checks...)
}

// createHTTPProxyDialer creates a proxy.Dialer for HTTP or HTTPS proxies.
// connectTimeout is the timeout for the connection phase. If 0, uses default timeout.
func createHTTPProxyDialer(
	proxyURL *url.URL,
	forward proxy.Dialer,
	connectTimeout time.Duration,
	tlsProfile TLSProfileOptions,
) (proxy.Dialer, error) {
	// Set default port if not specified
	if proxyURL.Port() == "" {
		switch proxyURL.Scheme {
		case "http":
			proxyURL.Host = net.JoinHostPort(proxyURL.Hostname(), "80")
		case "https":
			proxyURL.Host = net.JoinHostPort(proxyURL.Hostname(), "443")
		}
	}

	// Create TLS config for HTTPS proxies
	var tlsConfig *tls.Config
	if proxyURL.Scheme == "https" {
		tlsConfig = &tls.Config{
			ServerName:         proxyURL.Hostname(),
			InsecureSkipVerify: tlsProfile.InsecureSkipVerify,
		}
		if tlsProfile.HTTP2Connect && tlsProfile.Profile == nil {
			tlsConfig.NextProtos = []string{"h2"}
		}
	}
	if tlsProfile.HTTP2Connect && proxyURL.Scheme != "https" {
		return nil, fmt.Errorf("HTTP/2 CONNECT requires an https:// proxy")
	}
	if tlsProfile.HTTP2Connect && tlsProfile.Profile != nil && !slices.Contains(tlsProfile.Profile.ALPN, "h2") {
		return nil, fmt.Errorf("proxy TLS profile must offer h2 for HTTP/2 CONNECT")
	}

	return &httpProxyDialer{
		proxyURL:       proxyURL,
		forward:        forward,
		tlsConfig:      tlsConfig,
		connectTimeout: connectTimeout,
		tlsProfile:     tlsProfile,
	}, nil
}
