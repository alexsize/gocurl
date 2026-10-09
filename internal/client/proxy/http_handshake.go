package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/gocurl/internal/appversion"
	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	utls "github.com/refraction-networking/utls"
)

func (d *httpProxyDialer) handshakeHTTPSProxy(
	ctx context.Context,
	proxyConn net.Conn,
) (tlsConn net.Conn, proxyChecks []utlsengine.ProfileCheckResult, err error) {
	wrapProxyError := func(err error) error {
		return &tlsProxyObservationError{err: err, checks: proxyChecks}
	}
	var capture *utlsengine.CaptureConn
	// Set a deadline for the TLS handshake
	tlsTimeout := 30 * time.Second
	if d.connectTimeout > 0 {
		tlsTimeout = d.connectTimeout
	}
	if err = proxyConn.SetDeadline(time.Now().Add(tlsTimeout)); err != nil {
		log.OnCloserError(proxyConn, log.DEBUG)

		return nil, proxyChecks, wrapProxyError(fmt.Errorf("failed to set TLS handshake deadline: %w", err))
	}
	// Perform the TLS handshake, applying an imported profile only to this proxy leg.
	if d.tlsProfile.Profile != nil {
		utlsConfig := &utls.Config{
			ServerName:         d.tlsConfig.ServerName,
			MinVersion:         d.tlsConfig.MinVersion,
			MaxVersion:         d.tlsConfig.MaxVersion,
			CipherSuites:       append([]uint16(nil), d.tlsConfig.CipherSuites...),
			InsecureSkipVerify: d.tlsConfig.InsecureSkipVerify,
			NextProtos:         append([]string(nil), d.tlsProfile.Profile.ALPN...),
		}
		tlsConn, capture, err = utlsengine.Handshake(ctx, proxyConn, utlsConfig, *d.tlsProfile.Profile)
	} else {
		capture = &utlsengine.CaptureConn{Conn: proxyConn}
		standardTLSConn := tls.Client(capture, d.tlsConfig)
		tlsConn = standardTLSConn
		err = standardTLSConn.HandshakeContext(ctx)
		capture.StopCapture()
	}
	if d.tlsProfile.Check && d.tlsProfile.Document != nil {
		proxyChecks, _ = utlsengine.CaptureProfileChecks(*d.tlsProfile.Document, capture)
	} else {
		proxyChecks = utlsengine.CaptureObservations(capture)
	}
	if err != nil {
		log.OnCloserError(proxyConn, log.DEBUG)
		if d.tlsProfile.Strict {
			return nil, proxyChecks, wrapProxyError(
				utlsengine.NewProfileCheckError(
					"CONNECTION_ERROR",
					fmt.Errorf("TLS handshake with HTTPS proxy failed: %w", err),
				),
			)
		}
		return nil, proxyChecks, wrapProxyError(fmt.Errorf("TLS handshake with HTTPS proxy failed: %w", err))
	}
	if d.tlsProfile.HTTP2Connect && negotiatedProtocol(tlsConn) != "h2" {
		protocol := negotiatedProtocol(tlsConn)
		log.OnCloserError(tlsConn, log.DEBUG)
		return nil, proxyChecks, wrapProxyError(
			fmt.Errorf("HTTPS proxy negotiated %q, want h2 for HTTP/2 CONNECT", protocol),
		)
	}
	if d.tlsProfile.Strict {
		for _, check := range proxyChecks {
			if check.Status != "MATCH" {
				log.OnCloserError(tlsConn, log.DEBUG)
				return nil, proxyChecks, wrapProxyError(utlsengine.NewProfileCheckError(check.Status, nil))
			}
		}
	}
	// Reset the deadline
	if err = tlsConn.SetDeadline(time.Time{}); err != nil {
		log.OnCloserError(tlsConn, log.DEBUG)

		return nil, proxyChecks, wrapProxyError(fmt.Errorf("failed to reset TLS connection deadline: %w", err))
	}
	return &tlsProxyObservationConn{Conn: tlsConn, checks: proxyChecks}, proxyChecks, nil
}

func (d *httpProxyDialer) dialHTTP1Connect(proxyConn net.Conn, addr string) (net.Conn, error) {
	var err error
	// Send the CONNECT request
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}

	// Set User-Agent to gocurl.
	req.Header.Set("User-Agent", fmt.Sprintf("gocurl/%s", appversion.Version()))

	// Add proxy authentication if provided
	if d.proxyURL.User != nil {
		username := d.proxyURL.User.Username()
		password, _ := d.proxyURL.User.Password()
		req.SetBasicAuth(username, password)
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
		req.Header.Del("Authorization")
	}

	// Write the request to the proxy
	if err = req.Write(proxyConn); err != nil {
		log.OnCloserError(proxyConn, log.DEBUG)

		return nil, (fmt.Errorf("failed to write CONNECT request to proxy: %w", err))
	}

	// Read the response
	r := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		log.OnCloserError(proxyConn, log.DEBUG)

		return nil, (fmt.Errorf("failed to read response from proxy: %w", err))
	}
	defer log.OnCloserError(resp.Body, log.DEBUG)

	// Check if the connection was established successfully
	if resp.StatusCode != http.StatusOK {
		log.OnCloserError(proxyConn, log.DEBUG)

		return nil, (fmt.Errorf("proxy connection failed: %s", resp.Status))
	}

	if r.Buffered() > 0 {
		return &bufferedHTTPProxyConn{Conn: proxyConn, reader: r}, nil
	}
	return proxyConn, nil
}

type bufferedHTTPProxyConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedHTTPProxyConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *bufferedHTTPProxyConn) ProxyTLSObservations() []utlsengine.ProfileCheckResult {
	if provider, ok := c.Conn.(interface {
		ProxyTLSObservations() []utlsengine.ProfileCheckResult
	}); ok {
		return provider.ProxyTLSObservations()
	}
	return nil
}
