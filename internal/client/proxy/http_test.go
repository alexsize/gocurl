package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

func TestHTTPSProxyDialCapturesItsTLSClientHello(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Errorf("proxy request method = %q, want CONNECT", r.Method)
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("Hijack() error = %v", err)
			return
		}
		_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = rw.Flush()
		_ = conn.Close()
	}))
	defer server.Close()

	proxyURL := &url.URL{Scheme: "https", Host: server.Listener.Addr().String()}
	dialer, err := createHTTPProxyDialer(
		proxyURL,
		fixedDialer{address: server.Listener.Addr().String()},
		0,
		TLSProfileOptions{},
	)
	if err != nil {
		t.Fatalf("createHTTPProxyDialer() error = %v", err)
	}
	httpDialer := dialer.(*httpProxyDialer)
	httpDialer.tlsConfig.InsecureSkipVerify = true

	conn, err := httpDialer.Dial("tcp", "target.test:443")
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	observed, ok := conn.(interface {
		ProxyTLSObservations() []utlsengine.ProfileCheckResult
	})
	if !ok {
		_ = conn.Close()
		t.Fatalf("proxy connection type %T does not expose its TLS observation", conn)
	}
	checks := observed.ProxyTLSObservations()
	_ = conn.Close()
	if len(checks) != 1 || checks[0].Status != "OBSERVED" || checks[0].Actual.JA3 == "" || checks[0].Actual.JA4 == "" {
		t.Fatalf("proxy TLS observations = %+v, want observed JA3 and JA4", checks)
	}
}

func TestHTTPSProxyTunnelCapturesProxyAndTargetTLSClientHellos(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/through-proxy" {
			t.Errorf("target request = %s %s, want GET /through-proxy", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, "target response")
	}))
	defer target.Close()

	proxyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveCapturedHTTPSProxy(t, target.Listener.Addr().String(), w, r)
	}))
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	dialer, err := createHTTPProxyDialer(
		proxyURL,
		fixedDialer{address: proxyServer.Listener.Addr().String()},
		5*time.Second,
		TLSProfileOptions{},
	)
	if err != nil {
		t.Fatalf("createHTTPProxyDialer() error = %v", err)
	}
	httpDialer := dialer.(*httpProxyDialer)
	// Test server certificates are self-signed. This test-only override does not
	// change the production certificate-verification behavior.
	httpDialer.tlsConfig.InsecureSkipVerify = true

	tunnel, err := httpDialer.Dial("tcp", target.Listener.Addr().String())
	if err != nil {
		t.Fatalf("HTTPS proxy Dial() error = %v", err)
	}
	defer func() { _ = tunnel.Close() }()

	assertTunnelProxyFingerprint(t, tunnel)

	targetTLS, targetCapture, err := utlsengine.Handshake(
		context.Background(), tunnel,
		&utls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		},
		utlsengine.Profile{Preset: "chrome-120", ALPN: []string{"http/1.1"}},
	)
	if err != nil {
		t.Fatalf("target TLS handshake through HTTPS proxy: %v", err)
	}
	if got := utlsengine.CaptureObservations(targetCapture); len(got) != 1 || got[0].Status != "OBSERVED" ||
		got[0].Actual.JA3 == "" || got[0].Actual.JA4 == "" {
		t.Fatalf("target TLS observations = %+v, want observed target JA3 and JA4", got)
	}

	if _, err = io.WriteString(
		targetTLS,
		"GET /through-proxy HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	); err != nil {
		t.Fatalf("write target HTTP request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(targetTLS), nil)
	if err != nil {
		t.Fatalf("read target HTTP response: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read target response body: %v", err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "target response" {
		t.Fatalf("target response = %d %q, want 200 %q", response.StatusCode, body, "target response")
	}
}

func TestHTTPProxyCONNECTCarriesHTTP11TargetSession(t *testing.T) {
	targetRequests := make(chan string, 1)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests <- r.Proto + " " + r.URL.Path
		_, _ = io.WriteString(w, "http-connect-h1-ok")
	}))
	defer target.Close()

	proxyConnects := make(chan string, 1)
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveHTTP11ConnectProxy(t, target.Listener.Addr().String(), proxyConnects, w, r)
	}))
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("parse HTTP proxy URL: %v", err)
	}
	dialer, err := createHTTPProxyDialer(proxyURL,
		fixedDialer{address: proxyServer.Listener.Addr().String()}, 5*time.Second, TLSProfileOptions{})
	if err != nil {
		t.Fatalf("create HTTP proxy dialer: %v", err)
	}
	targetAddress := target.Listener.Addr().String()
	tunnel, err := dialer.Dial("tcp", targetAddress)
	if err != nil {
		t.Fatalf("CONNECT through HTTP proxy: %v", err)
	}
	defer func() { _ = tunnel.Close() }()
	targetTLS := tls.Client(tunnel, &tls.Config{
		ServerName:         "127.0.0.1",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	if err = targetTLS.Handshake(); err != nil {
		t.Fatalf("target TLS handshake through HTTP proxy: %v", err)
	}
	if got := targetTLS.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("target ALPN = %q, want http/1.1", got)
	}
	if _, err = io.WriteString(
		targetTLS,
		"GET /through-connect HTTP/1.1\r\nHost: target.test\r\nConnection: close\r\n\r\n",
	); err != nil {
		t.Fatalf("write HTTP/1.1 request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(targetTLS), nil)
	if err != nil {
		t.Fatalf("read target HTTP/1.1 response: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read target response body: %v", err)
	}
	if response.ProtoMajor != 1 || response.StatusCode != http.StatusOK || string(body) != "http-connect-h1-ok" {
		t.Fatalf("target response = %s %d body %q", response.Proto, response.StatusCode, body)
	}
	select {
	case got := <-proxyConnects:
		if got != targetAddress {
			t.Fatalf("proxy CONNECT target = %q, want %q", got, targetAddress)
		}
	default:
		t.Fatal("HTTP proxy did not receive CONNECT")
	}
	select {
	case got := <-targetRequests:
		if got != "HTTP/1.1 /through-connect" {
			t.Fatalf("target request = %q, want HTTP/1.1 /through-connect", got)
		}
	default:
		t.Fatal("target did not receive request through HTTP proxy CONNECT")
	}
}

func TestHTTPProxyBasicAuthUsesOnlyProxyAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Proxy-Authorization"); got != "Basic dXNlcjpwYXNz" {
			t.Errorf("Proxy-Authorization = %q, want Basic credentials", got)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("unexpected origin Authorization header = %q", got)
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("Hijack() error = %v", err)
			return
		}
		_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = rw.Flush()
		_ = conn.Close()
	}))
	defer server.Close()

	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("user", "pass")
	dialer, err := createHTTPProxyDialer(
		proxyURL,
		fixedDialer{address: server.Listener.Addr().String()},
		0,
		TLSProfileOptions{},
	)
	if err != nil {
		t.Fatalf("createHTTPProxyDialer() error = %v", err)
	}
	conn, err := dialer.(*httpProxyDialer).Dial("tcp", "target.test:443")
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	_ = conn.Close()
}

func TestHTTPSProxyHTTP2ConnectProvidesFullDuplexTunnel(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Method != http.MethodConnect || r.Host != "target.test:443" {
			t.Errorf("proxy request = %s %q %q, want HTTP/2 CONNECT target.test:443", r.Proto, r.Method, r.Host)
		}
		if got := r.Header.Get("Proxy-Authorization"); got != "Basic dXNlcjpwYXNz" {
			t.Errorf("Proxy-Authorization = %q, want Basic proxy credentials", got)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected Authorization header on proxy CONNECT: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		if _, err := io.CopyN(w, r.Body, int64(len("duplex tunnel payload"))); err != nil {
			t.Errorf("echo CONNECT stream: %v", err)
			return
		}
		w.(http.Flusher).Flush()
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("user", "pass")
	dialer, err := createHTTPProxyDialer(
		proxyURL, fixedDialer{address: server.Listener.Addr().String()}, 5*time.Second,
		TLSProfileOptions{HTTP2Connect: true},
	)
	if err != nil {
		t.Fatalf("createHTTPProxyDialer() error = %v", err)
	}
	httpDialer := dialer.(*httpProxyDialer)
	httpDialer.tlsConfig.InsecureSkipVerify = true
	conn, err := httpDialer.Dial("tcp", "target.test:443")
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	payload := []byte("duplex tunnel payload")
	if _, err = conn.Write(payload); err != nil {
		t.Fatalf("tunnel Write() error = %v", err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatalf("tunnel Read() error = %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("tunnel payload = %q, want %q", got, payload)
	}
	observed, ok := conn.(interface {
		ProxyTLSObservations() []utlsengine.ProfileCheckResult
	})
	if !ok || len(observed.ProxyTLSObservations()) != 1 {
		t.Fatalf("HTTP/2 tunnel did not preserve proxy TLS observations: %T", conn)
	}
}

func TestHTTPSProxyDialAppliesAndChecksIndependentTLSProfile(t *testing.T) {
	server := newHTTPSProxyTestServer(t)
	defer server.Close()
	profile := proxyTLSProfileForTest()
	materialized, _, err := profile.Materialize()
	if err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}
	proxyURL := &url.URL{Scheme: "https", Host: server.Listener.Addr().String()}
	dialer, err := createHTTPProxyDialer(
		proxyURL,
		fixedDialer{address: server.Listener.Addr().String()},
		0,
		TLSProfileOptions{Profile: &materialized, Document: &profile, Check: true},
	)
	if err != nil {
		t.Fatalf("createHTTPProxyDialer() error = %v", err)
	}
	httpDialer := dialer.(*httpProxyDialer)
	httpDialer.tlsConfig.InsecureSkipVerify = true
	conn, err := httpDialer.Dial("tcp", "target.test:443")
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	provider, ok := conn.(interface {
		ProxyTLSObservations() []utlsengine.ProfileCheckResult
	})
	if !ok {
		t.Fatalf("proxy connection type %T has no TLS profile report", conn)
	}
	checks := provider.ProxyTLSObservations()
	if len(checks) != 1 || checks[0].Status != "MATCH" || len(checks[0].Actual.ALPN) != 1 ||
		checks[0].Actual.ALPN[0] != "http/1.1" {
		t.Fatalf("proxy TLS profile checks = %+v, want MATCH with HTTP/1.1 ALPN", checks)
	}
}

func TestHTTPSProxyStrictProfileMismatchStopsBeforeConnect(t *testing.T) {
	server := newHTTPSProxyTestServer(t)
	defer server.Close()
	profile := proxyTLSProfileForTest()
	profile.Expected.JA4 = "not-the-observed-ja4"
	materialized, _, err := profile.Materialize()
	if err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}
	proxyURL := &url.URL{Scheme: "https", Host: server.Listener.Addr().String()}
	dialer, err := createHTTPProxyDialer(
		proxyURL,
		fixedDialer{address: server.Listener.Addr().String()},
		0,
		TLSProfileOptions{Profile: &materialized, Document: &profile, Check: true, Strict: true},
	)
	if err != nil {
		t.Fatalf("createHTTPProxyDialer() error = %v", err)
	}
	httpDialer := dialer.(*httpProxyDialer)
	httpDialer.tlsConfig.InsecureSkipVerify = true
	conn, err := httpDialer.Dial("tcp", "target.test:443")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("Dial() returned a connection despite strict TLS profile mismatch")
	}
	var profileErr *utlsengine.ProfileCheckError
	if !errors.As(err, &profileErr) || profileErr.Status() != "MISMATCH" || profileErr.ExitCode() != 4 {
		t.Fatalf("Dial() error = %v, want strict mismatch", err)
	}
	var provider interface {
		ProxyTLSObservations() []utlsengine.ProfileCheckResult
	}
	if !errors.As(err, &provider) {
		t.Fatalf("Dial() error %T does not preserve the proxy TLS report", err)
	}
	checks := provider.ProxyTLSObservations()
	if len(checks) != 1 || checks[0].Status != "MISMATCH" || checks[0].Actual.JA4 == "" {
		t.Fatalf("strict proxy TLS profile checks = %+v, want captured mismatch", checks)
	}
}

func newHTTPSProxyTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Errorf("proxy request method = %q, want CONNECT", r.Method)
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("Hijack() error = %v", err)
			return
		}
		_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = rw.Flush()
		_ = conn.Close()
	}))
}

func proxyTLSProfileForTest() utlsengine.ClientProfile {
	return utlsengine.ClientProfile{
		SchemaVersion: utlsengine.ProfileSchemaVersion,
		ID:            "proxy-test",
		Version:       1,
		Name:          "HTTPS proxy test",
		ProfileType:   "PRESET",
		Fields: utlsengine.ClientProfileFields{
			ALPN:       []string{"http/1.1"},
			ALPNPolicy: "CUSTOM",
			CustomALPN: []string{"http/1.1"},
		},
		Policy:        utlsengine.ClientProfilePolicy{MustMatch: []string{"fields.alpn"}},
		Engine:        utlsengine.ClientProfileEngine{Name: "uTLS", Version: "test"},
		BasePreset:    &utlsengine.ClientProfilePreset{Client: "Chrome", Version: "120"},
		Replayability: utlsengine.ClientProfileReplayability{Status: "REPLAYABLE"},
	}
}

type fixedDialer struct{ address string }

func (d fixedDialer) Dial(network, _ string) (net.Conn, error) {
	return net.Dial(network, d.address)
}

var _ proxy.Dialer = fixedDialer{}

func serveCapturedHTTPSProxy(t *testing.T, targetAddress string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || r.Host != targetAddress {
		t.Errorf("proxy CONNECT = %s %q, want target %q", r.Method, r.Host, targetAddress)
	}
	clientConn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Errorf("Hijack() error = %v", err)
		return
	}
	defer func() { _ = clientConn.Close() }()

	targetConn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		t.Errorf("dial target: %v", err)
		return
	}
	defer func() { _ = targetConn.Close() }()
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		t.Errorf("write CONNECT response: %v", err)
		return
	}
	if err = rw.Flush(); err != nil {
		t.Errorf("flush CONNECT response: %v", err)
		return
	}

	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(targetConn, rw)
		close(copyDone)
	}()
	_, _ = io.Copy(clientConn, targetConn)
	_ = clientConn.Close()
	<-copyDone
}

func serveHTTP11ConnectProxy(
	t *testing.T,
	targetAddress string,
	proxyConnects chan<- string,
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodConnect {
		http.Error(w, "expected CONNECT", http.StatusMethodNotAllowed)
		return
	}
	proxyConnects <- r.Host
	clientConn, buffered, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Errorf("hijack HTTP proxy connection: %v", err)
		return
	}
	defer func() { _ = clientConn.Close() }()
	targetConn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		t.Errorf("dial local TLS target: %v", err)
		return
	}
	defer func() { _ = targetConn.Close() }()
	if _, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		t.Errorf("write CONNECT response: %v", err)
		return
	}
	if err = buffered.Flush(); err != nil {
		t.Errorf("flush CONNECT response: %v", err)
		return
	}
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(targetConn, buffered)
		close(copyDone)
	}()
	_, _ = io.Copy(clientConn, targetConn)
	_ = clientConn.Close()
	<-copyDone
}

func assertTunnelProxyFingerprint(t *testing.T, tunnel net.Conn) {
	t.Helper()
	proxyObservation, ok := tunnel.(interface {
		ProxyTLSObservations() []utlsengine.ProfileCheckResult
	})
	if !ok {
		t.Fatalf("tunnel type %T does not expose proxy TLS observations", tunnel)
	}
	proxyChecks := proxyObservation.ProxyTLSObservations()
	if len(proxyChecks) != 1 || proxyChecks[0].Status != "OBSERVED" ||
		proxyChecks[0].Actual.JA3 == "" || proxyChecks[0].Actual.JA4 == "" {
		t.Fatalf("proxy TLS observations = %+v, want observed proxy JA3 and JA4", proxyChecks)
	}
}
