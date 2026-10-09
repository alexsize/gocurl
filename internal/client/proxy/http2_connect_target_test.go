package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestHTTPSProxyHTTP2ConnectCarriesHTTP2TargetSession(t *testing.T) {
	var targetRequests int
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests++
		if r.ProtoMajor != 2 || r.URL.Path != "/through-connect" {
			t.Errorf("target request = %s %s; want HTTP/2 /through-connect", r.Proto, r.URL.Path)
		}
		_, _ = io.WriteString(w, "h2-over-h2-connect-ok")
	}))
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()
	_, targetPortText, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	targetHost := net.JoinHostPort("target.test", targetPortText)

	var proxyRequests int
	proxyServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveHTTP2TargetConnect(t, target.Listener.Addr().String(), targetHost, &proxyRequests, w, r)
	}))
	proxyServer.EnableHTTP2 = true
	proxyServer.StartTLS()
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := createHTTPProxyDialer(
		proxyURL,
		fixedDialer{address: proxyServer.Listener.Addr().String()},
		5*time.Second,
		TLSProfileOptions{HTTP2Connect: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	httpProxyDialer := dialer.(*httpProxyDialer)
	httpProxyDialer.tlsConfig.InsecureSkipVerify = true

	transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			tunnel, dialErr := httpProxyDialer.Dial(network, addr)
			if dialErr != nil {
				return nil, dialErr
			}
			targetTLS := tls.Client(tunnel, &tls.Config{
				ServerName:         "target.test",
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2"},
			})
			if dialErr = targetTLS.HandshakeContext(ctx); dialErr != nil {
				_ = tunnel.Close()
				return nil, dialErr
			}
			if got := targetTLS.ConnectionState().NegotiatedProtocol; got != "h2" {
				_ = targetTLS.Close()
				return nil, fmt.Errorf("target ALPN = %q, want h2", got)
			}
			return targetTLS, nil
		},
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+targetHost+"/through-connect", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("HTTP/2 request through HTTPS proxy CONNECT: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusOK || string(body) != "h2-over-h2-connect-ok" {
		t.Fatalf(
			"response = %s %d body %q; want HTTP/2 200 with expected body",
			response.Proto,
			response.StatusCode,
			body,
		)
	}
	if proxyRequests != 1 || targetRequests != 1 {
		t.Fatalf("request counts proxy=%d target=%d; want one at both hops", proxyRequests, targetRequests)
	}
}

type proxyFlushWriter struct {
	writer  io.Writer
	flusher http.Flusher
}

func (w proxyFlushWriter) Write(data []byte) (int, error) {
	n, err := w.writer.Write(data)
	w.flusher.Flush()
	return n, err
}

func serveHTTP2TargetConnect(
	t *testing.T,
	targetAddress, targetHost string,
	proxyRequests *int,
	w http.ResponseWriter,
	r *http.Request,
) {
	(*proxyRequests)++
	if r.ProtoMajor != 2 || r.Method != http.MethodConnect || r.Host != targetHost {
		t.Errorf("proxy request = %s %q %q; want HTTP/2 CONNECT %q", r.Proto, r.Method, r.Host, targetHost)
	}
	upstream, dialErr := net.Dial("tcp", targetAddress)
	if dialErr != nil {
		http.Error(w, dialErr.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()
	flusher, ok := w.(http.Flusher)
	if !ok {
		t.Error("HTTP/2 proxy response writer does not implement Flusher")
		return
	}
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	go func() {
		_, _ = io.Copy(upstream, r.Body)
		if closeWriter, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
	}()
	_, _ = io.Copy(proxyFlushWriter{writer: w, flusher: flusher}, upstream)
}
