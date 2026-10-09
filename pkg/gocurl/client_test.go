package gocurl

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- Required by the WebSocket handshake fixture (RFC 6455).
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/testutil"

	ctls "github.com/ameshkov/cfcrypto/tls"
	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/chris-wood/ohttp-go"
	"github.com/cloudflare/circl/hpke"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type contextBlockingReader struct {
	ctx context.Context
}

func (r contextBlockingReader) Read(_ []byte) (int, error) {
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}

type failAfterReader struct {
	data []byte
	err  error
}

func (r *failAfterReader) Read(buffer []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(buffer, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestClientDoWSSAcrossDirectAndProxyRoutes(t *testing.T) {
	const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	observed := make(chan wssRouteObservation, 5)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveWSSRouteTarget(w, r, websocketGUID, observed)
	}))
	defer target.Close()
	_, targetPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}
	targetAddress := net.JoinHostPort("localhost", targetPort)
	websocketURL := "wss://" + targetAddress + "/socket"

	for _, tc := range []struct {
		name        string
		proxyScheme string
		wantATYP    byte
	}{
		{name: "direct"},
		{name: "HTTP proxy", proxyScheme: "http"},
		{name: "HTTPS proxy", proxyScheme: "https"},
		{name: "SOCKS5", proxyScheme: "socks5", wantATYP: 1},
		{name: "SOCKS5H", proxyScheme: "socks5h", wantATYP: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := Request{
				URL:      websocketURL,
				Insecure: true,
				Resolve:  map[string][]string{"localhost": {"127.0.0.1"}},
			}
			var proxyServer *httptest.Server
			var proxyListener net.Listener
			var socksATYP chan byte
			var proxyDone chan struct{}
			switch tc.proxyScheme {
			case "http", "https":
				connectHandler := testHTTPConnectHandler(target.Listener.Addr().String())
				if tc.proxyScheme == "http" {
					proxyServer = httptest.NewServer(connectHandler)
				} else {
					proxyServer = httptest.NewTLSServer(connectHandler)
					request.ProxyInsecure = true
				}
				defer proxyServer.Close()
				request.ProxyURL = proxyServer.URL
			case "socks5", "socks5h":
				var listenErr error
				proxyListener, listenErr = net.Listen("tcp", "127.0.0.1:0")
				if listenErr != nil {
					t.Fatalf("listen for SOCKS proxy: %v", listenErr)
				}
				defer proxyListener.Close()
				socksATYP = make(chan byte, 1)
				proxyDone = make(chan struct{})
				go serveSOCKS5Tunnel(t, proxyListener, target.Listener.Addr().String(), socksATYP, proxyDone)
				request.ProxyURL = tc.proxyScheme + "://" + proxyListener.Addr().String()
			}

			result, doErr := NewClient().Do(context.Background(), request)
			if doErr != nil {
				t.Fatalf("Do(WSS) through %s: %v", tc.name, doErr)
			}
			stream, ok := result.Response.Body.(io.ReadWriteCloser)
			if !ok {
				_ = result.Close()
				t.Fatalf("WSS response body type %T is not a full-duplex stream", result.Response.Body)
			}
			if result.Response.StatusCode != http.StatusSwitchingProtocols {
				_ = result.Close()
				t.Fatalf("WSS status = %d, want 101", result.Response.StatusCode)
			}
			observation := <-observed
			if observation.host != targetAddress {
				t.Errorf("target Host = %q, want %q", observation.host, targetAddress)
			}
			if observation.serverName != "localhost" {
				t.Errorf("target TLS SNI = %q, want localhost", observation.serverName)
			}
			// #nosec G401 -- SHA-1 is mandated by the WebSocket handshake (RFC 6455), not a security hash choice.
			acceptInput := sha1.Sum([]byte(observation.key + websocketGUID))
			wantAccept := base64.StdEncoding.EncodeToString(acceptInput[:])
			if got := result.Response.Header.Get("Sec-WebSocket-Accept"); got != wantAccept {
				t.Errorf("Sec-WebSocket-Accept = %q, want %q", got, wantAccept)
			}
			exchangeWSSRouteClient(t, stream, result)
			if doErr = result.Close(); doErr != nil {
				t.Errorf("close WSS result: %v", doErr)
			}
			if tc.wantATYP != 0 {
				select {
				case got := <-socksATYP:
					if got != tc.wantATYP {
						t.Errorf("SOCKS CONNECT ATYP = %d, want %d", got, tc.wantATYP)
					}
				case <-time.After(time.Second):
					t.Fatal("SOCKS proxy did not report CONNECT address type")
				}
				select {
				case <-proxyDone:
				case <-time.After(time.Second):
					t.Fatal("SOCKS proxy tunnel did not shut down")
				}
			}
		})
	}
}

func TestClientDoWebSocketHandshakeOnWire(t *testing.T) {
	const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	handshakeErr := make(chan error, 1)
	exchangeErr := make(chan error, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveWebSocketWireHandshake(w, r, websocketGUID, handshakeErr, exchangeErr)
	}))
	defer server.Close()

	websocketURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/socket"
	result, err := NewClient().Do(context.Background(), Request{URL: websocketURL})
	if err != nil {
		t.Fatalf("Do(WebSocket) error = %v", err)
	}
	if result.Response.StatusCode != http.StatusSwitchingProtocols {
		_ = result.Close()
		t.Fatalf("WebSocket status = %d, want %d", result.Response.StatusCode, http.StatusSwitchingProtocols)
	}
	clientStream, ok := result.Response.Body.(io.ReadWriteCloser)
	if !ok {
		_ = result.Close()
		t.Fatalf(
			"101 response body type %T is not an io.ReadWriteCloser; full-duplex WebSocket stream unavailable",
			result.Response.Body,
		)
	}
	if err = <-handshakeErr; err != nil {
		_ = result.Close()
		t.Fatal(err)
	}
	mask := []byte{0x11, 0x22, 0x33, 0x44}
	frame := []byte{0x81, 0x80 | 4}
	frame = append(frame, mask...)
	for i, value := range []byte("ping") {
		frame = append(frame, value^mask[i%len(mask)])
	}
	if _, err = clientStream.Write(frame); err != nil {
		_ = result.Close()
		t.Fatalf("write client WebSocket frame: %v", err)
	}
	var responseHeader [2]byte
	if _, err = io.ReadFull(clientStream, responseHeader[:]); err != nil {
		_ = result.Close()
		t.Fatalf("read server WebSocket frame header: %v", err)
	}
	if responseHeader != [2]byte{0x81, 4} {
		_ = result.Close()
		t.Fatalf("server WebSocket frame header = %x, want 8104", responseHeader)
	}
	responsePayload := make([]byte, responseHeader[1]&0x7f)
	if _, err = io.ReadFull(clientStream, responsePayload); err != nil {
		_ = result.Close()
		t.Fatalf("read server WebSocket payload: %v", err)
	}
	if string(responsePayload) != "pong" {
		_ = result.Close()
		t.Fatalf("server WebSocket message = %q, want pong", responsePayload)
	}
	if err = <-exchangeErr; err != nil {
		_ = result.Close()
		t.Fatal(err)
	}
	if err = result.Close(); err != nil {
		t.Errorf("close WebSocket response: %v", err)
	}
}

func TestClientDoRejectsInvalidWebSocketAccept(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
			return
		}
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(
			rw,
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: invalid\r\n\r\n",
		)
		_ = rw.Flush()
	}))
	defer server.Close()

	websocketURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/socket"
	result, err := NewClient().Do(context.Background(), Request{URL: websocketURL})
	if err == nil {
		if result != nil {
			_ = result.Close()
		}
		t.Fatal("Do(WebSocket) accepted an invalid Sec-WebSocket-Accept proof")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "websocket") {
		t.Fatalf("Do(WebSocket) error = %v, want WebSocket handshake diagnostic", err)
	}
}

func TestClientDoWebSocketThroughSOCKS5AndSOCKS5H(t *testing.T) {
	const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	observedRequest := make(chan string, 2)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveWebSocketSOCKSTarget(w, r, websocketGUID, observedRequest)
	}))
	defer target.Close()
	_, targetPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}

	for _, tc := range []struct {
		name         string
		proxyScheme  string
		requestHost  string
		wantAddrType byte
	}{
		{name: "SOCKS5 sends IP", proxyScheme: "socks5", requestHost: "127.0.0.1", wantAddrType: 1},
		{name: "SOCKS5H sends domain", proxyScheme: "socks5h", requestHost: "websocket-api.example.test", wantAddrType: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxyListener, listenErr := net.Listen("tcp", "127.0.0.1:0")
			if listenErr != nil {
				t.Fatalf("listen for SOCKS proxy: %v", listenErr)
			}
			defer proxyListener.Close()
			addrType := make(chan byte, 1)
			proxyDone := make(chan struct{})
			go serveSOCKS5Tunnel(t, proxyListener, target.Listener.Addr().String(), addrType, proxyDone)

			url := "ws://" + net.JoinHostPort(tc.requestHost, targetPort) + "/socket"
			result, doErr := NewClient().Do(context.Background(), Request{
				URL:      url,
				ProxyURL: tc.proxyScheme + "://" + proxyListener.Addr().String(),
			})
			if doErr != nil {
				t.Fatalf("Do(WebSocket) through %s: %v", tc.proxyScheme, doErr)
			}
			if result.Response.StatusCode != http.StatusSwitchingProtocols {
				_ = result.Close()
				t.Fatalf("WebSocket status = %d, want 101", result.Response.StatusCode)
			}
			if err = result.Close(); err != nil {
				t.Errorf("close WebSocket result: %v", err)
			}
			select {
			case got := <-observedRequest:
				wantHost := net.JoinHostPort(tc.requestHost, targetPort)
				if got != wantHost {
					t.Errorf("target Host = %q, want %q", got, wantHost)
				}
			case <-time.After(time.Second):
				t.Fatal("target did not observe WebSocket upgrade request")
			}
			select {
			case got := <-addrType:
				if got != tc.wantAddrType {
					t.Errorf("SOCKS CONNECT ATYP = %d, want %d", got, tc.wantAddrType)
				}
			case <-time.After(time.Second):
				t.Fatal("SOCKS proxy did not report CONNECT address type")
			}
			select {
			case <-proxyDone:
			case <-time.After(time.Second):
				t.Fatal("SOCKS proxy tunnel did not shut down")
			}
		})
	}
}

func TestClientDoWebSocketThroughHTTPAndHTTPSProxy(t *testing.T) {
	const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	backendRequests := make(chan struct{}, 2)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveWebSocketHTTPTarget(w, r, websocketGUID, backendRequests)
	}))
	defer target.Close()
	proxyConnectTargets := make(chan string, 2)
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusMethodNotAllowed)
			return
		}
		proxyConnectTargets <- r.Host
		targetConn, tunnelErr := net.DialTimeout("tcp", target.Listener.Addr().String(), time.Second)
		if tunnelErr != nil {
			http.Error(w, tunnelErr.Error(), http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			_ = targetConn.Close()
			http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
			return
		}
		proxyConn, rw, tunnelErr := hijacker.Hijack()
		if tunnelErr != nil {
			_ = targetConn.Close()
			return
		}
		defer proxyConn.Close()
		defer targetConn.Close()
		if _, tunnelErr = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); tunnelErr != nil {
			return
		}
		if tunnelErr = rw.Flush(); tunnelErr != nil {
			return
		}
		copyDone := make(chan struct{})
		go func() {
			_, _ = io.Copy(targetConn, rw)
			if closeWriter, ok := targetConn.(interface{ CloseWrite() error }); ok {
				_ = closeWriter.CloseWrite()
			}
			close(copyDone)
		}()
		_, _ = io.Copy(proxyConn, targetConn)
		<-copyDone
	})

	for _, tc := range []struct {
		name     string
		newProxy func(http.Handler) *httptest.Server
		insecure bool
	}{
		{name: "HTTP proxy", newProxy: httptest.NewServer},
		{name: "HTTPS proxy", newProxy: httptest.NewTLSServer, insecure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := tc.newProxy(proxyHandler)
			defer proxy.Close()

			result, err := NewClient().Do(context.Background(), Request{
				URL:           "ws://" + strings.TrimPrefix(target.URL, "http://") + "/socket",
				ProxyURL:      proxy.URL,
				ProxyInsecure: tc.insecure,
			})
			if err != nil {
				t.Fatalf("Do(WebSocket) through %s: %v", tc.name, err)
			}
			defer func() { _ = result.Close() }()
			if result.Response.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("WebSocket status = %d, want 101", result.Response.StatusCode)
			}
			select {
			case got := <-proxyConnectTargets:
				want := strings.TrimPrefix(target.URL, "http://")
				if got != want {
					t.Errorf("proxy CONNECT target = %q, want %q", got, want)
				}
			case <-time.After(time.Second):
				t.Fatalf("%s did not receive CONNECT", tc.name)
			}
			select {
			case <-backendRequests:
			case <-time.After(time.Second):
				t.Fatalf("%s did not relay the WebSocket upgrade to the target", tc.name)
			}
		})
	}
}

func TestClientDoReturnsRedirectWithoutReplayingOneShotBody(t *testing.T) {
	const payload = "single-use request body"
	var firstBody []byte
	var firstRequests, redirectRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			firstRequests++
			var err error
			firstBody, err = io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Location", "/redirect-target")
			w.WriteHeader(http.StatusTemporaryRedirect)
		case "/redirect-target":
			redirectRequests++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := NewClient().Do(context.Background(), Request{
		URL:           server.URL + "/start",
		Method:        http.MethodPost,
		Body:          strings.NewReader(payload),
		ContentLength: int64(len(payload)),
	})
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer func() { _ = result.Close() }()

	if result.Response.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("response status = %d, want %d", result.Response.StatusCode, http.StatusTemporaryRedirect)
	}
	if firstRequests != 1 || redirectRequests != 0 {
		t.Fatalf("requests: start=%d redirect=%d; want start=1 and redirect=0", firstRequests, redirectRequests)
	}
	if !bytes.Equal(firstBody, []byte(payload)) {
		t.Fatalf("first request body = %q, want %q", firstBody, payload)
	}
}

func TestClientDoRequestTargetOverridesWireTargetOnly(t *testing.T) {
	const wireTarget = "/wire-path?source=api"
	observedHost := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != wireTarget {
			t.Errorf("request target = %q, want %q", r.RequestURI, wireTarget)
		}
		if r.URL.Path != "/wire-path" || r.URL.RawQuery != "source=api" {
			t.Errorf("parsed request URL = %q, want path/query from request target", r.URL.String())
		}
		observedHost <- r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	result, err := NewClient().Do(context.Background(), Request{
		URL:           server.URL + "/url-path?original=1",
		Method:        http.MethodGet,
		HTTPVersion:   "1.1",
		RequestTarget: wireTarget,
	})
	if err != nil {
		t.Fatalf("Do() with RequestTarget: %v", err)
	}
	defer func() { _ = result.Close() }()
	if result.Response.StatusCode != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", result.Response.StatusCode, http.StatusNoContent)
	}
	if got, want := <-observedHost, strings.TrimPrefix(server.URL, "http://"); got != want {
		t.Errorf("request Host = %q, want original URL authority %q", got, want)
	}
}

func TestClientDoPreservesKnownAndUnknownBinaryBodyLengths(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff}
	type requestObservation struct {
		body             []byte
		contentLength    int64
		transferEncoding []string
	}
	observations := make(chan requestObservation, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		observations <- requestObservation{
			body:             body,
			contentLength:    r.ContentLength,
			transferEncoding: append([]string(nil), r.TransferEncoding...),
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	for _, tc := range []struct {
		name                string
		contentLength       int64
		wantLength          int64
		wantChunkedTransfer bool
	}{
		{name: "known length", contentLength: int64(len(payload)), wantLength: int64(len(payload))},
		{name: "unknown length", contentLength: 0, wantLength: -1, wantChunkedTransfer: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := NewClient().Do(context.Background(), Request{
				URL:           server.URL + "/binary-upload",
				Method:        http.MethodPost,
				HTTPVersion:   "1.1",
				Body:          bytes.NewReader(payload),
				ContentLength: tc.contentLength,
			})
			if err != nil {
				t.Fatalf("Do() error = %v", err)
			}
			defer func() { _ = result.Close() }()
			if result.Response.StatusCode != http.StatusNoContent {
				t.Fatalf("response status = %d, want %d", result.Response.StatusCode, http.StatusNoContent)
			}

			got := <-observations
			if !bytes.Equal(got.body, payload) {
				t.Errorf("request body = %v, want exact binary payload %v", got.body, payload)
			}
			if got.contentLength != tc.wantLength {
				t.Errorf("request ContentLength = %d, want %d", got.contentLength, tc.wantLength)
			}
			isChunked := slices.Contains(got.transferEncoding, "chunked")
			if isChunked != tc.wantChunkedTransfer {
				t.Errorf(
					"request TransferEncoding = %v, chunked = %t; want chunked = %t",
					got.transferEncoding,
					isChunked,
					tc.wantChunkedTransfer,
				)
			}
		})
	}
}

func TestClientDoPreservesOrderedRepeatedHeadersOnHTTP11Wire(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	type wireObservation struct {
		requestLine string
		headers     []string
		err         error
	}
	observed := make(chan wireObservation, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			observed <- wireObservation{err: acceptErr}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(conn)
		requestLine, readErr := reader.ReadString('\n')
		if readErr != nil {
			observed <- wireObservation{err: readErr}
			return
		}
		var headers []string
		for {
			line, lineErr := reader.ReadString('\n')
			if lineErr != nil {
				observed <- wireObservation{err: lineErr}
				return
			}
			if line == "\r\n" {
				break
			}
			headers = append(headers, strings.TrimRight(line, "\r\n"))
		}
		observed <- wireObservation{requestLine: strings.TrimRight(requestLine, "\r\n"), headers: headers}
		_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}()

	const requestTarget = "/ordered-headers"
	result, err := NewClient().Do(context.Background(), Request{
		URL:              "http://" + listener.Addr().String() + requestTarget,
		Method:           http.MethodGet,
		HTTPVersion:      "1.1",
		NoDefaultHeaders: true,
		Headers: []Header{
			{Name: "X-First", Value: "one"},
			{Name: "x-repeat", Value: "first"},
			{Name: "X-Last", Value: "last"},
			{Name: "X-Repeat", Value: "second"},
		},
	})
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer func() { _ = result.Close() }()
	if result.Response.StatusCode != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", result.Response.StatusCode, http.StatusNoContent)
	}

	got := <-observed
	if got.err != nil {
		t.Fatalf("read HTTP/1.1 request from wire: %v", got.err)
	}
	if want := "GET " + requestTarget + " HTTP/1.1"; got.requestLine != want {
		t.Errorf("request line = %q, want %q", got.requestLine, want)
	}
	var customHeaders []string
	for _, header := range got.headers {
		if strings.HasPrefix(strings.ToLower(header), "x-") {
			customHeaders = append(customHeaders, header)
		}
	}
	wantHeaders := []string{"X-First: one", "x-repeat: first", "X-Last: last", "X-Repeat: second"}
	if !slices.Equal(customHeaders, wantHeaders) {
		t.Errorf("custom headers on wire = %q, want %q", customHeaders, wantHeaders)
	}
}

func TestClientDoNoDefaultHeadersKeepsOnlyExplicitHeaders(t *testing.T) {
	const payload = "form=body"
	type requestObservation struct {
		userAgent   string
		contentType string
		explicit    string
		body        []byte
	}
	observed := make(chan requestObservation, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		observed <- requestObservation{
			userAgent:   r.Header.Get("User-Agent"),
			contentType: r.Header.Get("Content-Type"),
			explicit:    r.Header.Get("X-Only"),
			body:        body,
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	result, err := NewClient().Do(context.Background(), Request{
		URL:              server.URL + "/no-defaults",
		Method:           http.MethodPost,
		HTTPVersion:      "1.1",
		NoDefaultHeaders: true,
		Headers:          []Header{{Name: "X-Only", Value: "explicit"}},
		Body:             strings.NewReader(payload),
		ContentLength:    int64(len(payload)),
	})
	if err != nil {
		t.Fatalf("Do() with NoDefaultHeaders: %v", err)
	}
	defer func() { _ = result.Close() }()
	if result.Response.StatusCode != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", result.Response.StatusCode, http.StatusNoContent)
	}
	got := <-observed
	if got.userAgent != "" || got.contentType != "" {
		t.Errorf("default headers were sent: User-Agent=%q Content-Type=%q", got.userAgent, got.contentType)
	}
	if got.explicit != "explicit" {
		t.Errorf("explicit X-Only header = %q, want %q", got.explicit, "explicit")
	}
	if string(got.body) != payload {
		t.Errorf("request body = %q, want %q", got.body, payload)
	}
}

func TestResultRequestMetadataRedactsDetachedHeaderSnapshot(t *testing.T) {
	const secret = "api-token-do-not-leak"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != secret {
			t.Errorf("wire Authorization = %q, want original value", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	result, err := NewClient().Do(context.Background(), Request{
		URL: server.URL + "/metadata?visible=yes",
		Headers: []Header{
			{Name: "Authorization", Value: secret},
			{Name: "X-Visible", Value: "keep-me"},
		},
		JSONRedactHeaders: []string{"authorization"},
	})
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer func() { _ = result.Close() }()

	metadata := result.RequestMetadata()
	if metadata == nil {
		t.Fatal("RequestMetadata() = nil, want request snapshot")
	}
	if got := metadata.Headers.Get("Authorization"); got != "[REDACTED]" {
		t.Errorf("metadata Authorization = %q, want redacted placeholder", got)
	}
	if got := metadata.Headers.Get("X-Visible"); got != "keep-me" {
		t.Errorf("metadata X-Visible = %q, want unchanged value", got)
	}
	if !slices.Contains(metadata.RedactedHeaderNames, "Authorization") {
		t.Errorf("redacted header names = %v, want Authorization", metadata.RedactedHeaderNames)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("marshal request metadata: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("serialized request metadata leaked authorization value: %s", encoded)
	}
	if got := result.Response.Request.Header.Get("Authorization"); got != secret {
		t.Errorf("Response.Request was mutated to %q; want original request value", got)
	}
	metadata.Headers.Set("X-Visible", "mutated snapshot")
	if got := result.RequestMetadata().Headers.Get("X-Visible"); got != "keep-me" {
		t.Errorf("a later metadata snapshot contains caller mutation %q", got)
	}
}

func TestResultRequestMetadataRedactsURLCredentialsWithAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	result, err := NewClient().Do(context.Background(), Request{
		URL: strings.Replace(
			server.URL,
			"http://",
			"http://api-user:url-password-secret@",
			1,
		) + "/metadata",
		JSONRedactHeaders: []string{"Authorization"},
	})
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer func() { _ = result.Close() }()

	metadata := result.RequestMetadata()
	if metadata == nil {
		t.Fatal("RequestMetadata() = nil, want request snapshot")
	}
	if strings.Contains(metadata.URL, "api-user") || strings.Contains(metadata.URL, "url-password-secret") {
		t.Errorf("request metadata URL contains userinfo: %q", metadata.URL)
	}
	if got := metadata.Headers.Get("Authorization"); got != "[REDACTED]" {
		t.Errorf("metadata Authorization = %q, want redacted placeholder", got)
	}
	if got := result.Response.Request.URL.User.Username(); got != "api-user" {
		t.Errorf("Response.Request URL user = %q, want original value", got)
	}
	if got, _ := result.Response.Request.URL.User.Password(); got != "url-password-secret" {
		t.Errorf("Response.Request URL password = %q, want original value", got)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("marshal request metadata: %v", err)
	}
	if strings.Contains(string(encoded), "url-password-secret") {
		t.Fatalf("serialized request metadata leaked URL password: %s", encoded)
	}
}

func TestClientDoResolvePinsHostnameToLocalTLSServer(t *testing.T) {
	const hostname = "resolve-api.example.test"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Host, hostname+":") {
			t.Errorf("request Host = %q, want %s:<port>", r.Host, hostname)
		}
		if r.URL.Path != "/resolve-check" {
			t.Errorf("request path = %q, want /resolve-check", r.URL.Path)
		}
		if r.TLS == nil || r.TLS.ServerName != hostname {
			t.Errorf("TLS SNI = %v, want %q", r.TLS, hostname)
		}
		_, _ = io.WriteString(w, "resolved")
	}))
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	result, err := NewClient().Do(context.Background(), Request{
		URL:      "https://" + net.JoinHostPort(hostname, port) + "/resolve-check",
		Insecure: true, // The httptest TLS certificate is self-signed.
		Resolve:  map[string][]string{hostname: {"127.0.0.1"}},
	})
	if err != nil {
		t.Fatalf("Do() with Resolve override error = %v", err)
	}
	defer func() { _ = result.Close() }()

	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if result.Response.StatusCode != http.StatusOK || string(body) != "resolved" {
		t.Fatalf("response = %d %q, want 200 %q", result.Response.StatusCode, body, "resolved")
	}
}

func TestClientDoConnectToRedirectsSocketWithoutChangingHostOrSNI(t *testing.T) {
	const hostname = "connect-to-api.example.test"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != hostname+":443" {
			t.Errorf("request Host = %q, want %q", r.Host, hostname+":443")
		}
		if r.TLS == nil || r.TLS.ServerName != hostname {
			t.Errorf("TLS SNI = %v, want %q", r.TLS, hostname)
		}
		if r.URL.Path != "/connect-to-check" {
			t.Errorf("request path = %q, want /connect-to-check", r.URL.Path)
		}
		_, _ = io.WriteString(w, "connect-to ok")
	}))
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	result, err := NewClient().Do(context.Background(), Request{
		URL:       "https://" + hostname + ":443/connect-to-check",
		ConnectTo: []string{hostname + ":443:127.0.0.1:" + port},
		Insecure:  true, // The httptest TLS certificate is self-signed.
	})
	if err != nil {
		t.Fatalf("Do() with ConnectTo override: %v", err)
	}
	defer func() { _ = result.Close() }()
	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if result.Response.StatusCode != http.StatusOK || string(body) != "connect-to ok" {
		t.Fatalf("response = %d %q, want 200 with ConnectTo response", result.Response.StatusCode, body)
	}
}

func TestClientDoEnforcesTLSVersionBounds(t *testing.T) {
	const hostname = "tls-version-api.example.test"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			t.Errorf("negotiated TLS version = %v, want TLS 1.3", r.TLS)
		}
		if r.TLS.ServerName != hostname {
			t.Errorf("TLS SNI = %q, want %q", r.TLS.ServerName, hostname)
		}
		_, _ = io.WriteString(w, "TLS version bounds ok")
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	result, err := NewClient().Do(context.Background(), Request{
		URL:           "https://" + net.JoinHostPort(hostname, port) + "/tls-version",
		TLSMinVersion: "1.3",
		TLSMaxVersion: "1.3",
		Insecure:      true, // The httptest TLS certificate is self-signed.
		Resolve:       map[string][]string{hostname: {"127.0.0.1"}},
	})
	if err != nil {
		t.Fatalf("Do() with TLS version bounds: %v", err)
	}
	defer func() { _ = result.Close() }()
	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if result.Response.StatusCode != http.StatusOK || string(body) != "TLS version bounds ok" {
		t.Fatalf("response = %d %q, want 200 with TLS version response", result.Response.StatusCode, body)
	}
}

func TestClientDoECHAcceptedAcrossProxyRoutes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		proxyScheme string
		wantATYP    byte
	}{
		{name: "direct"},
		{name: "HTTP proxy", proxyScheme: "http"},
		{name: "HTTPS proxy", proxyScheme: "https"},
		{name: "SOCKS5", proxyScheme: "socks5", wantATYP: 1},
		{name: "SOCKS5H", proxyScheme: "socks5h", wantATYP: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			echConfig, provider := makeLocalECHConfigForPublicAPI(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen for local ECH target: %v", err)
			}
			defer listener.Close()
			_, targetPort, err := net.SplitHostPort(listener.Addr().String())
			if err != nil {
				t.Fatalf("split ECH target address: %v", err)
			}
			targetHost := "private.ech.example.test"
			if tc.proxyScheme == "socks5" {
				targetHost = "localhost"
			}
			targetAddress := net.JoinHostPort(targetHost, targetPort)
			targetURL := "https://" + targetAddress + "/ech-api"

			serverResultCh := make(chan apiECHServerResult, 1)
			go serveAPIAcceptedECH(listener, provider, serverResultCh)

			request := Request{
				URL:       targetURL,
				ECHConfig: echConfig,
				Insecure:  true,
				Resolve: map[string][]string{
					"localhost":                {"127.0.0.1"},
					"private.ech.example.test": {"127.0.0.1"},
				},
			}
			var proxyServer *httptest.Server
			var proxyListener net.Listener
			var socksATYP chan byte
			var proxyDone chan struct{}
			switch tc.proxyScheme {
			case "http", "https":
				connectHandler := testHTTPConnectHandler(listener.Addr().String())
				if tc.proxyScheme == "http" {
					proxyServer = httptest.NewServer(connectHandler)
				} else {
					proxyServer = httptest.NewTLSServer(connectHandler)
					request.ProxyInsecure = true
				}
				defer proxyServer.Close()
				request.ProxyURL = proxyServer.URL
			case "socks5", "socks5h":
				var listenErr error
				proxyListener, listenErr = net.Listen("tcp", "127.0.0.1:0")
				if listenErr != nil {
					t.Fatalf("listen for SOCKS proxy: %v", listenErr)
				}
				defer proxyListener.Close()
				socksATYP = make(chan byte, 1)
				proxyDone = make(chan struct{})
				go serveSOCKS5Tunnel(t, proxyListener, listener.Addr().String(), socksATYP, proxyDone)
				request.ProxyURL = tc.proxyScheme + "://" + proxyListener.Addr().String()
			}

			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			result, doErr := NewClient().Do(ctx, request)
			if doErr != nil {
				t.Fatalf("Do(ECH) through %s: %v", tc.name, doErr)
			}
			body, readErr := io.ReadAll(result.Response.Body)
			if readErr != nil {
				_ = result.Close()
				t.Fatalf("read %s ECH response: %v", tc.name, readErr)
			}
			if result.Response.StatusCode != http.StatusOK || string(body) != "ech-accepted" {
				_ = result.Close()
				t.Fatalf("%s ECH response = %d %q", tc.name, result.Response.StatusCode, body)
			}
			if closeErr := result.Close(); closeErr != nil {
				t.Errorf("close %s ECH response: %v", tc.name, closeErr)
			}
			assertAPIAcceptedECH(ctx, t, tc.name, targetAddress, serverResultCh)
			if tc.wantATYP != 0 {
				select {
				case got := <-socksATYP:
					if got != tc.wantATYP {
						t.Errorf("SOCKS CONNECT ATYP = %d, want %d", got, tc.wantATYP)
					}
				case <-ctx.Done():
					t.Fatalf("timed out waiting for SOCKS CONNECT")
				}
				select {
				case <-proxyDone:
				case <-ctx.Done():
					t.Fatalf("timed out waiting for SOCKS proxy tunnel shutdown")
				}
			}
		})
	}
}

func makeLocalECHConfigForPublicAPI(t *testing.T) (string, ctls.ECHProvider) {
	t.Helper()
	publicKey, privateKey, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate ECH HPKE key pair: %v", err)
	}
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal ECH public key: %v", err)
	}
	privateKeyBytes, err := privateKey.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal ECH private key: %v", err)
	}
	appendUint16 := func(dst []byte, value uint16) []byte {
		var encoded [2]byte
		binary.BigEndian.PutUint16(encoded[:], value)
		return append(dst, encoded[:]...)
	}
	contents := []byte{1} // config_id
	contents = appendUint16(contents, uint16(hpke.KEM_X25519_HKDF_SHA256))
	contents = appendUint16(contents, testutil.Uint16(len(publicKeyBytes)))
	contents = append(contents, publicKeyBytes...)
	contents = appendUint16(contents, 4) // cipher_suites length
	contents = appendUint16(contents, 1) // HKDF-SHA256
	contents = appendUint16(contents, 1) // AES-128-GCM
	publicName := []byte("public.test")
	contents = append(contents, 0, testutil.Uint8(len(publicName)))
	contents = append(contents, publicName...)
	contents = appendUint16(contents, 0) // extensions length
	rawConfig := appendUint16(nil, 0xfe0d)
	rawConfig = appendUint16(rawConfig, testutil.Uint16(len(contents)))
	rawConfig = append(rawConfig, contents...)
	encodedConfig := appendUint16(nil, testutil.Uint16(len(rawConfig)))
	encodedConfig = append(encodedConfig, rawConfig...)
	serializedKey := appendUint16(nil, testutil.Uint16(len(privateKeyBytes)))
	serializedKey = append(serializedKey, privateKeyBytes...)
	serializedKey = appendUint16(serializedKey, testutil.Uint16(len(rawConfig)))
	serializedKey = append(serializedKey, rawConfig...)
	keys, err := ctls.EXP_UnmarshalECHKeys(serializedKey)
	if err != nil {
		t.Fatalf("unmarshal local ECH server keys: %v", err)
	}
	provider, err := ctls.EXP_NewECHKeySet(keys)
	if err != nil {
		t.Fatalf("create local ECH server key set: %v", err)
	}
	return base64.StdEncoding.EncodeToString(encodedConfig), provider
}

func TestClientDoECHGreaseReportsUnobservedHandshake(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/ech-grease" {
			t.Errorf("request = %s %s, want GET /ech-grease", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	result, err := NewClient().Do(context.Background(), Request{
		URL:       server.URL + "/ech-grease",
		ECHGrease: true,
		Insecure:  true, // The httptest TLS certificate is self-signed.
	})
	if err != nil {
		t.Fatalf("Do() with ECHGrease: %v", err)
	}
	defer func() { _ = result.Close() }()
	if result.Response.StatusCode != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", result.Response.StatusCode, http.StatusNoContent)
	}
	if len(result.TLSReports) != 1 || result.TLSReports[0].CaptureStatus != "NOT_OBSERVED" {
		t.Fatalf("TLS reports = %+v; want one NOT_OBSERVED ECH GREASE report", result.TLSReports)
	}
}

func TestClientDoHTTP11CreatesNewTLSConnectionPerCall(t *testing.T) {
	var acceptedConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.ProtoMajor != 1 || r.ProtoMinor != 1 {
			http.Error(w, "expected TLS over HTTP/1.1", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			acceptedConnections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()

	client := NewClient()
	for i := 0; i < 2; i++ {
		result, err := client.Do(context.Background(), Request{
			URL:         server.URL,
			HTTPVersion: "1.1",
			Insecure:    true,
		})
		if err != nil {
			t.Fatalf("Do() call %d: %v", i+1, err)
		}
		body, readErr := io.ReadAll(result.Response.Body)
		if readErr != nil {
			_ = result.Close()
			t.Fatalf("read response %d: %v", i+1, readErr)
		}
		if result.Response.StatusCode != http.StatusOK || string(body) != "ok" {
			_ = result.Close()
			t.Fatalf("response %d = %d %q, want 200 ok", i+1, result.Response.StatusCode, body)
		}
		if err = result.Close(); err != nil {
			t.Errorf("close response %d: %v", i+1, err)
		}
	}
	if got := acceptedConnections.Load(); got != 2 {
		t.Fatalf("TLS connections accepted = %d, want one new connection per API call (2)", got)
	}
}

func TestClientDoPostQuantumHandshakeAcrossProxyRoutes(t *testing.T) {
	observed := make(chan apiPQRouteObservation, 5)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveAPIPQRouteTarget(w, r, observed)
	}))
	target.StartTLS()
	defer target.Close()
	_, targetPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}
	targetAddress := net.JoinHostPort("localhost", targetPort)
	targetURL := "https://" + targetAddress + "/pq"

	for _, tc := range []struct {
		name        string
		proxyScheme string
		wantATYP    byte
	}{
		{name: "direct"},
		{name: "HTTP proxy", proxyScheme: "http"},
		{name: "HTTPS proxy", proxyScheme: "https"},
		{name: "SOCKS5", proxyScheme: "socks5", wantATYP: 1},
		{name: "SOCKS5H", proxyScheme: "socks5h", wantATYP: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := Request{
				URL:         targetURL,
				PostQuantum: true,
				Insecure:    true,
				Resolve:     map[string][]string{"localhost": {"127.0.0.1"}},
			}
			var proxyServer *httptest.Server
			var proxyListener net.Listener
			var socksATYP chan byte
			var proxyDone chan struct{}
			switch tc.proxyScheme {
			case "http", "https":
				connectHandler := testHTTPConnectHandler(target.Listener.Addr().String())
				if tc.proxyScheme == "http" {
					proxyServer = httptest.NewServer(connectHandler)
				} else {
					proxyServer = httptest.NewTLSServer(connectHandler)
					request.ProxyInsecure = true
				}
				defer proxyServer.Close()
				request.ProxyURL = proxyServer.URL
			case "socks5", "socks5h":
				var listenErr error
				proxyListener, listenErr = net.Listen("tcp", "127.0.0.1:0")
				if listenErr != nil {
					t.Fatalf("listen for SOCKS proxy: %v", listenErr)
				}
				defer proxyListener.Close()
				socksATYP = make(chan byte, 1)
				proxyDone = make(chan struct{})
				go serveSOCKS5Tunnel(t, proxyListener, target.Listener.Addr().String(), socksATYP, proxyDone)
				request.ProxyURL = tc.proxyScheme + "://" + proxyListener.Addr().String()
			}

			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			result, doErr := NewClient().Do(ctx, request)
			if doErr != nil {
				t.Fatalf("Do(PostQuantum) through %s: %v", tc.name, doErr)
			}
			body, readErr := io.ReadAll(result.Response.Body)
			if readErr != nil {
				_ = result.Close()
				t.Fatalf("read %s response: %v", tc.name, readErr)
			}
			if result.Response.StatusCode != http.StatusOK || string(body) != "post-quantum proxy route ok" {
				_ = result.Close()
				t.Fatalf("%s response = %d %q", tc.name, result.Response.StatusCode, body)
			}
			if closeErr := result.Close(); closeErr != nil {
				t.Errorf("close %s response: %v", tc.name, closeErr)
			}
			assertAPIPQRouteTarget(ctx, t, tc.name, targetAddress, observed)
			if tc.wantATYP != 0 {
				select {
				case got := <-socksATYP:
					if got != tc.wantATYP {
						t.Errorf("SOCKS CONNECT ATYP = %d, want %d", got, tc.wantATYP)
					}
				case <-ctx.Done():
					t.Fatalf("timed out waiting for SOCKS CONNECT")
				}
				select {
				case <-proxyDone:
				case <-ctx.Done():
					t.Fatalf("timed out waiting for SOCKS proxy tunnel shutdown")
				}
			}
		})
	}
}

func TestClientDoPostQuantumHandshakeAgainstLocalTLSServer(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || uint16(r.TLS.CurveID) != 0x11ec {
			http.Error(w, "negotiated TLS group does not match X25519MLKEM768", http.StatusUpgradeRequired)
			return
		}
		_, _ = io.WriteString(w, "post-quantum handshake ok")
	}))
	server.StartTLS()
	defer server.Close()

	result, err := NewClient().Do(context.Background(), Request{
		URL:         server.URL,
		PostQuantum: true,
		Insecure:    true, // The httptest TLS certificate is self-signed.
	})
	if err != nil {
		t.Fatalf("Do() with PostQuantum: %v", err)
	}
	defer func() { _ = result.Close() }()
	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if result.Response.StatusCode != http.StatusOK || string(body) != "post-quantum handshake ok" {
		t.Fatalf("response = %d %q, want 200 with negotiated X25519MLKEM768", result.Response.StatusCode, body)
	}
}

func TestClientDoHTTPSOverSOCKS5AndSOCKS5H(t *testing.T) {
	const targetHost = "socks-api.example.test"
	type tlsRequestObservation struct {
		host       string
		serverName string
		proto      string
	}
	observed := make(chan tlsRequestObservation, 4)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/socks-route" {
			t.Errorf("request path = %q, want /socks-route", r.URL.Path)
		}
		var serverName string
		if r.TLS != nil {
			serverName = r.TLS.ServerName
		}
		observed <- tlsRequestObservation{host: r.Host, serverName: serverName, proto: r.Proto}
		_, _ = io.WriteString(w, "SOCKS TLS route ok")
	}))
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()
	_, targetPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(target) error = %v", err)
	}
	for _, tc := range []struct {
		name         string
		proxyScheme  string
		httpVersion  string
		wantProto    string
		wantAddrType byte
	}{
		{name: "HTTP1 SOCKS5 sends IP address", proxyScheme: "socks5", httpVersion: "1.1", wantProto: "HTTP/1.1", wantAddrType: 1},
		{name: "HTTP1 SOCKS5H sends domain name", proxyScheme: "socks5h", httpVersion: "1.1", wantProto: "HTTP/1.1", wantAddrType: 3},
		{name: "HTTP2 SOCKS5 sends IP address", proxyScheme: "socks5", httpVersion: "2", wantProto: "HTTP/2.0", wantAddrType: 1},
		{name: "HTTP2 SOCKS5H sends domain name", proxyScheme: "socks5h", httpVersion: "2", wantProto: "HTTP/2.0", wantAddrType: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxyListener, listenErr := net.Listen("tcp", "127.0.0.1:0")
			if listenErr != nil {
				t.Fatalf("listen for SOCKS proxy: %v", listenErr)
			}
			defer func() { _ = proxyListener.Close() }()
			addrType := make(chan byte, 1)
			proxyDone := make(chan struct{})
			go serveSOCKS5Tunnel(t, proxyListener, target.Listener.Addr().String(), addrType, proxyDone)
			requestHost := targetHost
			if tc.proxyScheme == "socks5" {
				requestHost = "127.0.0.1"
			}
			expectedHost := net.JoinHostPort(requestHost, targetPort)

			request := Request{
				URL:           "https://" + expectedHost + "/socks-route",
				TLSServerName: targetHost,
				ProxyURL:      tc.proxyScheme + "://" + proxyListener.Addr().String(),
				Insecure:      true, // The httptest TLS certificate is self-signed.
				HTTPVersion:   tc.httpVersion,
			}
			result, doErr := NewClient().Do(context.Background(), request)
			if doErr != nil {
				t.Fatalf("Do() through %s proxy: %v", tc.proxyScheme, doErr)
			}
			defer func() { _ = result.Close() }()
			body, readErr := io.ReadAll(result.Response.Body)
			if readErr != nil {
				t.Fatalf("read target response: %v", readErr)
			}
			if result.Response.StatusCode != http.StatusOK || string(body) != "SOCKS TLS route ok" {
				t.Fatalf("response = %d %q, want 200 SOCKS TLS response", result.Response.StatusCode, body)
			}
			_ = result.Close()
			select {
			case got := <-observed:
				if got.host != expectedHost || got.serverName != targetHost || got.proto != tc.wantProto {
					t.Errorf(
						"target observed Host=%q SNI=%q protocol=%q; want Host=%q SNI=%q protocol=%q",
						got.host,
						got.serverName,
						got.proto,
						expectedHost,
						targetHost,
						tc.wantProto,
					)
				}
			case <-time.After(time.Second):
				t.Error("target did not report HTTP Host and TLS SNI")
			}
			assertAPIHTTPSOverSOCKSAddressType(t, addrType, tc.wantAddrType)
			select {
			case <-proxyDone:
			case <-time.After(time.Second):
				t.Error("SOCKS proxy tunnel did not shut down")
			}
		})
	}
}

func TestClientDoStrictTLSProfileMismatchStopsSOCKS5AndSOCKS5HRequests(t *testing.T) {
	profile, err := os.ReadFile("../../internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatalf("read TLS profile fixture: %v", err)
	}
	profileJSON := strings.Replace(string(profile), `"value": 771`, `"value": 770`, 1)

	targetRequests := make(chan struct{}, 2)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	_, targetPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split local HTTPS target address: %v", err)
	}
	for _, tc := range []struct {
		name         string
		proxyScheme  string
		targetHost   string
		wantAddrType byte
	}{
		{name: "SOCKS5 IP target", proxyScheme: "socks5", targetHost: "127.0.0.1", wantAddrType: 1},
		{name: "SOCKS5H domain target", proxyScheme: "socks5h", targetHost: "example.test", wantAddrType: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
			if listenErr != nil {
				t.Fatalf("listen for SOCKS proxy: %v", listenErr)
			}
			defer func() { _ = listener.Close() }()

			addrType := make(chan byte, 1)
			proxyDone := make(chan struct{})
			go serveSOCKS5Tunnel(t, listener, target.Listener.Addr().String(), addrType, proxyDone)

			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			profileForHost := strings.Replace(profileJSON, `"example.test"`, `"`+tc.targetHost+`"`, 1)
			profilePath := filepath.Join(t.TempDir(), "strict-socks-profile.json")
			if writeErr := os.WriteFile(profilePath, []byte(profileForHost), 0o600); writeErr != nil {
				t.Fatalf("write TLS profile fixture: %v", writeErr)
			}
			_, requestErr := NewClient().Do(ctx, Request{
				URL:         "https://" + net.JoinHostPort(tc.targetHost, targetPort) + "/strict-socks-profile",
				ProxyURL:    tc.proxyScheme + "://" + listener.Addr().String(),
				HTTPVersion: "1.1",
				Insecure:    true,
				TLSProfile: &TLSProfile{
					ProfilePath: profilePath,
					Check:       true,
					Strict:      true,
				},
			})
			var status interface{ Status() string }
			var coded interface{ ExitCode() int }
			statusOK := errors.As(requestErr, &status)
			codeOK := errors.As(requestErr, &coded)
			if !statusOK || status.Status() != "MISMATCH" || !codeOK || coded.ExitCode() != 4 {
				gotStatus, gotCode := "<unavailable>", -1
				if statusOK {
					gotStatus = status.Status()
				}
				if codeOK {
					gotCode = coded.ExitCode()
				}
				t.Fatalf(
					"Do() error = %v (status=%q, exit_code=%d), want strict MISMATCH with exit code 4",
					requestErr,
					gotStatus,
					gotCode,
				)
			}

			select {
			case got := <-addrType:
				if got != tc.wantAddrType {
					t.Errorf("SOCKS address type = %d, want %d", got, tc.wantAddrType)
				}
			case <-ctx.Done():
				t.Fatal("timed out waiting for SOCKS CONNECT request")
			}
			select {
			case <-targetRequests:
				t.Fatal("strict TLS profile mismatch sent the HTTP request to the target")
			case <-time.After(100 * time.Millisecond):
			}
			select {
			case <-proxyDone:
			case <-time.After(2 * time.Second):
				t.Error("SOCKS tunnel did not close after the strict TLS profile failure")
			}
		})
	}
}

func TestClientDoHTTP2AgainstLocalTLSServer(t *testing.T) {
	type observation struct {
		proto      string
		host       string
		serverName string
		path       string
	}
	const targetHost = "h2-api.example.test"
	observed := make(chan observation, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverName := ""
		if r.TLS != nil {
			serverName = r.TLS.ServerName
		}
		observed <- observation{proto: r.Proto, host: r.Host, serverName: serverName, path: r.URL.Path}
		_, _ = io.WriteString(w, "public API HTTP/2 ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split local HTTPS listener address: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	result, err := NewClient().Do(ctx, Request{
		URL:         "https://" + net.JoinHostPort(targetHost, port) + "/api-http2",
		HTTPVersion: "2",
		Resolve:     map[string][]string{targetHost: {"127.0.0.1"}},
		Insecure:    true, // The local test certificate is self-signed.
	})
	if err != nil {
		t.Fatalf("Do() direct HTTP/2 request: %v", err)
	}
	defer func() { _ = result.Close() }()
	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("read HTTP/2 response: %v", err)
	}
	if result.Response.ProtoMajor != 2 || result.Response.StatusCode != http.StatusOK ||
		string(body) != "public API HTTP/2 ok" {
		t.Fatalf(
			"response = %s %d %q; want HTTP/2 200 with expected body",
			result.Response.Proto,
			result.Response.StatusCode,
			body,
		)
	}
	select {
	case got := <-observed:
		wantHost := net.JoinHostPort(targetHost, port)
		if got.proto != "HTTP/2.0" || got.host != wantHost || got.serverName != targetHost || got.path != "/api-http2" {
			t.Errorf(
				"local server observed %+v; want HTTP/2.0 Host=%q SNI=%q path=/api-http2",
				got,
				wantHost,
				targetHost,
			)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for the HTTP/2 request at local server")
	}
}

func TestClientDoStrictTLSProfileMismatchStopsHTTP2Request(t *testing.T) {
	requests := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split local HTTPS listener address: %v", err)
	}
	profile, err := os.ReadFile("../../internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatalf("read TLS profile fixture: %v", err)
	}
	profileJSON := strings.ReplaceAll(string(profile), `"http/1.1"`, `"h2"`)
	profileJSON = strings.Replace(profileJSON, `"value": 771`, `"value": 770`, 1)
	profilePath := filepath.Join(t.TempDir(), "strict-h2-profile.json")
	if err = os.WriteFile(profilePath, []byte(profileJSON), 0o600); err != nil {
		t.Fatalf("write TLS profile fixture: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err = NewClient().Do(ctx, Request{
		URL:         "https://example.test:" + port + "/strict-profile",
		HTTPVersion: "2",
		Resolve:     map[string][]string{"example.test": {"127.0.0.1"}},
		Insecure:    true,
		TLSProfile: &TLSProfile{
			ProfilePath: profilePath,
			Check:       true,
			Strict:      true,
		},
	})
	var status interface{ Status() string }
	var coded interface{ ExitCode() int }
	statusOK := errors.As(err, &status)
	codeOK := errors.As(err, &coded)
	if !statusOK || status.Status() != "MISMATCH" || !codeOK || coded.ExitCode() != 4 {
		gotStatus, gotCode := "<unavailable>", -1
		if statusOK {
			gotStatus = status.Status()
		}
		if codeOK {
			gotCode = coded.ExitCode()
		}
		t.Fatalf(
			"Do() error = %v (status=%q, exit_code=%d), want strict MISMATCH with exit code 4",
			err,
			gotStatus,
			gotCode,
		)
	}
	select {
	case <-requests:
		t.Fatal("strict TLS profile mismatch sent the HTTP/2 request to the server")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestClientDoStrictTargetTLSProfileMismatchStopsHTTPProxyConnectRequest(t *testing.T) {
	targetRequests := make(chan struct{}, 1)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	_, targetPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split local HTTPS target address: %v", err)
	}
	targetAuthority := net.JoinHostPort("example.test", targetPort)

	proxyConnects := make(chan string, 1)
	proxyDone := make(chan struct{}, 1)
	proxy := httptest.NewServer(
		testStrictHTTPConnectHandler(t, target.Listener.Addr().String(), proxyConnects, proxyDone),
	)
	defer proxy.Close()

	profile, err := os.ReadFile("../../internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatalf("read TLS profile fixture: %v", err)
	}
	profileJSON := strings.Replace(string(profile), `"value": 771`, `"value": 770`, 1)
	profilePath := filepath.Join(t.TempDir(), "strict-target-profile.json")
	if err = os.WriteFile(profilePath, []byte(profileJSON), 0o600); err != nil {
		t.Fatalf("write TLS profile fixture: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err = NewClient().Do(ctx, Request{
		URL:         "https://" + targetAuthority + "/strict-target-profile",
		ProxyURL:    proxy.URL,
		HTTPVersion: "1.1",
		Insecure:    true,
		TLSProfile: &TLSProfile{
			ProfilePath: profilePath,
			Check:       true,
			Strict:      true,
		},
	})
	var status interface{ Status() string }
	var coded interface{ ExitCode() int }
	statusOK := errors.As(err, &status)
	codeOK := errors.As(err, &coded)
	if !statusOK || status.Status() != "MISMATCH" || !codeOK || coded.ExitCode() != 4 {
		gotStatus, gotCode := "<unavailable>", -1
		if statusOK {
			gotStatus = status.Status()
		}
		if codeOK {
			gotCode = coded.ExitCode()
		}
		t.Fatalf(
			"Do() error = %v (status=%q, exit_code=%d), want target MISMATCH with exit code 4",
			err,
			gotStatus,
			gotCode,
		)
	}
	select {
	case got := <-proxyConnects:
		if got != targetAuthority {
			t.Errorf("proxy CONNECT authority = %q, want %q", got, targetAuthority)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for CONNECT to be established")
	}
	select {
	case <-targetRequests:
		t.Fatal("strict target TLS profile mismatch sent the HTTP request to the target")
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case <-proxyDone:
	case <-time.After(2 * time.Second):
		t.Error("HTTP CONNECT tunnel did not close after the strict TLS profile failure")
	}
}

func TestClientDoStrictTargetTLSProfileMismatchStopsHTTPSProxyConnectRequest(t *testing.T) {
	targetRequests := make(chan struct{}, 1)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	_, targetPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split local HTTPS target address: %v", err)
	}
	targetAuthority := net.JoinHostPort("example.test", targetPort)

	proxyConnects := make(chan string, 1)
	proxyDone := make(chan struct{}, 1)
	proxy := httptest.NewTLSServer(
		testStrictHTTPConnectHandler(t, target.Listener.Addr().String(), proxyConnects, proxyDone),
	)
	defer proxy.Close()

	profile, err := os.ReadFile("../../internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatalf("read TLS profile fixture: %v", err)
	}
	profileJSON := strings.Replace(string(profile), `"value": 771`, `"value": 770`, 1)
	profilePath := filepath.Join(t.TempDir(), "strict-target-https-proxy-profile.json")
	if err = os.WriteFile(profilePath, []byte(profileJSON), 0o600); err != nil {
		t.Fatalf("write TLS profile fixture: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err = NewClient().Do(ctx, Request{
		URL:           "https://" + targetAuthority + "/strict-target-https-proxy-profile",
		ProxyURL:      proxy.URL,
		ProxyInsecure: true,
		HTTPVersion:   "1.1",
		Insecure:      true,
		TLSProfile: &TLSProfile{
			ProfilePath: profilePath,
			Check:       true,
			Strict:      true,
		},
	})
	var status interface{ Status() string }
	var coded interface{ ExitCode() int }
	statusOK := errors.As(err, &status)
	codeOK := errors.As(err, &coded)
	if !statusOK || status.Status() != "MISMATCH" || !codeOK || coded.ExitCode() != 4 {
		gotStatus, gotCode := "<unavailable>", -1
		if statusOK {
			gotStatus = status.Status()
		}
		if codeOK {
			gotCode = coded.ExitCode()
		}
		t.Fatalf(
			"Do() error = %v (status=%q, exit_code=%d), want target MISMATCH with exit code 4",
			err,
			gotStatus,
			gotCode,
		)
	}
	select {
	case got := <-proxyConnects:
		if got != targetAuthority {
			t.Errorf("HTTPS proxy CONNECT authority = %q, want %q", got, targetAuthority)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for HTTPS CONNECT to be established")
	}
	select {
	case <-targetRequests:
		t.Fatal("strict target TLS profile mismatch sent the HTTP request to the target")
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case <-proxyDone:
	case <-time.After(2 * time.Second):
		t.Error("HTTPS CONNECT tunnel did not close after the strict TLS profile failure")
	}
}

func TestClientDoStrictTargetTLSProfileMismatchStopsHTTPSProxyHTTP2ConnectRequest(t *testing.T) {
	const targetHost = "strict-h2-target.example.test"
	targetRequests := make(chan struct{}, 1)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()
	_, targetPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split local target address: %v", err)
	}
	targetAuthority := net.JoinHostPort(targetHost, targetPort)

	proxyRequests := make(chan string, 1)
	proxyDone := make(chan struct{}, 1)
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveStrictAPIHTTP2Connect(t, target.Listener.Addr().String(), targetAuthority, proxyRequests, proxyDone, w, r)
	}))
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()

	profile, err := os.ReadFile("../../internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatalf("read TLS profile fixture: %v", err)
	}
	profileJSON := strings.ReplaceAll(string(profile), `"http/1.1"`, `"h2"`)
	profileJSON = strings.Replace(profileJSON, `"value": 771`, `"value": 770`, 1)
	profilePath := filepath.Join(t.TempDir(), "strict-target-https-proxy-h2-profile.json")
	if err = os.WriteFile(profilePath, []byte(profileJSON), 0o600); err != nil {
		t.Fatalf("write TLS profile fixture: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err = NewClient().Do(ctx, Request{
		URL:               "https://" + targetAuthority + "/strict-target-https-proxy-h2-profile",
		ProxyURL:          proxy.URL,
		ProxyInsecure:     true,
		ProxyHTTP2Connect: true,
		HTTPVersion:       "2",
		Resolve:           map[string][]string{targetHost: {"127.0.0.1"}},
		Insecure:          true,
		TLSProfile: &TLSProfile{
			ProfilePath: profilePath,
			Check:       true,
			Strict:      true,
		},
	})
	var status interface{ Status() string }
	var coded interface{ ExitCode() int }
	statusOK := errors.As(err, &status)
	codeOK := errors.As(err, &coded)
	if !statusOK || status.Status() != "MISMATCH" || !codeOK || coded.ExitCode() != 4 {
		gotStatus, gotCode := "<unavailable>", -1
		if statusOK {
			gotStatus = status.Status()
		}
		if codeOK {
			gotCode = coded.ExitCode()
		}
		t.Fatalf(
			"Do() error = %v (status=%q, exit_code=%d), want target MISMATCH with exit code 4",
			err,
			gotStatus,
			gotCode,
		)
	}
	select {
	case got := <-proxyRequests:
		want := "HTTP/2.0 CONNECT " + targetAuthority
		if got != want {
			t.Errorf("HTTPS proxy observed %q, want %q", got, want)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for HTTP/2 CONNECT at local proxy")
	}
	select {
	case <-targetRequests:
		t.Fatal("strict target TLS profile mismatch sent the HTTP request to the target")
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case <-proxyDone:
	case <-time.After(2 * time.Second):
		t.Error("HTTP/2 CONNECT tunnel did not close after the strict TLS profile failure")
	}
}

func TestClientDoHTTP2ThroughHTTPSProxyConnect(t *testing.T) {
	type targetObservation struct {
		proto      string
		host       string
		serverName string
		path       string
	}
	const targetHost = "h2-connect-api.example.test"
	targetObserved := make(chan targetObservation, 1)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverName := ""
		if r.TLS != nil {
			serverName = r.TLS.ServerName
		}
		targetObserved <- targetObservation{proto: r.Proto, host: r.Host, serverName: serverName, path: r.URL.Path}
		_, _ = io.WriteString(w, "public API HTTP/2 through proxy ok")
	}))
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()
	_, targetPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split local target address: %v", err)
	}
	targetAuthority := net.JoinHostPort(targetHost, targetPort)

	proxyRequests := make(chan string, 1)
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveAPIHTTP2Connect(t, target.Listener.Addr().String(), targetAuthority, proxyRequests, w, r)
	}))
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	result, err := NewClient().Do(ctx, Request{
		URL:               "https://" + targetAuthority + "/api-h2-connect",
		ProxyURL:          proxy.URL,
		ProxyInsecure:     true,
		ProxyHTTP2Connect: true,
		HTTPVersion:       "2",
		Resolve:           map[string][]string{targetHost: {"127.0.0.1"}},
		Insecure:          true,
	})
	if err != nil {
		t.Fatalf("Do() HTTP/2 through HTTPS proxy CONNECT: %v", err)
	}
	defer func() { _ = result.Close() }()
	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("read HTTP/2 proxy response: %v", err)
	}
	if result.Response.ProtoMajor != 2 || result.Response.StatusCode != http.StatusOK ||
		string(body) != "public API HTTP/2 through proxy ok" {
		t.Fatalf(
			"response = %s %d %q; want HTTP/2 200 with expected body",
			result.Response.Proto,
			result.Response.StatusCode,
			body,
		)
	}
	select {
	case got := <-proxyRequests:
		want := "HTTP/2.0 CONNECT " + targetAuthority
		if got != want {
			t.Errorf("HTTPS proxy observed %q, want %q", got, want)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for HTTP/2 CONNECT at local proxy")
	}
	select {
	case got := <-targetObserved:
		if got.proto != "HTTP/2.0" || got.host != targetAuthority || got.serverName != targetHost ||
			got.path != "/api-h2-connect" {
			t.Errorf(
				"target observed %+v; want HTTP/2.0 Host=%q SNI=%q path=/api-h2-connect",
				got,
				targetAuthority,
				targetHost,
			)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for target HTTP/2 request")
	}
}

type apiProxyFlushWriter struct {
	writer  io.Writer
	flusher http.Flusher
}

func (w apiProxyFlushWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if err == nil {
		w.flusher.Flush()
	}
	return n, err
}

func TestClientDoHTTP3AgainstLocalQUICServer(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for local QUIC server: %v", err)
	}
	requests := make(chan string, 1)
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests <- r.Proto + " " + r.URL.Path
			_, _ = io.WriteString(w, "public API HTTP/3 ok")
		}),
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(packetConn) }()
	defer func() {
		_ = server.Close()
		_ = packetConn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	result, err := NewClient().Do(ctx, Request{
		URL:         "https://" + packetConn.LocalAddr().String() + "/api-http3",
		HTTPVersion: "3",
		Insecure:    true, // The local test certificate is self-signed.
	})
	if err != nil {
		select {
		case serveErr := <-serveErr:
			t.Fatalf("Do() HTTP/3 request error = %v (server: %v)", err, serveErr)
		default:
			t.Fatalf("Do() HTTP/3 request error = %v", err)
		}
	}
	defer func() { _ = result.Close() }()
	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 response: %v", err)
	}
	if result.Response.ProtoMajor != 3 || result.Response.StatusCode != http.StatusOK ||
		string(body) != "public API HTTP/3 ok" {
		t.Fatalf(
			"response = %s %d %q; want HTTP/3 200 with expected body",
			result.Response.Proto,
			result.Response.StatusCode,
			body,
		)
	}
	select {
	case got := <-requests:
		if got != "HTTP/3.0 /api-http3" {
			t.Errorf("local server observed %q; want HTTP/3.0 /api-http3", got)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for the HTTP/3 request at local server")
	}
}

func TestClientDoRejectsTLSProfileWithHTTP3BeforeNetwork(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for QUIC packets: %v", err)
	}
	defer func() { _ = packetConn.Close() }()

	profile, err := os.ReadFile("../../internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatalf("read TLS profile fixture: %v", err)
	}
	profilePath := filepath.Join(t.TempDir(), "strict-http3-profile.json")
	if err = os.WriteFile(profilePath, profile, 0o600); err != nil {
		t.Fatalf("write TLS profile fixture: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err = NewClient().Do(ctx, Request{
		URL:         "https://" + packetConn.LocalAddr().String() + "/tls-profile-http3",
		HTTPVersion: "3",
		TLSProfile: &TLSProfile{
			ProfilePath: profilePath,
			Check:       true,
			Strict:      true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "--tls-profile cannot be combined") ||
		!strings.Contains(err.Error(), "HTTP/3") {
		t.Fatalf("Do() error = %v, want explicit TLS-profile/HTTP/3 incompatibility", err)
	}
	if err = packetConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set QUIC listener deadline: %v", err)
	}
	buffer := make([]byte, 2048)
	if n, addr, readErr := packetConn.ReadFrom(buffer); readErr == nil {
		t.Fatalf("incompatible HTTP/3 request sent %d QUIC bytes to %v before validation", n, addr)
	} else if timeoutErr, ok := readErr.(net.Error); !ok || !timeoutErr.Timeout() {
		t.Fatalf("QUIC listener ReadFrom() error = %v, want timeout with no network packet", readErr)
	}
}

func TestClientDoRejectsUnsupportedTLSProfileBeforeNetwork(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	profilePath, err := filepath.Abs("../../internal/client/utlsengine/testdata/profile-v1-unsupported.json")
	if err != nil {
		t.Fatalf("resolve unsupported profile fixture: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = NewClient().Do(ctx, Request{
		URL: "https://" + listener.Addr().String() + "/unsupported-profile",
		TLSProfile: &TLSProfile{
			ProfilePath: profilePath,
		},
	})
	var unsupportedErr *utlsengine.UnsupportedProfileError
	if !errors.As(err, &unsupportedErr) || unsupportedErr.Status() != "UNSUPPORTED" {
		t.Fatalf("Do() error = %v, want typed UNSUPPORTED profile error", err)
	}

	if tcpListener, ok := listener.(*net.TCPListener); ok {
		if err = tcpListener.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatalf("set listener deadline: %v", err)
		}
	}
	connection, acceptErr := listener.Accept()
	if acceptErr == nil {
		_ = connection.Close()
		t.Fatal("Go API connected to the target before rejecting the unsupported profile")
	}
	if timeoutErr, ok := acceptErr.(net.Error); !ok || !timeoutErr.Timeout() {
		t.Fatalf("listener Accept() error = %v, want timeout proving no dial", acceptErr)
	}
}

func TestClientDoReportsConnectionErrorAfterTLSHandshakeStarts(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			acceptErr = connection.Close()
		}
		accepted <- acceptErr
	}()

	profilePath, err := filepath.Abs("../../internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatalf("resolve valid profile fixture: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = NewClient().Do(ctx, Request{
		URL: "https://" + listener.Addr().String() + "/connection-error",
		TLSProfile: &TLSProfile{
			ProfilePath: profilePath,
			Check:       true,
		},
	})
	var profileErr *utlsengine.ProfileCheckError
	if !errors.As(err, &profileErr) || profileErr.Status() != "CONNECTION_ERROR" || profileErr.ExitCode() != 3 {
		t.Fatalf("Do() error = %v, want typed CONNECTION_ERROR with exit code 3", err)
	}
	select {
	case acceptErr := <-accepted:
		if acceptErr != nil {
			t.Fatalf("accept and close TLS connection: %v", acceptErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Go API did not establish the TCP connection before reporting CONNECTION_ERROR")
	}
}

func TestClientDoReportsIncompleteWhenClientHelloWriteIsInterrupted(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	firstChunkRead := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			firstChunkRead <- acceptErr
			return
		}
		buffer := make([]byte, 5)
		_, readErr := io.ReadFull(connection, buffer)
		if tcpConnection, ok := connection.(*net.TCPConn); ok {
			if lingerErr := tcpConnection.SetLinger(0); readErr == nil {
				readErr = lingerErr
			}
		}
		if closeErr := connection.Close(); readErr == nil {
			readErr = closeErr
		}
		firstChunkRead <- readErr
	}()

	profilePath, err := filepath.Abs("../../internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatalf("resolve valid profile fixture: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = NewClient().Do(ctx, Request{
		URL: "https://" + listener.Addr().String() + "/incomplete-client-hello",
		TLSSplitHello: &TLSSplitHello{
			FirstChunkSize: 5,
			Delay:          250 * time.Millisecond,
		},
		TLSProfile: &TLSProfile{
			ProfilePath: profilePath,
			Check:       true,
		},
	})
	var profileErr *utlsengine.ProfileCheckError
	if !errors.As(err, &profileErr) || profileErr.Status() != "INCOMPLETE" || profileErr.ExitCode() != 5 {
		t.Fatalf("Do() error = %v, want typed INCOMPLETE with exit code 5", err)
	}
	select {
	case readErr := <-firstChunkRead:
		if readErr != nil {
			t.Fatalf("read and abort first ClientHello chunk: %v", readErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Go API did not send the first ClientHello chunk")
	}
}

func TestClientDoStreamingBodyFailureDoesNotRetry(t *testing.T) {
	t.Run("context cancellation", func(t *testing.T) {
		requestStarted := make(chan struct{}, 1)
		var requestCount atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			requestCount.Add(1)
			requestStarted <- struct{}{}
			_, _ = io.Copy(io.Discard, request.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := NewClient().Do(ctx, Request{
				URL:    server.URL + "/cancel-stream",
				Method: http.MethodPost,
				Body:   contextBlockingReader{ctx: ctx},
			})
			result <- err
		}()

		select {
		case <-requestStarted:
			cancel()
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatal("server did not receive request headers before cancellation")
		}
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Do() error = %v, want context.Canceled", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Do() did not return after context cancellation")
		}
		if got := requestCount.Load(); got != 1 {
			t.Fatalf("request count = %d, want one attempt", got)
		}
	})

	t.Run("reader error", func(t *testing.T) {
		var requestCount atomic.Int32
		requestStarted := make(chan struct{}, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			requestCount.Add(1)
			requestStarted <- struct{}{}
			_, _ = io.Copy(io.Discard, request.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		bodyErr := errors.New("stream body failed")
		body := &failAfterReader{data: []byte("partial-body"), err: bodyErr}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := NewClient().Do(ctx, Request{
			URL:           server.URL + "/reader-error",
			Method:        http.MethodPost,
			Body:          body,
			ContentLength: int64(len("partial-body") + 10),
		})
		if !errors.Is(err, bodyErr) {
			t.Fatalf("Do() error = %v, want streaming body error", err)
		}
		select {
		case <-requestStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("server did not observe the request before the body reader failed")
		}
		if got := requestCount.Load(); got != 1 {
			t.Fatalf("request count = %d, want one attempt", got)
		}
	})
}

func TestClientDoRejectsWebSocketHTTPVersionsBeforeNetwork(t *testing.T) {
	for _, tc := range []struct {
		name        string
		scheme      string
		httpVersion string
	}{
		{name: "ws HTTP/2", scheme: "ws", httpVersion: "2"},
		{name: "wss HTTP/2", scheme: "wss", httpVersion: "2"},
		{name: "ws HTTP/3", scheme: "ws", httpVersion: "3"},
		{name: "wss HTTP/3", scheme: "wss", httpVersion: "3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen for unexpected WebSocket connection: %v", err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err = NewClient().Do(ctx, Request{
				URL:         tc.scheme + "://" + listener.Addr().String() + "/socket",
				HTTPVersion: tc.httpVersion,
			})
			if err == nil || !strings.Contains(err.Error(), "WebSocket requests require HTTP/1.1") {
				t.Fatalf("Do() error = %v, want WebSocket/HTTP-version incompatibility", err)
			}
			tcpListener := listener.(*net.TCPListener)
			if err = tcpListener.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatalf("set listener deadline: %v", err)
			}
			conn, acceptErr := tcpListener.Accept()
			if conn != nil {
				_ = conn.Close()
				t.Fatal("incompatible WebSocket request reached the network before validation")
			}
			if timeoutErr, ok := acceptErr.(net.Error); !ok || !timeoutErr.Timeout() {
				t.Fatalf("listener Accept() error = %v, want timeout with no connection", acceptErr)
			}
		})
	}
}

func TestClientDoRejectsHTTP3HTTPProxyBeforeNetwork(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen for proxy: %v", err)
			}
			defer func() { _ = listener.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err = NewClient().Do(ctx, Request{
				URL:         "https://target.example.test/",
				ProxyURL:    scheme + "://" + listener.Addr().String(),
				HTTPVersion: "3",
			})
			if err == nil || !strings.Contains(err.Error(), "does not support HTTP(S) proxies") {
				t.Fatalf("Do() error = %v, want HTTP/3/HTTP(S)-proxy incompatibility", err)
			}

			tcpListener := listener.(*net.TCPListener)
			if err = tcpListener.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatalf("set proxy listener deadline: %v", err)
			}
			conn, acceptErr := tcpListener.Accept()
			if conn != nil {
				_ = conn.Close()
				t.Fatal("incompatible HTTP/3 request reached proxy before validation")
			}
			if timeoutErr, ok := acceptErr.(net.Error); !ok || !timeoutErr.Timeout() {
				t.Fatalf("proxy Accept() error = %v, want timeout with no network connection", acceptErr)
			}
		})
	}
}

func TestClientDoRejectsManualTCPClientHelloWithHTTP3BeforeNetwork(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for QUIC packets: %v", err)
	}
	defer func() { _ = listener.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = NewClient().Do(ctx, Request{
		URL:         "https://" + listener.LocalAddr().String() + "/",
		HTTPVersion: "3",
		TLSProfile: &TLSProfile{ClientHello: &TLSClientHello{
			Preset: "chrome-120",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "manual TCP TLS ClientHello profiles cannot be used with HTTP/3") {
		t.Fatalf("Do() error = %v, want manual TCP ClientHello/HTTP/3 incompatibility", err)
	}
	if err = listener.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set QUIC listener deadline: %v", err)
	}
	buffer := make([]byte, 2048)
	if n, addr, readErr := listener.ReadFrom(buffer); readErr == nil {
		t.Fatalf("incompatible HTTP/3 request sent %d QUIC bytes to %v before validation", n, addr)
	} else if timeoutErr, ok := readErr.(net.Error); !ok || !timeoutErr.Timeout() {
		t.Fatalf("QUIC listener ReadFrom() error = %v, want timeout with no network packet", readErr)
	}
}

func serveSOCKS5Tunnel(
	t *testing.T,
	listener net.Listener,
	targetAddress string,
	addrType chan<- byte,
	done chan<- struct{},
) {
	t.Helper()
	defer close(done)
	clientConn, err := listener.Accept()
	if err != nil {
		return
	}
	defer func() { _ = clientConn.Close() }()
	var greeting [2]byte
	if _, err = io.ReadFull(clientConn, greeting[:]); err != nil {
		t.Errorf("read SOCKS greeting: %v", err)
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err = io.ReadFull(clientConn, methods); err != nil {
		t.Errorf("read SOCKS methods: %v", err)
		return
	}
	if _, err = clientConn.Write([]byte{5, 0}); err != nil {
		t.Errorf("write SOCKS method selection: %v", err)
		return
	}
	var requestHeader [4]byte
	if _, err = io.ReadFull(clientConn, requestHeader[:]); err != nil {
		t.Errorf("read SOCKS CONNECT request: %v", err)
		return
	}
	addrType <- requestHeader[3]
	switch requestHeader[3] {
	case 1:
		var addressAndPort [6]byte
		_, err = io.ReadFull(clientConn, addressAndPort[:])
	case 3:
		var length [1]byte
		if _, err = io.ReadFull(clientConn, length[:]); err == nil {
			addressAndPort := make([]byte, int(length[0])+2)
			_, err = io.ReadFull(clientConn, addressAndPort)
		}
	case 4:
		var addressAndPort [18]byte
		_, err = io.ReadFull(clientConn, addressAndPort[:])
	default:
		t.Errorf("unexpected SOCKS address type %d", requestHeader[3])
		return
	}
	if err != nil {
		t.Errorf("read SOCKS CONNECT address: %v", err)
		return
	}
	targetConn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		t.Errorf("dial local HTTPS target: %v", err)
		return
	}
	defer func() { _ = targetConn.Close() }()
	if _, err = clientConn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Errorf("write SOCKS CONNECT success: %v", err)
		return
	}
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(targetConn, clientConn)
		if tcpConn, ok := targetConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		close(copyDone)
	}()
	_, _ = io.Copy(clientConn, targetConn)
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
	<-copyDone
}

func TestClientDoConnectTimeoutStopsStalledSOCKSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan net.Conn, 1)
	releaseProxy := make(chan struct{})
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- conn
		defer func() { _ = conn.Close() }()
		greeting := make([]byte, 3)
		if _, readErr := io.ReadFull(conn, greeting); readErr == nil {
			<-releaseProxy // Receive the greeting, then deliberately stall.
		}
	}()

	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_, err = NewClient().Do(ctx, Request{
		URL:            "http://192.0.2.1/",
		ProxyURL:       "socks5://" + listener.Addr().String(),
		ConnectTimeout: time.Second,
	})
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("Do() with a stalled SOCKS5 handshake unexpectedly succeeded")
	}
	if elapsed > 2500*time.Millisecond {
		t.Errorf("Do() took %s to honor one-second ConnectTimeout", elapsed)
	}
	close(releaseProxy)
	select {
	case conn := <-accepted:
		_ = conn.Close() // Ensure the intentionally stalled test peer exits cleanly.
	default:
	}
	_ = listener.Close()
	<-proxyDone
}

func TestClientDoOHTTPUsesGatewayAndPreservesRequest(t *testing.T) {
	privateConfig, err := ohttp.NewConfig(1, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	if err != nil {
		t.Fatalf("create OHTTP config: %v", err)
	}
	gateway := ohttp.NewDefaultGateway([]ohttp.PrivateConfig{privateConfig})
	const payload = "api-ohttp-body"
	var observation apiOHTTPInnerRequestObservation
	var connectionCount atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveAPIRecordedOHTTPGateway(w, r, privateConfig, gateway, &observation)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connectionCount.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()

	result, err := NewClient().Do(context.Background(), Request{
		URL:             "https://hidden-target.example.test/private%2Fresource?mode=api",
		Method:          http.MethodPost,
		Headers:         []Header{{Name: "X-Inner-Request", Value: "preserved"}},
		Body:            strings.NewReader(payload),
		ContentLength:   int64(len(payload)),
		HTTPVersion:     "1.1",
		Insecure:        true,
		OHTTPGatewayURL: server.URL + "/gateway",
		OHTTPKeysURL:    server.URL + "/keys",
	})
	if err != nil {
		t.Fatalf("Do() with OHTTP API configuration: %v", err)
	}
	defer func() { _ = result.Close() }()
	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("read decrypted OHTTP response: %v", err)
	}
	if result.Response.StatusCode != http.StatusCreated || string(body) != "decrypted response" ||
		result.Response.Header.Get("X-OHTTP-API") != "ok" {
		t.Fatalf(
			"response = %d, headers %v, body %q; want decrypted 201 response",
			result.Response.StatusCode,
			result.Response.Header,
			body,
		)
	}
	if observation.method != http.MethodPost ||
		observation.url != "https://hidden-target.example.test/private%2Fresource?mode=api" ||
		observation.body != payload ||
		observation.header != "preserved" {
		t.Errorf(
			"decrypted request = %s %q header %q body %q; want exact URL/query, custom header, and body %q",
			observation.method,
			observation.url,
			observation.header,
			observation.body,
			payload,
		)
	}
	if got := connectionCount.Load(); got != 1 {
		t.Fatalf("OHTTP TLS connections = %d, want one connection shared by keys and gateway", got)
	}
	foundReuse := false
	for _, report := range result.TLSReports {
		if report.Leg == "gateway" && report.CaptureStatus == "REUSED_CONNECTION" {
			foundReuse = true
		}
	}
	if !foundReuse {
		t.Fatalf("OHTTP TLS reports = %+v, want a real gateway REUSED_CONNECTION report", result.TLSReports)
	}
}

func TestClientDoOHTTPThroughHTTPAndSOCKSProxies(t *testing.T) {
	privateConfig, err := ohttp.NewConfig(1, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	if err != nil {
		t.Fatalf("create OHTTP config: %v", err)
	}
	gateway := ohttp.NewDefaultGateway([]ohttp.PrivateConfig{privateConfig})
	var gatewayConnections atomic.Int32
	observedTargets := make(chan string, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveAPIProxiedOHTTPGateway(w, r, privateConfig, gateway, observedTargets)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			gatewayConnections.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	for _, tc := range []struct {
		name          string
		proxyScheme   string
		proxyInsecure bool
		wantSOCKSATYP byte
	}{
		{name: "HTTP proxy", proxyScheme: "http"},
		{name: "HTTPS proxy", proxyScheme: "https", proxyInsecure: true},
		{name: "SOCKS5", proxyScheme: "socks5", wantSOCKSATYP: 1},
		{name: "SOCKS5H", proxyScheme: "socks5h", wantSOCKSATYP: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var proxyURL string
			var proxyRequests, proxyConnections atomic.Int32
			var proxyServer *httptest.Server
			var proxyListener net.Listener
			var socksATYP chan byte
			var socksDone chan struct{}
			if tc.proxyScheme == "http" || tc.proxyScheme == "https" {
				proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					serveAPIOHTTPConnect(w, r, server.Listener.Addr().String(), &proxyRequests)
				})
				proxyServer = httptest.NewUnstartedServer(proxyHandler)
				proxyServer.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateNew {
						proxyConnections.Add(1)
					}
				}
				if tc.proxyScheme == "https" {
					proxyServer.StartTLS()
				} else {
					proxyServer.Start()
				}
				defer proxyServer.Close()
				proxyURL = proxyServer.URL
			} else {
				proxyListener, err = net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("listen for local SOCKS proxy: %v", err)
				}
				defer proxyListener.Close()
				socksATYP = make(chan byte, 1)
				socksDone = make(chan struct{})
				go serveSOCKS5Tunnel(t, proxyListener, server.Listener.Addr().String(), socksATYP, socksDone)
				proxyURL = tc.proxyScheme + "://" + proxyListener.Addr().String()
			}

			keysURL, gatewayURL := apiOHTTPEndpoints(t, server.URL, tc.proxyScheme)
			const targetURL = "https://hidden-ohttp.example.test/resource?via=proxy"
			connectionsBeforeRequest := gatewayConnections.Load()
			result, requestErr := NewClient().Do(context.Background(), Request{
				URL:             targetURL,
				HTTPVersion:     "1.1",
				ProxyURL:        proxyURL,
				ProxyInsecure:   tc.proxyInsecure,
				OHTTPKeysURL:    keysURL.String(),
				OHTTPGatewayURL: gatewayURL.String(),
			})
			if requestErr != nil {
				t.Fatalf("Do() through %s: %v", tc.name, requestErr)
			}
			body, readErr := io.ReadAll(result.Response.Body)
			if readErr != nil {
				t.Fatalf("read OHTTP response through %s: %v", tc.name, readErr)
			}
			if result.Response.StatusCode != http.StatusCreated || string(body) != "ohttp-proxy-ok" ||
				result.Response.Header.Get("X-OHTTP-Route") != "verified" {
				t.Fatalf(
					"OHTTP response through %s = %d, %v, %q",
					tc.name,
					result.Response.StatusCode,
					result.Response.Header,
					body,
				)
			}
			if closeErr := result.Close(); closeErr != nil {
				t.Fatalf("close OHTTP result through %s: %v", tc.name, closeErr)
			}
			select {
			case got := <-observedTargets:
				if got != targetURL {
					t.Errorf("decrypted target through %s = %q, want %q", tc.name, got, targetURL)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("OHTTP gateway was not reached through %s", tc.name)
			}
			if got := gatewayConnections.Load() - connectionsBeforeRequest; got != 1 {
				t.Errorf("gateway connections through %s = %d, want one shared connection", tc.name, got)
			}
			assertAPIOHTTPProxyReuse(
				t,
				tc.name,
				tc.wantSOCKSATYP,
				socksATYP,
				socksDone,
				&proxyRequests,
				&proxyConnections,
			)
		})
	}
}

func TestClientDoUsesCustomDNSUpstreamAndIPv4Only(t *testing.T) {
	const hostname = "api-dns.example.test"
	var aQueries, aaaaQueries atomic.Int32
	dnsPacketConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for DNS: %v", err)
	}
	dnsServer := &dns.Server{
		PacketConn: dnsPacketConn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(req)
			for _, question := range req.Question {
				switch question.Qtype {
				case dns.TypeA:
					aQueries.Add(1)
					response.Answer = append(response.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
						A:   net.ParseIP("127.0.0.1"),
					})
				case dns.TypeAAAA:
					aaaaQueries.Add(1)
				}
			}
			_ = w.WriteMsg(response)
		}),
	}
	go func() { _ = dnsServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = dnsServer.Shutdown()
		_ = dnsPacketConn.Close()
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns-upstream" {
			t.Errorf("request path = %q, want /dns-upstream", r.URL.Path)
		}
		_, _ = io.WriteString(w, "custom DNS route ok")
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("SplitHostPort(server URL) error = %v", err)
	}
	result, err := NewClient().Do(context.Background(), Request{
		URL:        "http://" + net.JoinHostPort(hostname, port) + "/dns-upstream",
		IPVersion:  "4",
		DNSServers: []string{dnsPacketConn.LocalAddr().String()},
	})
	if err != nil {
		t.Fatalf("Do() with custom DNS and IPv4-only resolution: %v", err)
	}
	defer func() { _ = result.Close() }()
	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if result.Response.StatusCode != http.StatusOK || string(body) != "custom DNS route ok" {
		t.Fatalf("response = %d %q, want 200 with custom DNS response", result.Response.StatusCode, body)
	}
	if aQueries.Load() != 1 || aaaaQueries.Load() != 0 {
		t.Errorf("custom DNS query counts: A=%d AAAA=%d; want A=1 AAAA=0", aQueries.Load(), aaaaQueries.Load())
	}
}

func TestClientDoOverridesTLSServerNameWithoutChangingHTTPHost(t *testing.T) {
	const serverName = "sni-override.example.test"
	var expectedHost string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.ServerName != serverName {
			t.Errorf("TLS SNI = %v, want %q", r.TLS, serverName)
		}
		if r.Host != expectedHost {
			t.Errorf("HTTP Host = %q, want %q", r.Host, expectedHost)
		}
		if r.URL.Path != "/sni" {
			t.Errorf("request path = %q, want /sni", r.URL.Path)
		}
		_, _ = io.WriteString(w, "sni override ok")
	}))
	defer server.Close()
	expectedHost = strings.TrimPrefix(server.URL, "https://")

	result, err := NewClient().Do(context.Background(), Request{
		URL:           server.URL + "/sni",
		TLSServerName: serverName,
		Insecure:      true, // The httptest TLS certificate is self-signed.
	})
	if err != nil {
		t.Fatalf("Do() with TLSServerName override: %v", err)
	}
	defer func() { _ = result.Close() }()
	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if result.Response.StatusCode != http.StatusOK || string(body) != "sni override ok" {
		t.Fatalf("response = %d %q, want 200 with SNI override body", result.Response.StatusCode, body)
	}
}

func TestClientDoHTTP11ThroughHTTPSProxyConnect(t *testing.T) {
	const targetHost = "https-target.example.test"
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/via-https-proxy" {
			t.Errorf("target request = %s %s, want GET /via-https-proxy", r.Method, r.URL.Path)
		}
		if !strings.HasPrefix(r.Host, targetHost+":") {
			t.Errorf("target Host = %q, want %s:<port>", r.Host, targetHost)
		}
		if r.TLS == nil || r.TLS.ServerName != targetHost {
			t.Errorf("target TLS SNI = %v, want %q", r.TLS, targetHost)
		}
		_, _ = io.WriteString(w, "https proxy tunnel ok")
	}))
	defer target.Close()

	_, targetPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(target) error = %v", err)
	}
	targetAddress := net.JoinHostPort(targetHost, targetPort)
	proxyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveAPIHTTP11HTTPSConnect(t, targetAddress, target.Listener.Addr().String(), w, r)
	}))
	defer proxyServer.Close()

	result, err := NewClient().Do(context.Background(), Request{
		URL:           "https://" + targetAddress + "/via-https-proxy",
		ProxyURL:      proxyServer.URL,
		ProxyInsecure: true,
		HTTPVersion:   "1.1",
		Resolve:       map[string][]string{targetHost: {"127.0.0.1"}},
		Insecure:      true, // Both local httptest TLS certificates are self-signed.
		TLSProfile: &TLSProfile{
			ProfilePath:      "../../internal/client/utlsengine/testdata/profile-v1-valid.json",
			Check:            true,
			ProxyProfilePath: "../../internal/client/utlsengine/testdata/profile-v1-valid.json",
			ProxyCheck:       true,
		},
	})
	if err != nil {
		t.Fatalf("Do() through HTTPS proxy: %v", err)
	}
	defer func() { _ = result.Close() }()

	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if result.Response.StatusCode != http.StatusOK || string(body) != "https proxy tunnel ok" {
		t.Fatalf("response = %d %q, want 200 with tunneled target body", result.Response.StatusCode, body)
	}
	assertAPIHTTP11ProxyTLSReports(t, result)
}

func TestClientDoStrictProxyTLSProfileMismatchStopsBeforeConnect(t *testing.T) {
	connectRequests := make(chan struct{}, 1)
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		connectRequests <- struct{}{}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer proxy.Close()

	profile, err := os.ReadFile("../../internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatalf("read TLS profile fixture: %v", err)
	}
	profileJSON := strings.Replace(string(profile), `"value": 771`, `"value": 770`, 1)
	profilePath := filepath.Join(t.TempDir(), "strict-proxy-profile.json")
	if err = os.WriteFile(profilePath, []byte(profileJSON), 0o600); err != nil {
		t.Fatalf("write TLS profile fixture: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err = NewClient().Do(ctx, Request{
		URL:           "https://target.example.test:8443/strict-proxy-profile",
		ProxyURL:      proxy.URL,
		ProxyInsecure: true,
		HTTPVersion:   "1.1",
		TLSProfile: &TLSProfile{
			ProxyProfilePath: profilePath,
			ProxyCheck:       true,
			ProxyStrict:      true,
		},
	})
	var status interface{ Status() string }
	var coded interface{ ExitCode() int }
	statusOK := errors.As(err, &status)
	codeOK := errors.As(err, &coded)
	if !statusOK || status.Status() != "MISMATCH" || !codeOK || coded.ExitCode() != 4 {
		gotStatus, gotCode := "<unavailable>", -1
		if statusOK {
			gotStatus = status.Status()
		}
		if codeOK {
			gotCode = coded.ExitCode()
		}
		t.Fatalf(
			"Do() error = %v (status=%q, exit_code=%d), want proxy MISMATCH with exit code 4",
			err,
			gotStatus,
			gotCode,
		)
	}
	select {
	case <-connectRequests:
		t.Fatal("strict proxy TLS profile mismatch sent CONNECT to the proxy")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestClientDoStrictProxyTLSProfileMismatchStopsHTTP2Connect(t *testing.T) {
	connectRequests := make(chan struct{}, 1)
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		connectRequests <- struct{}{}
		http.Error(w, "unexpected CONNECT", http.StatusBadRequest)
	}))
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()

	profile, err := os.ReadFile("../../internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatalf("read TLS profile fixture: %v", err)
	}
	profileJSON := strings.ReplaceAll(string(profile), `"http/1.1"`, `"h2"`)
	profileJSON = strings.Replace(profileJSON, `"value": 771`, `"value": 770`, 1)
	profilePath := filepath.Join(t.TempDir(), "strict-proxy-h2-profile.json")
	if err = os.WriteFile(profilePath, []byte(profileJSON), 0o600); err != nil {
		t.Fatalf("write TLS profile fixture: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err = NewClient().Do(ctx, Request{
		URL:               "https://target.example.test:8443/strict-proxy-h2-profile",
		ProxyURL:          proxy.URL,
		ProxyInsecure:     true,
		ProxyHTTP2Connect: true,
		HTTPVersion:       "2",
		TLSProfile: &TLSProfile{
			ProxyProfilePath: profilePath,
			ProxyCheck:       true,
			ProxyStrict:      true,
		},
	})
	var status interface{ Status() string }
	var coded interface{ ExitCode() int }
	statusOK := errors.As(err, &status)
	codeOK := errors.As(err, &coded)
	if !statusOK || status.Status() != "MISMATCH" || !codeOK || coded.ExitCode() != 4 {
		gotStatus, gotCode := "<unavailable>", -1
		if statusOK {
			gotStatus = status.Status()
		}
		if codeOK {
			gotCode = coded.ExitCode()
		}
		t.Fatalf(
			"Do() error = %v (status=%q, exit_code=%d), want proxy MISMATCH with exit code 4",
			err,
			gotStatus,
			gotCode,
		)
	}
	select {
	case <-connectRequests:
		t.Fatal("strict proxy TLS profile mismatch sent HTTP/2 CONNECT")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestDoWithTransportPreservesProfileCheckError(t *testing.T) {
	want := utlsengine.NewProfileCheckError("REUSED_CONNECTION", nil)
	request, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DoWithTransport(
		context.Background(),
		request,
		roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, want
		}),
	)
	var status interface{ Status() string }
	var coded interface{ ExitCode() int }
	if !errors.As(err, &status) || status.Status() != "REUSED_CONNECTION" ||
		!errors.As(err, &coded) || coded.ExitCode() != 5 {
		t.Fatalf("DoWithTransport() error = %v, want REUSED_CONNECTION and exit code 5", err)
	}
}

type wssRouteObservation struct {
	host       string
	serverName string
	key        string
}

func exchangeWSSRouteTarget(rw *bufio.ReadWriter) {
	var err error
	var header [2]byte
	if _, err = io.ReadFull(rw.Reader, header[:]); err != nil {
		return
	}
	if header[0] != 0x81 || header[1]&0x80 == 0 || header[1]&0x7f > 125 {
		return
	}
	mask := make([]byte, 4)
	if _, err = io.ReadFull(rw.Reader, mask); err != nil {
		return
	}
	payload := make([]byte, int(header[1]&0x7f))
	if _, err = io.ReadFull(rw.Reader, payload); err != nil {
		return
	}
	for i := range payload {
		payload[i] ^= mask[i%len(mask)]
	}
	if string(payload) != "ping" {
		return
	}
	if _, err = rw.Write([]byte{0x81, 4, 'p', 'o', 'n', 'g'}); err == nil {
		_ = rw.Flush()
	}
}

func exchangeWSSRouteClient(t *testing.T, stream io.ReadWriteCloser, result *Result) {
	t.Helper()
	var doErr error
	mask := []byte{0x11, 0x22, 0x33, 0x44}
	frame := []byte{0x81, 0x84}
	frame = append(frame, mask...)
	for i, value := range []byte("ping") {
		frame = append(frame, value^mask[i%len(mask)])
	}
	if _, doErr = stream.Write(frame); doErr != nil {
		_ = result.Close()
		t.Fatalf("write masked WSS frame: %v", doErr)
	}
	var responseHeader [2]byte
	if _, doErr = io.ReadFull(stream, responseHeader[:]); doErr != nil {
		_ = result.Close()
		t.Fatalf("read WSS frame header: %v", doErr)
	}
	responsePayload := make([]byte, int(responseHeader[1]&0x7f))
	if responseHeader != [2]byte{0x81, 4} {
		_ = result.Close()
		t.Fatalf("WSS frame header = %x, want 8104", responseHeader)
	}
	if _, doErr = io.ReadFull(stream, responsePayload); doErr != nil {
		_ = result.Close()
		t.Fatalf("read WSS frame payload: %v", doErr)
	}
	if string(responsePayload) != "pong" {
		t.Errorf("server WSS frame = %q, want pong", responsePayload)
	}
}

func serveWSSRouteTarget(
	w http.ResponseWriter,
	r *http.Request,
	websocketGUID string,
	observed chan<- wssRouteObservation,
) {
	if r.Method != http.MethodGet || r.URL.Path != "/socket" ||
		!strings.EqualFold(r.Header.Get("Connection"), "Upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "invalid WebSocket upgrade", http.StatusBadRequest)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decodedKey) != 16 {
		http.Error(w, "invalid WebSocket key", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	// #nosec G401 -- SHA-1 is mandated by the WebSocket handshake (RFC 6455), not a security hash choice.
	acceptInput := sha1.Sum([]byte(key + websocketGUID))
	accept := base64.StdEncoding.EncodeToString(acceptInput[:])
	// #nosec G705 -- Raw WebSocket 101 headers with a base64 handshake value, not an HTML response.
	if _, err = fmt.Fprintf(
		rw,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		accept,
	); err == nil {
		err = rw.Flush()
	}
	if err != nil {
		return
	}
	serverName := ""
	if r.TLS != nil {
		serverName = r.TLS.ServerName
	}
	observed <- wssRouteObservation{host: r.Host, serverName: serverName, key: key}

	exchangeWSSRouteTarget(rw)
}

func exchangeWebSocketWireTarget(rw *bufio.ReadWriter, exchangeErr chan<- error) {
	var err error
	var frameHeader [2]byte
	if _, err = io.ReadFull(rw.Reader, frameHeader[:]); err != nil {
		exchangeErr <- fmt.Errorf("read client WebSocket frame header: %w", err)
		return
	}
	if frameHeader[0] != 0x81 || frameHeader[1]&0x80 == 0 || frameHeader[1]&0x7f > 125 {
		exchangeErr <- fmt.Errorf("invalid client WebSocket frame header %x", frameHeader)
		return
	}
	mask := make([]byte, 4)
	if _, err = io.ReadFull(rw.Reader, mask); err != nil {
		exchangeErr <- fmt.Errorf("read client WebSocket mask: %w", err)
		return
	}
	payload := make([]byte, int(frameHeader[1]&0x7f))
	if _, err = io.ReadFull(rw.Reader, payload); err != nil {
		exchangeErr <- fmt.Errorf("read client WebSocket payload: %w", err)
		return
	}
	for i := range payload {
		payload[i] ^= mask[i%len(mask)]
	}
	if string(payload) != "ping" {
		exchangeErr <- fmt.Errorf("client WebSocket message = %q, want ping", payload)
		return
	}
	if _, err = rw.Write([]byte{0x81, 4, 'p', 'o', 'n', 'g'}); err == nil {
		err = rw.Flush()
	}
	if err != nil {
		exchangeErr <- fmt.Errorf("write server WebSocket frame: %w", err)
		return
	}
	exchangeErr <- nil
}

func serveWebSocketWireHandshake(
	w http.ResponseWriter,
	r *http.Request,
	websocketGUID string,
	handshakeErr, exchangeErr chan<- error,
) {
	if r.Method != http.MethodGet || r.URL.Path != "/socket" ||
		!strings.EqualFold(r.Header.Get("Connection"), "Upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		r.Header.Get("Sec-WebSocket-Version") != "13" {
		handshakeErr <- fmt.Errorf("unexpected WebSocket request: %s %s, headers=%v", r.Method, r.URL, r.Header)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decodedKey) != 16 {
		handshakeErr <- fmt.Errorf("invalid Sec-WebSocket-Key %q: decoded length %d, err=%v", key, len(decodedKey), err)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		handshakeErr <- errors.New("HTTP test server does not support connection hijacking")
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		handshakeErr <- fmt.Errorf("hijack WebSocket connection: %w", err)
		return
	}
	// #nosec G401 -- SHA-1 is mandated by the WebSocket handshake (RFC 6455), not a security hash choice.
	acceptInput := sha1.Sum([]byte(key + websocketGUID))
	accept := base64.StdEncoding.EncodeToString(acceptInput[:])
	// #nosec G705 -- Raw WebSocket 101 headers with a base64 handshake value, not an HTML response.
	if _, err = fmt.Fprintf(
		rw,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		accept,
	); err == nil {
		err = rw.Flush()
	}
	if err != nil {
		_ = conn.Close()
		handshakeErr <- fmt.Errorf("write WebSocket handshake response: %w", err)
		return
	}
	defer conn.Close()
	handshakeErr <- nil

	exchangeWebSocketWireTarget(rw, exchangeErr)
}

func serveWebSocketSOCKSTarget(
	w http.ResponseWriter,
	r *http.Request,
	websocketGUID string,
	observedRequest chan<- string,
) {
	if r.Method != http.MethodGet || r.URL.Path != "/socket" ||
		!strings.EqualFold(r.Header.Get("Connection"), "Upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "invalid WebSocket upgrade", http.StatusBadRequest)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if decoded, err := base64.StdEncoding.DecodeString(key); err != nil || len(decoded) != 16 {
		http.Error(w, "invalid WebSocket key", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	// #nosec G401 -- SHA-1 is mandated by the WebSocket handshake (RFC 6455), not a security hash choice.
	acceptInput := sha1.Sum([]byte(key + websocketGUID))
	accept := base64.StdEncoding.EncodeToString(acceptInput[:])
	// #nosec G705 -- Raw WebSocket 101 headers with a base64 handshake value, not an HTML response.
	if _, err = fmt.Fprintf(
		rw,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		accept,
	); err == nil {
		err = rw.Flush()
	}
	if err == nil {
		observedRequest <- r.Host
	}
}

func serveWebSocketHTTPTarget(
	w http.ResponseWriter,
	r *http.Request,
	websocketGUID string,
	backendRequests chan<- struct{},
) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if r.Method != http.MethodGet || r.URL.Path != "/socket" ||
		!strings.EqualFold(r.Header.Get("Connection"), "Upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || key == "" {
		http.Error(w, "invalid WebSocket upgrade", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	// #nosec G401 -- SHA-1 is mandated by the WebSocket handshake (RFC 6455), not a security hash choice.
	acceptInput := sha1.Sum([]byte(key + websocketGUID))
	accept := base64.StdEncoding.EncodeToString(acceptInput[:])
	// #nosec G705 -- Raw WebSocket 101 headers with a base64 handshake value, not an HTML response.
	if _, err = fmt.Fprintf(
		rw,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		accept,
	); err == nil {
		err = rw.Flush()
	}
	if err == nil {
		backendRequests <- struct{}{}
	}
}

type apiECHServerResult struct {
	accepted bool
	host     string
	path     string
	err      error
}

func serveAPIAcceptedECH(listener net.Listener, provider ctls.ECHProvider, serverResultCh chan<- apiECHServerResult) {
	conn, acceptErr := listener.Accept()
	if acceptErr != nil {
		serverResultCh <- apiECHServerResult{err: acceptErr}
		return
	}
	defer conn.Close()
	certificateServer := httptest.NewTLSServer(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	)
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()
	tlsConn := ctls.Server(conn, &ctls.Config{
		Certificates: []ctls.Certificate{
			{
				Certificate: certificate.Certificate,
				PrivateKey:  certificate.PrivateKey,
				Leaf:        certificate.Leaf,
			},
		},
		MinVersion:        ctls.VersionTLS13,
		ECHEnabled:        true,
		ServerECHProvider: provider,
	})
	if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
		serverResultCh <- apiECHServerResult{err: fmt.Errorf("local ECH TLS handshake: %w", handshakeErr)}
		return
	}
	request, readErr := http.ReadRequest(bufio.NewReader(tlsConn))
	if readErr != nil {
		serverResultCh <- apiECHServerResult{accepted: tlsConn.ConnectionState().ECHAccepted, err: fmt.Errorf("read local ECH HTTP request: %w", readErr)}
		return
	}
	_ = request.Body.Close()
	_, writeErr := io.WriteString(
		tlsConn,
		"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nech-accepted",
	)
	serverResultCh <- apiECHServerResult{
		accepted: tlsConn.ConnectionState().ECHAccepted,
		host:     request.Host,
		path:     request.URL.RequestURI(),
		err:      writeErr,
	}
}

func assertAPIAcceptedECH(
	ctx context.Context,
	t *testing.T,
	routeName, targetAddress string,
	serverResultCh <-chan apiECHServerResult,
) {
	t.Helper()
	select {
	case got := <-serverResultCh:
		if got.err != nil || !got.accepted || got.host != targetAddress || got.path != "/ech-api" {
			t.Fatalf(
				"%s ECH server result = %+v, want accepted ECH and Host %q path /ech-api",
				routeName,
				got,
				targetAddress,
			)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s ECH server result", routeName)
	}
}

type apiPQRouteObservation struct {
	host       string
	serverName string
	curveID    tls.CurveID
}

func serveAPIPQRouteTarget(w http.ResponseWriter, r *http.Request, observed chan<- apiPQRouteObservation) {
	if r.TLS == nil || uint16(r.TLS.CurveID) != 0x11ec {
		var curveID uint16
		if r.TLS != nil {
			curveID = uint16(r.TLS.CurveID)
		}
		http.Error(
			w,
			fmt.Sprintf("negotiated TLS group = 0x%04x, want X25519MLKEM768 (0x11ec)", curveID),
			http.StatusUpgradeRequired,
		)
		return
	}
	observed <- apiPQRouteObservation{host: r.Host, serverName: r.TLS.ServerName, curveID: r.TLS.CurveID}
	_, _ = io.WriteString(w, "post-quantum proxy route ok")
}

func assertAPIPQRouteTarget(
	ctx context.Context,
	t *testing.T,
	routeName, targetAddress string,
	observed <-chan apiPQRouteObservation,
) {
	t.Helper()
	select {
	case got := <-observed:
		if got.host != targetAddress || got.serverName != "localhost" || uint16(got.curveID) != 0x11ec {
			t.Errorf(
				"%s target TLS observation = %+v, want Host %q, SNI localhost, X25519MLKEM768",
				routeName,
				got,
				targetAddress,
			)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s target TLS observation", routeName)
	}
}

func serveStrictAPIHTTP2Connect(
	t *testing.T,
	targetAddress, targetAuthority string,
	proxyRequests chan<- string,
	proxyDone chan<- struct{},
	w http.ResponseWriter,
	r *http.Request,
) {
	proxyRequests <- r.Proto + " " + r.Method + " " + r.Host
	if r.ProtoMajor != 2 || r.Method != http.MethodConnect || r.Host != targetAuthority {
		http.Error(w, "unexpected HTTP/2 CONNECT request", http.StatusBadRequest)
		return
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
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, r.Body)
		if closeWriter, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
		close(copyDone)
	}()
	_, _ = io.Copy(apiProxyFlushWriter{writer: w, flusher: flusher}, upstream)
	<-copyDone
	proxyDone <- struct{}{}
}

func serveAPIHTTP2Connect(
	t *testing.T,
	targetAddress, targetAuthority string,
	proxyRequests chan<- string,
	w http.ResponseWriter,
	r *http.Request,
) {
	proxyRequests <- r.Proto + " " + r.Method + " " + r.Host
	if r.ProtoMajor != 2 || r.Method != http.MethodConnect || r.Host != targetAuthority {
		http.Error(w, "unexpected HTTP/2 CONNECT request", http.StatusBadRequest)
		return
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
	_, _ = io.Copy(apiProxyFlushWriter{writer: w, flusher: flusher}, upstream)
}

func serveAPIHTTP11HTTPSConnect(
	t *testing.T,
	targetAddress, upstreamAddress string,
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodConnect || r.Host != targetAddress {
		t.Errorf("proxy request = %s %q, want CONNECT %q", r.Method, r.Host, targetAddress)
	}
	clientConn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Errorf("proxy Hijack() error = %v", err)
		return
	}
	defer func() { _ = clientConn.Close() }()

	targetConn, err := net.Dial("tcp", upstreamAddress)
	if err != nil {
		t.Errorf("proxy dial target: %v", err)
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
		if tcpConn, ok := targetConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		close(copyDone)
	}()
	_, _ = io.Copy(clientConn, targetConn)
	_ = clientConn.Close()
	<-copyDone
}

func assertAPIHTTP11ProxyTLSReports(t *testing.T, result *Result) {
	t.Helper()
	if len(result.TLSReports) != 2 {
		t.Fatalf("TLS reports = %+v, want separate proxy and target reports", result.TLSReports)
	}
	reportsByLeg := make(map[string]ConnectionReport, len(result.TLSReports))
	for _, report := range result.TLSReports {
		reportsByLeg[report.Leg] = report
	}
	for _, leg := range []string{"proxy", "target"} {
		report, ok := reportsByLeg[leg]
		if !ok {
			t.Errorf("TLS reports omit %q leg: %+v", leg, result.TLSReports)
			continue
		}
		if (report.CaptureStatus != "MATCH" && report.CaptureStatus != "PARTIAL_MATCH") ||
			report.Actual == nil || len(report.Actual.ALPN) != 1 || report.Actual.ALPN[0] != "http/1.1" {
			t.Errorf("%s TLS report = %+v, want observed ClientHello with matching required HTTP/1.1 ALPN", leg, report)
		}
		for _, difference := range report.Diff {
			if difference.Policy != "SHOULD" {
				t.Errorf("%s TLS report contains non-optional difference: %+v", leg, difference)
			}
		}
	}
	if proxyReport, targetReport := reportsByLeg["proxy"], reportsByLeg["target"]; proxyReport.ConnectionID != "" &&
		targetReport.ConnectionID != "" &&
		proxyReport.ConnectionID == targetReport.ConnectionID {
		t.Errorf("proxy and target TLS legs share connection ID %q", proxyReport.ConnectionID)
	}
}

func assertAPIHTTPSOverSOCKSAddressType(t *testing.T, addrType <-chan byte, wantAddrType byte) {
	t.Helper()
	select {
	case got := <-addrType:
		if got != wantAddrType {
			t.Errorf("SOCKS CONNECT ATYP = %d, want %d", got, wantAddrType)
		}
	case <-time.After(time.Second):
		t.Error("SOCKS proxy did not report a CONNECT address type")
	}
}

type apiOHTTPInnerRequestObservation struct{ method, url, body, header string }

func serveAPIRecordedOHTTPGateway(
	w http.ResponseWriter,
	r *http.Request,
	privateConfig ohttp.PrivateConfig,
	gateway ohttp.Gateway,
	observation *apiOHTTPInnerRequestObservation,
) {
	switch r.URL.Path {
	case "/keys":
		w.Header().Set("Content-Type", "application/ohttp-keys")
		_, _ = w.Write(privateConfig.Config().Marshal())
	case "/gateway":
		encodedRequest, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadRequest)
			return
		}
		encapsulatedRequest, decodeErr := ohttp.UnmarshalEncapsulatedRequest(encodedRequest)
		if decodeErr != nil {
			http.Error(w, decodeErr.Error(), http.StatusBadRequest)
			return
		}
		binaryRequest, responseContext, decodeErr := gateway.DecapsulateRequest(encapsulatedRequest)
		if decodeErr != nil {
			http.Error(w, decodeErr.Error(), http.StatusBadRequest)
			return
		}
		decodedRequest, decodeErr := ohttp.UnmarshalBinaryRequest(binaryRequest)
		if decodeErr != nil {
			http.Error(w, decodeErr.Error(), http.StatusBadRequest)
			return
		}
		observation.method = decodedRequest.Method
		observation.url = decodedRequest.URL.String()
		observation.header = decodedRequest.Header.Get("X-Inner-Request")
		body, bodyErr := io.ReadAll(decodedRequest.Body)
		if bodyErr != nil {
			http.Error(w, bodyErr.Error(), http.StatusBadRequest)
			return
		}
		observation.body = string(body)
		binaryResponse, marshalErr := (*ohttp.BinaryResponse)(&http.Response{
			StatusCode: http.StatusCreated,
			Header:     http.Header{"X-OHTTP-API": []string{"ok"}},
			Body:       io.NopCloser(strings.NewReader("decrypted response")),
		}).Marshal()
		if marshalErr != nil {
			http.Error(w, marshalErr.Error(), http.StatusInternalServerError)
			return
		}
		encapsulatedResponse, encodeErr := responseContext.EncapsulateResponse(binaryResponse)
		if encodeErr != nil {
			http.Error(w, encodeErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "message/ohttp-res")
		_, _ = w.Write(encapsulatedResponse.Marshal())
	default:
		http.NotFound(w, r)
	}
}

func serveAPIProxiedOHTTPGateway(
	w http.ResponseWriter,
	r *http.Request,
	privateConfig ohttp.PrivateConfig,
	gateway ohttp.Gateway,
	observedTargets chan<- string,
) {
	switch r.URL.Path {
	case "/keys":
		w.Header().Set("Content-Type", "application/ohttp-keys")
		_, _ = w.Write(privateConfig.Config().Marshal())
	case "/gateway":
		encoded, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadRequest)
			return
		}
		encapsulated, decodeErr := ohttp.UnmarshalEncapsulatedRequest(encoded)
		if decodeErr != nil {
			http.Error(w, decodeErr.Error(), http.StatusBadRequest)
			return
		}
		binaryRequest, responseContext, decodeErr := gateway.DecapsulateRequest(encapsulated)
		if decodeErr != nil {
			http.Error(w, decodeErr.Error(), http.StatusBadRequest)
			return
		}
		decodedRequest, decodeErr := ohttp.UnmarshalBinaryRequest(binaryRequest)
		if decodeErr != nil {
			http.Error(w, decodeErr.Error(), http.StatusBadRequest)
			return
		}
		observedTargets <- decodedRequest.URL.String()
		binaryResponse, marshalErr := (*ohttp.BinaryResponse)(&http.Response{
			StatusCode: http.StatusCreated,
			Header:     http.Header{"X-OHTTP-Route": []string{"verified"}},
			Body:       io.NopCloser(strings.NewReader("ohttp-proxy-ok")),
		}).Marshal()
		if marshalErr != nil {
			http.Error(w, marshalErr.Error(), http.StatusInternalServerError)
			return
		}
		encapsulatedResponse, encodeErr := responseContext.EncapsulateResponse(binaryResponse)
		if encodeErr != nil {
			http.Error(w, encodeErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "message/ohttp-res")
		_, _ = w.Write(encapsulatedResponse.Marshal())
	default:
		http.NotFound(w, r)
	}
}

func serveAPIOHTTPConnect(w http.ResponseWriter, r *http.Request, targetAddress string, proxyRequests *atomic.Int32) {
	proxyRequests.Add(1)
	if r.Method != http.MethodConnect {
		http.Error(w, "expected CONNECT", http.StatusMethodNotAllowed)
		return
	}
	upstream, dialErr := net.Dial("tcp", targetAddress)
	if dialErr != nil {
		http.Error(w, dialErr.Error(), http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "proxy does not support CONNECT", http.StatusInternalServerError)
		return
	}
	client, buffered, hijackErr := hijacker.Hijack()
	if hijackErr != nil {
		_ = upstream.Close()
		return
	}
	defer client.Close()
	defer upstream.Close()
	if _, writeErr := buffered.WriteString(
		"HTTP/1.1 200 Connection Established\r\n\r\n",
	); writeErr != nil {
		return
	}
	if flushErr := buffered.Flush(); flushErr != nil {
		return
	}
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, buffered)
		close(copyDone)
	}()
	_, _ = io.Copy(client, upstream)
	<-copyDone
}

func assertAPIOHTTPProxyReuse(
	t *testing.T,
	routeName string,
	wantSOCKSATYP byte,
	socksATYP <-chan byte,
	socksDone <-chan struct{},
	proxyRequests, proxyConnections *atomic.Int32,
) {
	t.Helper()
	if wantSOCKSATYP != 0 {
		select {
		case got := <-socksATYP:
			if got != wantSOCKSATYP {
				t.Errorf("%s address type = %d, want %d", routeName, got, wantSOCKSATYP)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s proxy did not receive CONNECT", routeName)
		}
		select {
		case <-socksDone:
		case <-time.After(2 * time.Second):
			t.Errorf("%s proxy tunnel did not close", routeName)
		}
	} else {
		if got := proxyRequests.Load(); got != 1 {
			t.Errorf("%s CONNECT tunnels = %d, want one tunnel shared by key fetch and gateway", routeName, got)
		}
		if got := proxyConnections.Load(); got != 1 {
			t.Errorf("%s proxy connections = %d, want one reused connection", routeName, got)
		}
	}
}

func apiOHTTPEndpoints(t *testing.T, serverURL, proxyScheme string) (url.URL, url.URL) {
	t.Helper()
	endpoint, parseErr := url.Parse(serverURL)
	if parseErr != nil {
		t.Fatalf("parse OHTTP endpoint: %v", parseErr)
	}
	if proxyScheme == "socks5h" {
		_, port, splitErr := net.SplitHostPort(endpoint.Host)
		if splitErr != nil {
			t.Fatalf("split OHTTP endpoint port: %v", splitErr)
		}
		endpoint.Host = net.JoinHostPort("localhost", port)
	}
	keysURL := *endpoint
	keysURL.Path = "/keys"
	gatewayURL := *endpoint
	gatewayURL.Path = "/gateway"
	return keysURL, gatewayURL
}
