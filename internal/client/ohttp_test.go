package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/chris-wood/ohttp-go"
	"github.com/cloudflare/circl/hpke"
)

func TestObliviousHTTPReportsGatewayTLSAndKeepsTargetResponseContext(t *testing.T) {
	privateConfig, err := ohttp.NewConfig(
		1,
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KDF_HKDF_SHA256,
		hpke.AEAD_AES128GCM,
	)
	if err != nil {
		t.Fatalf("create OHTTP key config: %v", err)
	}
	gateway := ohttp.NewDefaultGateway([]ohttp.PrivateConfig{privateConfig})
	var observedGatewayRequest *http.Request
	base := &ohttpTestTransport{roundTrip: func(request *http.Request) (*http.Response, error) {
		observedGatewayRequest = request
		return observeOHTTPGatewayRoundTrip(t, gateway, request)
	}}
	transport := &obliviousHTTPTransport{
		base:         base,
		gatewayURL:   &url.URL{Scheme: "https", Host: "gateway.example", Path: "/ohttp"},
		publicConfig: privateConfig.Config(),
		cfg:          &config.Config{OutputJSON: true},
		out:          output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, true),
	}
	request, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://hidden-target.example/path",
		nil,
	)
	if err != nil {
		t.Fatalf("create target request: %v", err)
	}

	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("OHTTP RoundTrip: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if observedGatewayRequest == nil || observedGatewayRequest.URL.Host != "gateway.example" {
		t.Fatalf("gateway request = %v, want gateway.example", observedGatewayRequest)
	}
	if response.StatusCode != http.StatusCreated || response.Request == nil ||
		response.Request.URL.Host != "hidden-target.example" {
		t.Fatalf(
			"decrypted response metadata = status %d, request %v; want target request context",
			response.StatusCode,
			response.Request,
		)
	}
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("response TLS state = %+v, want gateway TLS state", response.TLS)
	}
	reports, ok := utlsengine.ProfileCheckReports(response.Request.Context())
	if !ok || len(reports) != 2 || reports[0].Leg != "gateway" || reports[0].CaptureStatus != "REUSED_CONNECTION" ||
		reports[1].Leg != "gateway" || reports[1].Actual == nil || reports[1].Actual.JA4 != "gateway-ja4" {
		t.Fatalf("OHTTP connection reports = %+v, found=%t; want gateway reuse and fingerprint reports", reports, ok)
	}

	assertOHTTPGatewayJSON(t, response)
}

func TestObliviousHTTPReusesSameOriginHTTP11Connection(t *testing.T) {
	privateConfig, err := ohttp.NewConfig(
		1,
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KDF_HKDF_SHA256,
		hpke.AEAD_AES128GCM,
	)
	if err != nil {
		t.Fatalf("create OHTTP key config: %v", err)
	}
	gateway := ohttp.NewDefaultGateway([]ohttp.PrivateConfig{privateConfig})
	var connectionCount atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveReusedOHTTPGateway(w, r, privateConfig, gateway)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connectionCount.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse local OHTTP server URL: %v", err)
	}
	keysURL := *serverURL
	keysURL.Path = "/keys"
	gatewayURL := *serverURL
	gatewayURL.Path = "/gateway"
	targetURL, err := url.Parse("https://hidden-target.invalid/resource")
	if err != nil {
		t.Fatalf("parse hidden target URL: %v", err)
	}
	cfg := &config.Config{
		RequestURL:      targetURL,
		OHTTPKeysURL:    &keysURL,
		OHTTPGatewayURL: &gatewayURL,
		ForceHTTP11:     true,
		Insecure:        true,
		OutputJSON:      true,
	}
	out := output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, true)
	transport, err := newObliviousHTTPTransport(cfg, out)
	if err != nil {
		t.Fatalf("create OHTTP transport: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, targetURL.String(), nil)
	if err != nil {
		t.Fatalf("create hidden target request: %v", err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("OHTTP round trip: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read OHTTP response: %v", err)
	}
	if string(body) != "reused" {
		t.Fatalf("response body = %q, want reused", body)
	}
	if err = response.Body.Close(); err != nil {
		t.Fatalf("close OHTTP response body: %v", err)
	}
	if got := connectionCount.Load(); got != 1 {
		t.Fatalf("TLS connection count = %d, want one shared HTTP/1.1 connection", got)
	}
	reports, ok := utlsengine.ProfileCheckReports(response.Request.Context())
	if !ok {
		t.Fatal("OHTTP response has no connection reports")
	}
	foundReuse := false
	for _, report := range reports {
		if report.Leg == "gateway" && report.CaptureStatus == "REUSED_CONNECTION" {
			foundReuse = true
		}
	}
	if !foundReuse {
		t.Fatalf("connection reports = %+v, want real gateway REUSED_CONNECTION", reports)
	}

	assertStrictOHTTPReuseRejected(t, cfg, targetURL, transport, &connectionCount)
}

func TestSameOHTTPOrigin(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{
			name: "same HTTPS origin with implicit port",
			a:    "https://EXAMPLE.test/keys",
			b:    "https://example.test/gateway",
			want: true,
		},
		{
			name: "same HTTP origin with implicit port",
			a:    "http://example.test/keys",
			b:    "http://example.test:80/gateway",
			want: true,
		},
		{name: "different scheme", a: "http://example.test/keys", b: "https://example.test/gateway"},
		{name: "different host", a: "https://one.example/keys", b: "https://two.example/gateway"},
		{name: "different port", a: "https://example.test:8443/keys", b: "https://example.test/gateway"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a, err := url.Parse(test.a)
			if err != nil {
				t.Fatal(err)
			}
			b, err := url.Parse(test.b)
			if err != nil {
				t.Fatal(err)
			}
			if got := sameOHTTPOrigin(a, b); got != test.want {
				t.Fatalf("sameOHTTPOrigin(%q, %q) = %t, want %t", test.a, test.b, got, test.want)
			}
		})
	}
}

func TestObliviousHTTPUsesLocalProxyForKeysAndGateway(t *testing.T) {
	runObliviousHTTPUsesLocalProxyForKeysAndGateway(t, "http")
}

func TestObliviousHTTPUsesLocalHTTPSProxyForKeysAndGateway(t *testing.T) {
	runObliviousHTTPUsesLocalProxyForKeysAndGateway(t, "https")
}

func TestObliviousHTTPUsesLocalSOCKS5ProxyForKeysAndGateway(t *testing.T) {
	runObliviousHTTPUsesLocalProxyForKeysAndGateway(t, "socks5")
}

func TestObliviousHTTPUsesLocalSOCKS5HProxyForKeysAndGateway(t *testing.T) {
	runObliviousHTTPUsesLocalProxyForKeysAndGateway(t, "socks5h")
}

func runObliviousHTTPUsesLocalProxyForKeysAndGateway(t *testing.T, proxyScheme string) {
	t.Helper()
	privateConfig, err := ohttp.NewConfig(
		1,
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KDF_HKDF_SHA256,
		hpke.AEAD_AES128GCM,
	)
	if err != nil {
		t.Fatalf("create OHTTP key config: %v", err)
	}
	gateway := ohttp.NewDefaultGateway([]ohttp.PrivateConfig{privateConfig})
	var gatewayRequests int
	var targetRequestURL string
	gatewayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveProxiedOHTTPGateway(w, r, privateConfig, gateway, &gatewayRequests, &targetRequestURL)
	}))
	defer gatewayServer.Close()

	var proxyConnections atomic.Int32
	proxyATYPs := make(chan byte, 4)
	proxyErrors := make(chan error, 4)
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveOHTTPConnectProxy(w, r, &proxyConnections)
	})
	var proxyServer *httptest.Server
	var proxyURLString string
	switch proxyScheme {
	case "http", "https":
		if proxyScheme == "https" {
			proxyServer = httptest.NewTLSServer(proxyHandler)
		} else {
			proxyServer = httptest.NewServer(proxyHandler)
		}
		defer proxyServer.Close()
		proxyURLString = proxyServer.URL
	case "socks5", "socks5h":
		proxyListener, listenErr := net.Listen("tcp", "127.0.0.1:0")
		if listenErr != nil {
			t.Fatalf("listen for local SOCKS5 proxy: %v", listenErr)
		}
		defer func() { _ = proxyListener.Close() }()
		proxyURLString = proxyScheme + "://" + proxyListener.Addr().String()
		go serveOHTTPTestSOCKS5Proxy(proxyListener, &proxyConnections, proxyATYPs, proxyErrors)
	default:
		t.Fatalf("unsupported local proxy scheme %q", proxyScheme)
	}

	proxyURL, err := url.Parse(proxyURLString)
	if err != nil {
		t.Fatalf("parse local proxy URL: %v", err)
	}
	gatewayURL, keysURL := localOHTTPGatewayURLs(t, gatewayServer, proxyScheme)
	targetURL, err := url.Parse("https://hidden-target.invalid/custom")
	if err != nil {
		t.Fatalf("parse hidden target URL: %v", err)
	}
	cfg := &config.Config{
		ProxyURL:        proxyURL,
		ProxyInsecure:   proxyScheme == "https",
		RequestURL:      targetURL,
		OHTTPGatewayURL: gatewayURL,
		OHTTPKeysURL:    keysURL,
	}
	out := output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false)
	transport, err := newObliviousHTTPTransport(cfg, out)
	if err != nil {
		t.Fatalf("create OHTTP transport through local proxy: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, targetURL.String(), nil)
	if err != nil {
		t.Fatalf("create hidden target request: %v", err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("OHTTP request through local proxy: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read OHTTP response: %v", err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "local-ohttp-proxy-ok" ||
		response.Header.Get("X-OHTTP-Test") != "ok" {
		t.Fatalf("OHTTP response = %d, headers %v, body %q", response.StatusCode, response.Header, body)
	}
	if proxyConnections.Load() != 2 || gatewayRequests != 1 {
		t.Fatalf(
			"proxy connections=%d; gateway requests=%d; want two proxy connections and one gateway request",
			proxyConnections.Load(),
			gatewayRequests,
		)
	}
	assertOHTTPProxyAddressTypes(t, proxyScheme, proxyATYPs, proxyErrors)
	if targetRequestURL != targetURL.String() {
		t.Fatalf("decrypted target URL = %q, want %q", targetRequestURL, targetURL)
	}
}

func serveOHTTPTestSOCKS5Proxy(
	listener net.Listener,
	connections *atomic.Int32,
	atyp chan<- byte,
	proxyErrors chan<- error,
) {
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		connections.Add(1)
		go handleOHTTPTestSOCKS5Connection(client, atyp, proxyErrors)
	}
}

func handleOHTTPTestSOCKS5Connection(client net.Conn, atyp chan<- byte, proxyErrors chan<- error) {
	defer func() { _ = client.Close() }()
	reader := bufio.NewReader(client)
	if err := acceptOHTTPProxySOCKSGreeting(client, reader); err != nil {
		proxyErrors <- err
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(reader, request[:]); err != nil || request[0] != 5 || request[1] != 1 {
		if err == nil {
			err = errors.New("SOCKS5 request is not CONNECT")
		}
		proxyErrors <- err
		return
	}
	var host string
	switch request[3] {
	case 1:
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, address); err != nil {
			proxyErrors <- err
			return
		}
		host = net.IP(address).String()
	case 3:
		length, err := reader.ReadByte()
		if err != nil {
			proxyErrors <- err
			return
		}
		address := make([]byte, int(length))
		if _, err = io.ReadFull(reader, address); err != nil {
			proxyErrors <- err
			return
		}
		host = string(address)
	case 4:
		address := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, address); err != nil {
			proxyErrors <- err
			return
		}
		host = net.IP(address).String()
	default:
		_, _ = client.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		proxyErrors <- errors.New("unsupported SOCKS5 address type")
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(reader, portBytes[:]); err != nil {
		proxyErrors <- err
		return
	}
	atyp <- request[3]
	// #nosec G704 -- Local proxy fixture deliberately dials the loopback target supplied by its test client.
	upstream, err := net.DialTimeout(
		"tcp",
		net.JoinHostPort(host, strconv.Itoa(int(portBytes[0])<<8|int(portBytes[1]))),
		2*time.Second,
	)
	if err != nil {
		_, _ = client.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		proxyErrors <- err
		return
	}
	defer func() { _ = upstream.Close() }()
	if _, err = client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		proxyErrors <- err
		return
	}
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, reader)
		if closeWriter, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
		close(copyDone)
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	<-copyDone
}

type ohttpTestTransport struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (t *ohttpTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.roundTrip(request)
}

func (*ohttpTestTransport) Conn() net.Conn { return nil }

func observeOHTTPGatewayRoundTrip(t *testing.T, gateway ohttp.Gateway, request *http.Request) (*http.Response, error) {
	t.Helper()
	if got := tlsLegFromContext(request.Context()); got != "gateway" {
		t.Errorf("gateway TLS leg = %q, want gateway", got)
	}
	if _, ok := utlsengine.ProfileCheckReports(request.Context()); !ok {
		t.Fatal("gateway request has no request-local TLS report slot")
	}
	trace := httptrace.ContextClientTrace(request.Context())
	if trace == nil || trace.GotConn == nil {
		t.Fatal("gateway request has no TLS connection reuse callback")
	}
	trace.GotConn(httptrace.GotConnInfo{
		Conn: &reportedConn{connectionID: "gateway-reused", attempt: 1, helloIndex: 1}, Reused: true,
	})
	utlsengine.RecordProfileCheck(request.Context(), utlsengine.NewConnectionReportForLeg(
		utlsengine.ClientProfile{},
		utlsengine.ProfileCheckResult{
			Status: "OBSERVED",
			Actual: utlsengine.Fingerprint{JA3: "gateway-ja3", JA4: "gateway-ja4"},
		},
		"gateway-connection", "gateway", 1, 1,
	))

	encapsulatedRequestBytes, readErr := io.ReadAll(request.Body)
	if readErr != nil {
		return nil, readErr
	}
	encapsulatedRequest, decodeErr := ohttp.UnmarshalEncapsulatedRequest(encapsulatedRequestBytes)
	if decodeErr != nil {
		return nil, decodeErr
	}
	_, responseContext, decodeErr := gateway.DecapsulateRequest(encapsulatedRequest)
	if decodeErr != nil {
		return nil, decodeErr
	}
	binaryResponse, marshalErr := (*ohttp.BinaryResponse)(&http.Response{
		StatusCode: http.StatusCreated,
		Header:     http.Header{"X-Target-Response": []string{"preserved"}},
		Body:       io.NopCloser(strings.NewReader("target response")),
	}).Marshal()
	if marshalErr != nil {
		return nil, marshalErr
	}
	encapsulatedResponse, encodeErr := responseContext.EncapsulateResponse(binaryResponse)
	if encodeErr != nil {
		return nil, encodeErr
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"message/ohttp-res"}},
		Body:       io.NopCloser(bytes.NewReader(encapsulatedResponse.Marshal())),
		TLS: &tls.ConnectionState{
			Version:            tls.VersionTLS13,
			NegotiatedProtocol: "http/1.1",
		},
	}, nil
}

func assertOHTTPGatewayJSON(t *testing.T, response *http.Response) {
	t.Helper()
	var err error
	jsonOutput := &bytes.Buffer{}
	out := output.NewOutputWithWriters(jsonOutput, &bytes.Buffer{}, false, true)
	if err = out.Write(response, response.Body, &config.Config{OutputJSON: true}); err != nil {
		t.Fatalf("write OHTTP JSON response: %v", err)
	}
	var result output.ResponseData
	if err = json.Unmarshal(jsonOutput.Bytes(), &result); err != nil {
		t.Fatalf("decode OHTTP JSON response: %v", err)
	}
	if result.TLS == nil || result.TLS.Version != "TLS 1.3" || len(result.Connections) != 2 ||
		result.Connections[0].Leg != "gateway" || result.Connections[1].Leg != "gateway" {
		t.Fatalf("OHTTP JSON response = %+v, want gateway TLS and connection metadata", result)
	}
}

func serveReusedOHTTPGateway(
	w http.ResponseWriter,
	r *http.Request,
	privateConfig ohttp.PrivateConfig,
	gateway ohttp.Gateway,
) {
	switch r.URL.Path {
	case "/keys":
		w.Header().Set("Content-Type", "application/ohttp-keys")
		_, _ = w.Write(privateConfig.Config().Marshal())
	case "/gateway":
		payload, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadRequest)
			return
		}
		encapsulatedRequest, decodeErr := ohttp.UnmarshalEncapsulatedRequest(payload)
		if decodeErr != nil {
			http.Error(w, decodeErr.Error(), http.StatusBadRequest)
			return
		}
		_, responseContext, decodeErr := gateway.DecapsulateRequest(encapsulatedRequest)
		if decodeErr != nil {
			http.Error(w, decodeErr.Error(), http.StatusBadRequest)
			return
		}
		binaryResponse, marshalErr := (*ohttp.BinaryResponse)(&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("reused")),
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

func assertStrictOHTTPReuseRejected(
	t *testing.T,
	cfg *config.Config,
	targetURL *url.URL,
	transport Transport,
	connectionCount *atomic.Int32,
) {
	t.Helper()
	cfg.TLSProfileStrict = true
	strictRequest, err := http.NewRequest(http.MethodGet, targetURL.String(), nil)
	if err != nil {
		t.Fatalf("create strict hidden target request: %v", err)
	}
	_, err = transport.RoundTrip(strictRequest)
	var profileErr interface {
		Status() string
		ExitCode() int
	}
	if !errors.As(err, &profileErr) || profileErr.Status() != "REUSED_CONNECTION" || profileErr.ExitCode() != 5 {
		t.Fatalf("strict OHTTP round trip error = %v, want REUSED_CONNECTION with exit code 5", err)
	}
	if got := connectionCount.Load(); got != 1 {
		t.Fatalf("TLS connection count after strict request = %d, want one reused connection", got)
	}
}

func serveProxiedOHTTPGateway(
	w http.ResponseWriter,
	r *http.Request,
	privateConfig ohttp.PrivateConfig,
	gateway ohttp.Gateway,
	gatewayRequests *int,
	targetRequestURL *string,
) {
	switch r.URL.Path {
	case "/keys":
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "application/ohttp-keys")
		_, _ = w.Write(privateConfig.Config().Marshal())
	case "/gateway":
		w.Header().Set("Connection", "close")
		(*gatewayRequests)++
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "message/ohttp-req" {
			http.Error(w, "unexpected OHTTP gateway request", http.StatusBadRequest)
			return
		}
		payload, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadRequest)
			return
		}
		encapsulatedRequest, decodeErr := ohttp.UnmarshalEncapsulatedRequest(payload)
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
		*targetRequestURL = decodedRequest.URL.String()
		binaryResponse, marshalErr := (*ohttp.BinaryResponse)(&http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"X-OHTTP-Test": []string{"ok"}},
			Body:       io.NopCloser(strings.NewReader("local-ohttp-proxy-ok")),
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

func serveOHTTPConnectProxy(w http.ResponseWriter, r *http.Request, proxyConnections *atomic.Int32) {
	if r.Method != http.MethodConnect {
		http.Error(w, "proxy expects CONNECT", http.StatusMethodNotAllowed)
		return
	}
	proxyConnections.Add(1)
	// #nosec G704 -- Local proxy fixture deliberately dials the loopback target supplied by its test client.
	upstream, dialErr := net.Dial("tcp", r.Host)
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
	if _, writeErr := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); writeErr != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	if flushErr := buffered.Flush(); flushErr != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	go func() {
		_, _ = io.Copy(upstream, buffered)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	_ = upstream.Close()
}

func assertOHTTPProxyAddressTypes(t *testing.T, proxyScheme string, proxyATYPs <-chan byte, proxyErrors <-chan error) {
	t.Helper()
	if proxyScheme == "socks5" || proxyScheme == "socks5h" {
		wantATYP := byte(1)
		if proxyScheme == "socks5h" {
			wantATYP = 3
		}
		for i := 0; i < 2; i++ {
			select {
			case got := <-proxyATYPs:
				if got != wantATYP {
					t.Errorf("SOCKS5 request %d ATYP = %d, want %d for %s", i+1, got, wantATYP, proxyScheme)
				}
			case proxyErr := <-proxyErrors:
				t.Fatalf("SOCKS5 request %d failed: %v", i+1, proxyErr)
			default:
				t.Fatalf("SOCKS5 proxy observed fewer than two requests; got %d", i)
			}
		}
	}
}

func acceptOHTTPProxySOCKSGreeting(client net.Conn, reader *bufio.Reader) error {
	var greeting [2]byte
	if _, err := io.ReadFull(reader, greeting[:]); err != nil || greeting[0] != 5 {
		if err == nil {
			err = errors.New("invalid SOCKS5 greeting version")
		}
		return err
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}
	noAuth := false
	for _, method := range methods {
		if method == 0 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = client.Write([]byte{5, 0xff})
		return errors.New("SOCKS5 client did not offer no-auth method")
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		return err
	}
	return nil
}

func localOHTTPGatewayURLs(t *testing.T, gatewayServer *httptest.Server, proxyScheme string) (*url.URL, *url.URL) {
	t.Helper()
	gatewayURLString := gatewayServer.URL + "/gateway"
	keysURLString := gatewayServer.URL + "/keys"
	if proxyScheme == "socks5h" {
		_, port, splitErr := net.SplitHostPort(gatewayServer.Listener.Addr().String())
		if splitErr != nil {
			t.Fatalf("split local gateway address: %v", splitErr)
		}
		gatewayURLString = "http://localhost:" + port + "/gateway"
		keysURLString = "http://localhost:" + port + "/keys"
	}
	gatewayURL, err := url.Parse(gatewayURLString)
	if err != nil {
		t.Fatalf("parse local gateway URL: %v", err)
	}
	keysURL, err := url.Parse(keysURLString)
	if err != nil {
		t.Fatalf("parse local OHTTP keys URL: %v", err)
	}
	return gatewayURL, keysURL
}
