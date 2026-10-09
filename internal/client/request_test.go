package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/testutil"

	"github.com/AdguardTeam/dnsproxy/upstream"
	ctls "github.com/ameshkov/cfcrypto/tls"
	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/cloudflare/circl/hpke"
	"github.com/miekg/dns"
)

func TestNewRequestPrefersExplicitContentType(t *testing.T) {
	requestURL, err := url.Parse("https://example.org/")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	cfg := &config.Config{
		RequestURL: requestURL,
		Data:       `{"hello":"world"}`,
		Headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	req, err := NewRequest(cfg)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	values := req.Header.Values("Content-Type")
	if len(values) != 1 || values[0] != "application/json" {
		t.Fatalf("Content-Type values = %#v, want [application/json]", values)
	}
}

func TestHTTP11NoDefaultHeadersWritesOnlyRequestedHeaders(t *testing.T) {
	cfg, err := config.ParseConfig([]string{
		"--http1.1", "--no-default-headers", "--data=abc", "-H", "X-Only: yes", "http://example.test/upload",
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewRequest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := req.Write(&wire); err != nil {
		t.Fatal(err)
	}
	got := wire.String()
	if strings.Contains(strings.ToLower(got), "user-agent:") ||
		strings.Contains(strings.ToLower(got), "content-type:") ||
		!strings.Contains(got, "X-Only: yes\r\n") ||
		!strings.HasSuffix(got, "\r\n\r\nabc") {
		t.Fatalf("unexpected HTTP/1.1 wire request: %q", got)
	}
}

func TestExactHTTP11FramingMatchesConfiguredHeaders(t *testing.T) {
	for _, tt := range []struct {
		name    string
		headers []string
		want    string
	}{
		{"length", []string{"Content-Length: 3"}, "Content-Length: 3\r\n"},
		{"chunked", []string{"Transfer-Encoding: chunked"}, "Transfer-Encoding: chunked\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"--http1.1", "--no-default-headers", "--data=abc"}
			for _, header := range tt.headers {
				args = append(args, "-H", header)
			}
			args = append(args, "http://example.test/upload")
			cfg, err := config.ParseConfig(args)
			if err != nil {
				t.Fatal(err)
			}
			req, err := NewRequest(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var wire bytes.Buffer
			if err := req.Write(&wire); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(wire.String(), tt.want) {
				t.Fatalf("wire request missing %q: %q", tt.want, wire.String())
			}
			if tt.name == "chunked" && !strings.HasSuffix(wire.String(), "3\r\nabc\r\n0\r\n\r\n") {
				t.Fatalf("chunked body was not sent: %q", wire.String())
			}
		})
	}
}

func TestExactHTTP11RejectsBodyLengthMismatchBeforeNetwork(t *testing.T) {
	cfg, err := config.ParseConfig(
		[]string{"--http1.1", "--no-default-headers", "--data=abc", "-H", "Content-Length: 4", "http://example.test/"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRequest(cfg); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("NewRequest() error = %v, want body length mismatch", err)
	}
}

func TestExactHTTP11RejectsUnknownStdinLength(t *testing.T) {
	cfg, err := config.ParseConfig(
		[]string{
			"--http1.1",
			"--no-default-headers",
			"--data-binary=@-",
			"-H",
			"Content-Length: 3",
			"http://example.test/",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRequest(cfg); err == nil || !strings.Contains(err.Error(), "known body length") {
		t.Fatalf("NewRequest() error = %v, want unknown body length rejection", err)
	}
}

func TestNewRequestReadsBinaryFileWithoutEncoding(t *testing.T) {
	data := []byte{0x00, 0x01, 0xff, '\n', 0x00}
	path := filepath.Join(t.TempDir(), "body.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	requestURL, err := url.Parse("https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewRequest(&config.Config{RequestURL: requestURL, DataBinary: "@" + path})
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	defer func() { _ = req.Body.Close() }()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll(body) error = %v", err)
	}
	if string(body) != string(data) {
		t.Fatalf("request body = %v, want %v", body, data)
	}
	if req.Method != http.MethodPost || req.ContentLength != int64(len(data)) {
		t.Fatalf("method/content length = %s/%d, want POST/%d", req.Method, req.ContentLength, len(data))
	}
	if got := req.Header.Get("Content-Type"); got != "" {
		t.Fatalf("Content-Type = %q, want no implicit form encoding", got)
	}
}

func TestNewRequestEmptyBinaryFileHasZeroLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.bin")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	requestURL, _ := url.Parse("https://example.test/")
	req, err := NewRequest(&config.Config{RequestURL: requestURL, DataBinary: "@" + path})
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	defer func() { _ = req.Body.Close() }()
	if req.ContentLength != 0 {
		t.Fatalf("ContentLength = %d, want 0", req.ContentLength)
	}
	if body, readErr := io.ReadAll(req.Body); readErr != nil || len(body) != 0 {
		t.Fatalf("body = %v, ReadAll() error = %v; want empty body", body, readErr)
	}
}

func TestCreateBinaryBodyReadsStdin(t *testing.T) {
	want := []byte{0x00, 0x01, 0xff, 0x00}
	body, err := createBinaryBody("@-", bytes.NewReader(want))
	if err != nil {
		t.Fatalf("createBinaryBody() error = %v", err)
	}
	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("ReadAll(body) error = %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("stdin body = %v, want %v", got, want)
	}
}

func TestTransportUsesImportedTLSProfile(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	profileData, err := os.ReadFile(filepath.Join("utlsengine", "testdata", "profile-v1-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	clientProfile, err := utlsengine.DecodeClientProfile(profileData)
	if err != nil {
		t.Fatal(err)
	}
	profile, _, err := clientProfile.Materialize()
	if err != nil {
		t.Fatal(err)
	}
	requestURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	jsonOutput := &bytes.Buffer{}
	cfg := &config.Config{
		RequestURL: requestURL, Insecure: true, TLSProfile: &profile,
		TLSProfileDocument: &clientProfile, TLSProfileCheck: true, OutputJSON: true,
	}
	out := output.NewOutputWithWriters(jsonOutput, logs, false, false)
	transport, err := NewTransport(cfg, out)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if err = out.Write(resp, resp.Body, cfg); err != nil {
		t.Fatalf("write JSON response: %v", err)
	}
	var jsonResponse output.ResponseData
	if err = json.Unmarshal(jsonOutput.Bytes(), &jsonResponse); err != nil {
		t.Fatalf("decode JSON response: %v; body=%s", err, jsonOutput.String())
	}
	assertImportedTLSJSONReport(t, jsonResponse, logs)

	assertImportedTLSStrictMismatch(t, clientProfile, &profile, requestURL, server.URL, out)

	assertImportedTLSHTTP2Profile(t, clientProfile, requestURL, server.URL, out, jsonOutput)
}

func TestJSONOutputCapturesTLSWithoutProfileCheck(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	requestURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	jsonOutput := &bytes.Buffer{}
	cfg := &config.Config{RequestURL: requestURL, Insecure: true, OutputJSON: true}
	out := output.NewOutputWithWriters(jsonOutput, &bytes.Buffer{}, false, false)
	transport, err := NewTransport(cfg, out)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	defer resp.Body.Close()
	if err = out.Write(resp, resp.Body, cfg); err != nil {
		t.Fatalf("write JSON response: %v", err)
	}
	var got output.ResponseData
	if err = json.Unmarshal(jsonOutput.Bytes(), &got); err != nil {
		t.Fatalf("decode JSON response: %v", err)
	}
	if len(got.Connections) != 1 {
		t.Fatalf("connection reports = %+v, want one wire capture", got.Connections)
	}
	connection := got.Connections[0]
	if connection.CaptureStatus != "OBSERVED" || connection.Actual == nil || connection.Actual.JA3 == "" ||
		connection.Actual.JA4 == "" {
		t.Fatalf("connection report = %+v, want observed JA3/JA4 without profile comparison", connection)
	}
}

func TestReusedConnectionReportOmitsNewFingerprint(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request = withTLSProfileCheckContext(request, true, nil)
	trace := httptrace.ContextClientTrace(request.Context())
	if trace == nil || trace.GotConn == nil {
		t.Fatal("request context has no GotConn callback")
	}
	trace.GotConn(httptrace.GotConnInfo{Conn: &reportedConn{
		connectionID: "tls-reused", attempt: 2, helloIndex: 2,
	}, Reused: true})
	reports, ok := utlsengine.ProfileCheckReports(request.Context())
	if !ok || len(reports) != 1 {
		t.Fatalf("reports = %+v, found=%t; want one reuse report", reports, ok)
	}
	report := reports[0]
	if report.ConnectionID != "tls-reused" || report.Attempt != 2 || report.HelloIndex != 2 ||
		report.CaptureStatus != "REUSED_CONNECTION" || report.Actual != nil {
		t.Fatalf("reuse report = %+v, want existing identity and no new fingerprint", report)
	}
}

func TestHTTP11TransportCreatesFreshTLSConnections(t *testing.T) {
	var acceptedConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("request method = %q, want GET", r.Method)
		}
		_, _ = io.WriteString(w, "reuse-ok")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			acceptedConnections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()

	requestURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse local TLS URL: %v", err)
	}
	cfg := &config.Config{RequestURL: requestURL, Insecure: true, OutputJSON: true}
	jsonOutput := &bytes.Buffer{}
	out := output.NewOutputWithWriters(jsonOutput, &bytes.Buffer{}, false, true)
	transport, err := NewTransport(cfg, out)
	if err != nil {
		t.Fatalf("create transport: %v", err)
	}
	defer func() {
		if conn := transport.Conn(); conn != nil {
			_ = conn.Close()
		}
	}()

	for i := 0; i < 2; i++ {
		request, requestErr := http.NewRequest(http.MethodGet, server.URL, nil)
		if requestErr != nil {
			t.Fatalf("create request %d: %v", i+1, requestErr)
		}
		response, roundTripErr := transport.RoundTrip(request)
		if roundTripErr != nil {
			t.Fatalf("request %d: %v", i+1, roundTripErr)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			t.Fatalf("read response %d: %v", i+1, readErr)
		}
		if response.StatusCode != http.StatusOK || string(body) != "reuse-ok" {
			t.Fatalf("response %d = %d body %q", i+1, response.StatusCode, body)
		}
		if err = out.Write(response, io.NopCloser(bytes.NewReader(body)), cfg); err != nil {
			t.Fatalf("write response %d JSON: %v", i+1, err)
		}
		var result output.ResponseData
		if err = json.Unmarshal(jsonOutput.Bytes(), &result); err != nil {
			t.Fatalf("decode response %d JSON: %v", i+1, err)
		}
		if len(result.Connections) != 1 || result.Connections[0].CaptureStatus != "OBSERVED" ||
			result.Connections[0].Actual == nil {
			t.Fatalf(
				"request %d connection reports = %+v, want a fresh observed TLS handshake",
				i+1,
				result.Connections,
			)
		}
		jsonOutput.Reset()
	}
	if accepted := acceptedConnections.Load(); accepted != 2 {
		t.Fatalf("TLS server accepted %d connections, want two fresh HTTP/1.1 connections", accepted)
	}
}

func TestStrictProfileCheckRejectsReusedConnection(t *testing.T) {
	cfg := &config.Config{TLSProfileStrict: true}
	base := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		trace := httptrace.ContextClientTrace(request.Context())
		if trace == nil || trace.GotConn == nil {
			t.Fatal("request context has no GotConn callback")
		}
		trace.GotConn(httptrace.GotConnInfo{Conn: &reportedConn{connectionID: "tls-reused"}, Reused: true})
		return nil, request.Context().Err()
	})
	rt := &transport{d: &clientDialer{cfg: cfg}, base: base}
	request, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rt.RoundTrip(request)
	var profileErr *utlsengine.ProfileCheckError
	if !errors.As(err, &profileErr) || profileErr.Status() != "REUSED_CONNECTION" || profileErr.ExitCode() != 5 {
		t.Fatalf("RoundTrip() error = %v, want strict REUSED_CONNECTION failure with exit code 5", err)
	}
}

func TestStrictProfileCheckRejectsUnobservedTLSAndClosesConnection(t *testing.T) {
	clientConn, peerConn := net.Pipe()
	defer peerConn.Close()
	err := rejectStrictProfileCheck(clientConn, true, "NOT_OBSERVED")
	var profileErr *utlsengine.ProfileCheckError
	if !errors.As(err, &profileErr) || profileErr.Status() != "NOT_OBSERVED" || profileErr.ExitCode() != 5 {
		t.Fatalf("strict check error = %v, want NOT_OBSERVED with exit code 5", err)
	}
	if _, err = clientConn.Write([]byte("must not be sent")); err == nil {
		t.Fatal("strict rejection left the TLS connection open")
	}
}

func TestStrictECHGreaseRejectsUnobservedClientHello(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("HTTP request reached server despite strict NOT_OBSERVED result")
	}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "https://")
	out := output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false)
	dialer := &clientDialer{
		cfg:       &config.Config{TLSProfileCheck: true, TLSProfileStrict: true, ECHGrease: true},
		out:       out,
		tlsConfig: &tls.Config{ServerName: "example.test", InsecureSkipVerify: true},
		dial: func(network, _ string) (net.Conn, error) {
			return net.Dial(network, addr)
		},
	}
	ctx, _ := utlsengine.NewProfileCheckContext(context.Background())
	conn, err := dialer.DialTLSContext(ctx, "tcp", addr)
	if conn != nil {
		_ = conn.Close()
		t.Fatal("DialTLSContext() returned a connection despite strict NOT_OBSERVED result")
	}
	var profileErr *utlsengine.ProfileCheckError
	if !errors.As(err, &profileErr) || profileErr.Status() != "NOT_OBSERVED" || profileErr.ExitCode() != 5 {
		t.Fatalf("DialTLSContext() error = %v, want NOT_OBSERVED with exit code 5", err)
	}
	reports, ok := utlsengine.ProfileCheckReports(ctx)
	if !ok || len(reports) != 1 || reports[0].CaptureStatus != "NOT_OBSERVED" {
		t.Fatalf("strict ECH reports = %+v, found=%t; want one NOT_OBSERVED report", reports, ok)
	}
}

func TestECHGreaseAllowsLocalRequestWithUnobservedCapture(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/ech-grease" {
			t.Errorf("request = %s %s, want GET /ech-grease", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	requestURL, err := url.Parse(server.URL + "/ech-grease")
	if err != nil {
		t.Fatalf("parse local TLS URL: %v", err)
	}
	jsonOutput := &bytes.Buffer{}
	cfg := &config.Config{RequestURL: requestURL, Insecure: true, ECHGrease: true, OutputJSON: true}
	out := output.NewOutputWithWriters(jsonOutput, &bytes.Buffer{}, false, true)
	transport, err := NewTransport(cfg, out)
	if err != nil {
		t.Fatalf("create ECH GREASE transport: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, requestURL.String(), nil)
	if err != nil {
		t.Fatalf("create local request: %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("local request with ECH GREASE: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if err = out.Write(resp, resp.Body, cfg); err != nil {
		t.Fatalf("write JSON response: %v", err)
	}
	var result output.ResponseData
	if err = json.Unmarshal(jsonOutput.Bytes(), &result); err != nil {
		t.Fatalf("decode JSON output: %v", err)
	}
	if len(result.Connections) != 1 || result.Connections[0].CaptureStatus != "NOT_OBSERVED" {
		t.Fatalf("connection report = %+v, want one NOT_OBSERVED ECH GREASE capture", result.Connections)
	}
}

func TestECHAcceptedLocalServerHandlesHTTPRequest(t *testing.T) {
	runECHAcceptedLocalServerHandlesHTTPRequest(t, "")
}

func TestECHAcceptedLocalServerHandlesHTTPRequestThroughHTTPConnect(t *testing.T) {
	runECHAcceptedLocalServerHandlesHTTPRequest(t, "http")
}

func TestECHAcceptedLocalServerHandlesHTTPRequestThroughHTTPSProxyConnect(t *testing.T) {
	runECHAcceptedLocalServerHandlesHTTPRequest(t, "https")
}

func TestECHAcceptedLocalServerHandlesHTTPRequestThroughSOCKS5AndSOCKS5H(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			runECHAcceptedLocalServerHandlesHTTPRequest(t, scheme)
		})
	}
}

func runECHAcceptedLocalServerHandlesHTTPRequest(t *testing.T, proxyScheme string) {
	echConfig, provider, err := localECHConfigAndProvider()
	if err != nil {
		t.Fatalf("create local ECH keys: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	targetHost := "ech.example.test"
	if proxyScheme == "socks5" {
		// SOCKS5 resolves names with the system resolver. Use localhost here so
		// the test remains offline while still exercising the IPv4 SOCKS ATYP.
		targetHost = "localhost"
	}
	_, targetPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	targetURL := "https://" + net.JoinHostPort(targetHost, targetPort) + "/ech-accepted"
	proxyRequests := make(chan string, 1)
	proxyURL, socksResults := startECHRouteProxy(t, proxyScheme, listener, proxyRequests)
	cert := localTestCertificate(t)
	serverResults := make(chan echHTTPServerResult, 1)
	go serveAcceptedECHHTTP(listener, cert, provider, serverResults)

	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsRequests := make(chan string, 1)
	dnsServer := &dns.Server{
		PacketConn: dnsConn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
			serveECHHTTPSRecord(w, request, targetHost, echConfig, dnsRequests)
		}),
	}
	go func() { _ = dnsServer.ActivateAndServe() }()
	t.Cleanup(func() { _ = dnsServer.Shutdown() })
	dnsUpstream, err := upstream.AddressToUpstream(dnsConn.LocalAddr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		RequestURL: parsedURL,
		ECH:        true,
		DNSServers: []upstream.Upstream{dnsUpstream},
		Resolve:    map[string][]net.IP{targetHost: {net.IPv4(127, 0, 0, 1).To4()}},
		Insecure:   true,
	}
	cfg.ProxyURL = proxyURL
	cfg.ProxyInsecure = proxyScheme == "https"
	transport, err := NewTransport(cfg, output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false))
	if err != nil {
		t.Fatalf("create ECH transport: %v", err)
	}
	defer func() {
		if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}()
	request, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("gocurl HTTP request with ECH: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatalf("read ECH response: %v", readErr)
	}
	if response.StatusCode != http.StatusOK || string(body) != "ech-accepted" {
		t.Fatalf("response = %d %q, want 200 ech-accepted", response.StatusCode, body)
	}
	assertAcceptedECHServer(t, targetHost, dnsRequests, serverResults)
	assertECHProxyRoute(t, proxyScheme, targetHost, targetPort, proxyRequests, socksResults)
}

type localECHSOCKSResult struct {
	atyp    byte
	address string
	err     error
}

func serveLocalECHSOCKSProxy(proxy net.Listener, target net.Listener, results chan<- localECHSOCKSResult) {
	client, err := proxy.Accept()
	if err != nil {
		results <- localECHSOCKSResult{err: err}
		return
	}
	defer func() { _ = client.Close() }()
	reader := bufio.NewReader(client)
	if err = acceptECHSOCKSGreeting(client, reader); err != nil {
		results <- localECHSOCKSResult{err: err}
		return
	}
	request := make([]byte, 4)
	if _, err = io.ReadFull(reader, request); err != nil {
		results <- localECHSOCKSResult{err: err}
		return
	}
	if request[0] != 5 || request[1] != 1 {
		results <- localECHSOCKSResult{err: fmt.Errorf("SOCKS request version/command = %d/%d, want 5/CONNECT", request[0], request[1])}
		return
	}
	var address string
	switch request[3] {
	case 1:
		ip := make([]byte, net.IPv4len)
		if _, err = io.ReadFull(reader, ip); err != nil {
			results <- localECHSOCKSResult{err: err}
			return
		}
		address = net.IP(ip).String()
	case 3:
		length, readErr := reader.ReadByte()
		if readErr != nil {
			results <- localECHSOCKSResult{err: readErr}
			return
		}
		domain := make([]byte, int(length))
		if _, err = io.ReadFull(reader, domain); err != nil {
			results <- localECHSOCKSResult{err: err}
			return
		}
		address = string(domain)
	case 4:
		ip := make([]byte, net.IPv6len)
		if _, err = io.ReadFull(reader, ip); err != nil {
			results <- localECHSOCKSResult{err: err}
			return
		}
		address = net.IP(ip).String()
	default:
		results <- localECHSOCKSResult{err: fmt.Errorf("unexpected SOCKS address type %d", request[3])}
		return
	}
	port := make([]byte, 2)
	if _, err = io.ReadFull(reader, port); err != nil {
		results <- localECHSOCKSResult{err: err}
		return
	}
	upstreamConn, err := net.Dial("tcp", target.Addr().String())
	if err != nil {
		results <- localECHSOCKSResult{err: err}
		return
	}
	defer func() { _ = upstreamConn.Close() }()
	results <- localECHSOCKSResult{atyp: request[3], address: address}
	if _, err = client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	go func() { _, _ = io.Copy(upstreamConn, reader) }()
	_, _ = io.Copy(client, upstreamConn)
}

func localECHConfigAndProvider() (encodedConfig []byte, provider ctls.ECHProvider, err error) {
	publicKey, privateKey, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	privateKeyBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
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
	contents = append(contents, 0, testutil.Uint8(len(publicName))) // maximum_name_length and name length
	contents = append(contents, publicName...)
	contents = appendUint16(contents, 0) // extensions length
	rawConfig := appendUint16(nil, 0xfe0d)
	rawConfig = appendUint16(rawConfig, testutil.Uint16(len(contents)))
	rawConfig = append(rawConfig, contents...)
	encodedConfig = appendUint16(nil, testutil.Uint16(len(rawConfig)))
	encodedConfig = append(encodedConfig, rawConfig...)
	serializedKey := appendUint16(nil, testutil.Uint16(len(privateKeyBytes)))
	serializedKey = append(serializedKey, privateKeyBytes...)
	serializedKey = appendUint16(serializedKey, testutil.Uint16(len(rawConfig)))
	serializedKey = append(serializedKey, rawConfig...)
	keys, err := ctls.EXP_UnmarshalECHKeys(serializedKey)
	if err != nil {
		return nil, nil, err
	}
	keySet, err := ctls.EXP_NewECHKeySet(keys)
	if err != nil {
		return nil, nil, err
	}
	return encodedConfig, keySet, nil
}

func TestPostQuantumHandshakeCompletesAgainstLocalTLSServer(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		_, _ = io.WriteString(w, "pq-handshake-ok")
	}))
	server.StartTLS()
	defer server.Close()
	requestURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse local TLS URL: %v", err)
	}
	cfg := &config.Config{
		RequestURL: requestURL,
		Insecure:   true,
		OutputJSON: true,
		Experiments: map[config.Experiment]string{
			config.ExpPostQuantum: "",
		},
	}
	jsonOutput := &bytes.Buffer{}
	out := output.NewOutputWithWriters(jsonOutput, &bytes.Buffer{}, false, true)
	transport, err := NewTransport(cfg, out)
	if err != nil {
		t.Fatalf("create PQ transport: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("create local request: %v", err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("PQ TLS request to local server: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read local response: %v", err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "pq-handshake-ok" ||
		response.TLS == nil || !response.TLS.HandshakeComplete || response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("PQ response = %d body %q TLS %+v", response.StatusCode, body, response.TLS)
	}
	if err = out.Write(response, io.NopCloser(bytes.NewReader(body)), cfg); err != nil {
		t.Fatalf("write JSON response: %v", err)
	}
	var result output.ResponseData
	if err = json.Unmarshal(jsonOutput.Bytes(), &result); err != nil {
		t.Fatalf("decode JSON output: %v", err)
	}
	if len(result.Connections) != 1 || result.Connections[0].CaptureStatus != "NOT_OBSERVED" {
		t.Fatalf("connection report = %+v, want NOT_OBSERVED for cfcrypto TLS engine", result.Connections)
	}
}

func TestPostQuantumHandshakeCompletesThroughHTTPConnect(t *testing.T) {
	runPostQuantumHandshakeThroughProxy(t, "http")
}

func TestPostQuantumHandshakeCompletesThroughHTTPSProxyConnect(t *testing.T) {
	runPostQuantumHandshakeThroughProxy(t, "https")
}

func runPostQuantumHandshakeThroughProxy(t *testing.T, proxyScheme string) {
	const targetHost = "pq-connect-target.test"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		servePQTestResponse(w, r, "pq-proxy-connect-ok", false)
	}))
	server.StartTLS()
	defer server.Close()
	_, targetPort, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}
	targetURL := "https://" + net.JoinHostPort(targetHost, targetPort) + "/pq"

	proxyRequests := make(chan string, 1)
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		servePQHTTPProxy(t, proxyScheme, server.Listener.Addr().String(), proxyRequests, w, r)
	})
	var proxyServer *httptest.Server
	if proxyScheme == "https" {
		proxyServer = httptest.NewTLSServer(proxyHandler)
	} else {
		proxyServer = httptest.NewServer(proxyHandler)
	}
	defer proxyServer.Close()
	requestURL, err := url.Parse(targetURL)
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	cfg := &config.Config{
		RequestURL:    requestURL,
		ProxyURL:      proxyURL,
		Insecure:      true,
		ProxyInsecure: proxyScheme == "https",
		Experiments: map[config.Experiment]string{
			config.ExpPostQuantum: "",
		},
	}
	transport, err := NewTransport(cfg, output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false))
	if err != nil {
		t.Fatalf("create post-quantum HTTP proxy transport: %v", err)
	}
	defer func() {
		if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("create PQ request: %v", err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("post-quantum request through HTTP CONNECT: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("read PQ response: %v", err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "pq-proxy-connect-ok" ||
		response.TLS == nil || !response.TLS.HandshakeComplete || response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf(
			"post-quantum %s proxy CONNECT response = %d %q TLS %+v",
			proxyScheme,
			response.StatusCode,
			body,
			response.TLS,
		)
	}
	select {
	case authority := <-proxyRequests:
		if authority != net.JoinHostPort(targetHost, targetPort) {
			t.Fatalf("CONNECT authority = %q, want %q", authority, net.JoinHostPort(targetHost, targetPort))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s proxy CONNECT", proxyScheme)
	}
}

func TestPostQuantumHandshakeCompletesThroughSOCKS5AndSOCKS5H(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			runPostQuantumHandshakeThroughSOCKS(t, scheme)
		})
	}
}

func runPostQuantumHandshakeThroughSOCKS(t *testing.T, scheme string) {
	targetHost := "pq-target.test"
	if scheme == "socks5" {
		// SOCKS5 resolves with the system resolver; localhost keeps the test offline.
		targetHost = "localhost"
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		servePQTestResponse(w, r, "pq-socks-ok", false)
	}))
	server.StartTLS()
	defer server.Close()
	_, targetPort, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}
	targetURL := "https://" + net.JoinHostPort(targetHost, targetPort) + "/pq"

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for %s proxy: %v", scheme, err)
	}
	defer func() { _ = proxyListener.Close() }()
	proxyResult := make(chan localECHSOCKSResult, 1)
	go serveLocalECHSOCKSProxy(proxyListener, server.Listener, proxyResult)

	requestURL, err := url.Parse(targetURL)
	if err != nil {
		t.Fatalf("parse local target URL: %v", err)
	}
	proxyURL := &url.URL{Scheme: scheme, Host: proxyListener.Addr().String()}
	cfg := &config.Config{
		RequestURL: requestURL,
		ProxyURL:   proxyURL,
		Insecure:   true,
		Experiments: map[config.Experiment]string{
			config.ExpPostQuantum: "",
		},
	}
	transport, err := NewTransport(cfg, output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false))
	if err != nil {
		t.Fatalf("create post-quantum %s transport: %v", scheme, err)
	}
	defer func() {
		if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("create post-quantum request: %v", err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("post-quantum request through %s: %v", scheme, err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("read post-quantum response: %v", err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "pq-socks-ok" ||
		response.TLS == nil || !response.TLS.HandshakeComplete || response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("post-quantum %s response = %d %q TLS %+v", scheme, response.StatusCode, body, response.TLS)
	}
	assertPQSOCKSRoute(ctx, t, scheme, targetHost, proxyResult)
}

func TestPostQuantumHTTP2HandshakeCompletesThroughSOCKS5H(t *testing.T) {
	const targetHost = "pq-h2-target.test"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		servePQTestResponse(w, r, "pq-http2-socks5h-ok", true)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	_, targetPort, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}
	targetURL := "https://" + net.JoinHostPort(targetHost, targetPort) + "/pq-http2"

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SOCKS5H proxy: %v", err)
	}
	defer func() { _ = proxyListener.Close() }()
	proxyResult := make(chan localECHSOCKSResult, 1)
	go serveLocalECHSOCKSProxy(proxyListener, server.Listener, proxyResult)

	requestURL, err := url.Parse(targetURL)
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}
	cfg := &config.Config{
		RequestURL: requestURL,
		ProxyURL:   &url.URL{Scheme: "socks5h", Host: proxyListener.Addr().String()},
		Insecure:   true,
		ForceHTTP2: true,
		Experiments: map[config.Experiment]string{
			config.ExpPostQuantum: "",
		},
	}
	transport, err := NewTransport(cfg, output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false))
	if err != nil {
		t.Fatalf("create post-quantum HTTP/2 SOCKS5H transport: %v", err)
	}
	defer func() {
		if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("create HTTP/2 PQ request: %v", err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("post-quantum HTTP/2 request through SOCKS5H: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("read HTTP/2 PQ response: %v", err)
	}
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusOK || string(body) != "pq-http2-socks5h-ok" ||
		response.TLS == nil || !response.TLS.HandshakeComplete || response.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("PQ SOCKS5H response = %s %d %q TLS %+v", response.Proto, response.StatusCode, body, response.TLS)
	}
	select {
	case result := <-proxyResult:
		if result.err != nil || result.atyp != 3 || result.address != targetHost {
			t.Fatalf("SOCKS5H CONNECT = %+v, want domain ATYP for %q", result, targetHost)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for SOCKS5H CONNECT observation")
	}
}

func TestProxyTLSObservationIsReportedAsSeparateLeg(t *testing.T) {
	ctx, _ := utlsengine.NewProfileCheckContext(context.Background())
	check := utlsengine.ProfileCheckResult{
		Status: "OBSERVED",
		Actual: utlsengine.Fingerprint{JA3: "proxy-ja3", JA4: "proxy-ja4"},
	}
	dialer := &clientDialer{}
	dialer.recordProxyTLSObservation(
		ctx,
		proxyObservationTestConn{checks: []utlsengine.ProfileCheckResult{check}},
		nil,
		3,
	)
	reports, ok := utlsengine.ProfileCheckReports(ctx)
	if !ok || len(reports) != 1 {
		t.Fatalf("reports = %+v, found=%t; want one proxy report", reports, ok)
	}
	report := reports[0]
	if report.Leg != "proxy" || report.Attempt != 3 || report.ConnectionID == "" ||
		report.CaptureStatus != "OBSERVED" || report.Actual == nil || report.Actual.JA3 != "proxy-ja3" {
		t.Fatalf("proxy report = %+v, want independent observed proxy leg", report)
	}
}

func TestTransportRoundTripUsesRequestLocalTLSStateConcurrently(t *testing.T) {
	connByPath := map[string]net.Conn{
		"/tls12": tlsStateTestConn{state: tls.ConnectionState{Version: tls.VersionTLS12}},
		"/tls13": tlsStateTestConn{state: tls.ConnectionState{Version: tls.VersionTLS13}},
	}
	entered := make(chan struct{}, len(connByPath))
	release := make(chan struct{})
	base := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		trace := httptrace.ContextClientTrace(r.Context())
		if trace == nil || trace.GotConn == nil {
			return nil, fmt.Errorf("request has no GotConn callback")
		}
		trace.GotConn(httptrace.GotConnInfo{Conn: connByPath[r.URL.Path]})
		entered <- struct{}{}
		<-release
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    r,
		}, nil
	})
	d := &clientDialer{cfg: &config.Config{}}
	// Simulate another concurrent dial completing last with TLS 1.3. Each
	// response must still use the connection captured from its own request.
	d.setConn(connByPath["/tls13"])
	tr := &transport{d: d, base: base}

	type roundTripResult struct {
		path string
		resp *http.Response
		err  error
	}
	results := make(chan roundTripResult, len(connByPath))
	for path := range connByPath {
		path := path
		go func() {
			req, err := http.NewRequest(http.MethodGet, "http://example.test"+path, nil)
			if err == nil {
				var resp *http.Response
				resp, err = tr.RoundTrip(req)
				results <- roundTripResult{path: path, resp: resp, err: err}
				return
			}
			results <- roundTripResult{path: path, err: err}
		}()
	}
	for range len(connByPath) {
		<-entered
	}
	close(release)

	for range len(connByPath) {
		result := <-results
		if result.err != nil {
			t.Errorf("RoundTrip(%s) error = %v", result.path, result.err)
			continue
		}
		want := uint16(tls.VersionTLS12)
		if result.path == "/tls13" {
			want = tls.VersionTLS13
		}
		if result.resp.TLS == nil || result.resp.TLS.Version != want {
			var got uint16
			if result.resp.TLS != nil {
				got = result.resp.TLS.Version
			}
			t.Errorf("RoundTrip(%s) TLS version = %#x, want %#x", result.path, got, want)
		}
		_ = result.resp.Body.Close()
	}
}

func TestHTTP2TransportReportsALPNHandshakeFailure(t *testing.T) {
	requests := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()

	cfg, err := config.ParseConfig([]string{"--http2", "--insecure", server.URL})
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	tr, err := NewTransport(cfg, output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false))
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	_, err = tr.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), `HTTP/2 requires TLS ALPN "h2"`) {
		t.Fatalf("RoundTrip() error = %v, want explicit h2 ALPN failure", err)
	}
	select {
	case <-requests:
		t.Fatal("HTTP request reached the handler despite ALPN mismatch")
	default:
	}
}

func TestHTTP2TransportRejectsMissingNegotiatedALPNBeforeSendingRequest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer listener.Close()
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{localTestCertificate(t)}})
	serverHandshake := make(chan error, 1)
	serverData := make(chan []byte, 1)
	go func() {
		conn, acceptErr := tlsListener.Accept()
		if acceptErr != nil {
			serverHandshake <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
			serverHandshake <- handshakeErr
			return
		}
		serverHandshake <- nil
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		data := make([]byte, 24)
		n, _ := conn.Read(data)
		serverData <- data[:n]
	}()

	requestURL := "https://" + listener.Addr().String()
	cfg, err := config.ParseConfig([]string{"--http2", "--insecure", requestURL})
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	tr, err := NewTransport(cfg, output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false))
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	_, err = tr.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), `requires negotiated ALPN "h2", got ""`) {
		t.Fatalf("RoundTrip() error = %v, want missing h2 ALPN error", err)
	}
	if err = <-serverHandshake; err != nil {
		t.Fatalf("server TLS handshake error = %v", err)
	}
	if data := <-serverData; len(data) != 0 {
		t.Fatalf("client sent %d application bytes before rejecting missing ALPN", len(data))
	}
}

type tlsStateTestConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c tlsStateTestConn) ConnectionState() tls.ConnectionState { return c.state }

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type proxyObservationTestConn struct {
	net.Conn
	checks []utlsengine.ProfileCheckResult
}

func (c proxyObservationTestConn) ProxyTLSObservations() []utlsengine.ProfileCheckResult {
	return c.checks
}

func TestNewRequestAddsDefaultFormContentTypeForData(t *testing.T) {
	requestURL, err := url.Parse("https://example.org/")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	cfg := &config.Config{
		RequestURL: requestURL,
		Data:       "a=1",
		Headers:    make(http.Header),
	}

	req, err := NewRequest(cfg)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	values := req.Header.Values("Content-Type")
	if len(values) != 1 || values[0] != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type values = %#v, want [application/x-www-form-urlencoded]", values)
	}
}

func serveECHHTTPProxy(
	t *testing.T,
	proxyScheme, targetAddress string,
	proxyRequests chan<- string,
	w http.ResponseWriter,
	r *http.Request,
) {
	if proxyScheme == "https" && (r.TLS == nil || !r.TLS.HandshakeComplete) {
		t.Error("HTTPS proxy did not complete its TLS handshake")
	}
	if r.Method != http.MethodConnect {
		http.Error(w, "expected CONNECT", http.StatusMethodNotAllowed)
		return
	}
	select {
	case proxyRequests <- r.Host:
	default:
	}
	tunnel, rw, hijackErr := w.(http.Hijacker).Hijack()
	if hijackErr != nil {
		t.Errorf("hijack HTTP CONNECT: %v", hijackErr)
		return
	}
	defer func() { _ = tunnel.Close() }()
	upstreamConn, dialErr := net.Dial("tcp", targetAddress)
	if dialErr != nil {
		t.Errorf("dial local ECH target: %v", dialErr)
		_, _ = io.WriteString(rw, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		_ = rw.Flush()
		return
	}
	defer func() { _ = upstreamConn.Close() }()
	if _, writeErr := io.WriteString(rw, "HTTP/1.1 200 Connection Established\r\n\r\n"); writeErr != nil {
		t.Errorf("write CONNECT response: %v", writeErr)
		return
	}
	if flushErr := rw.Flush(); flushErr != nil {
		t.Errorf("flush CONNECT response: %v", flushErr)
		return
	}
	go func() { _, _ = io.Copy(upstreamConn, tunnel) }()
	_, _ = io.Copy(tunnel, upstreamConn)
}

func startECHRouteProxy(
	t *testing.T,
	proxyScheme string,
	listener net.Listener,
	proxyRequests chan<- string,
) (proxyURL *url.URL, socksResults chan localECHSOCKSResult) {
	t.Helper()
	var err error
	var proxyServer *httptest.Server
	switch proxyScheme {
	case "http", "https":
		proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveECHHTTPProxy(t, proxyScheme, listener.Addr().String(), proxyRequests, w, r)
		})
		if proxyScheme == "https" {
			proxyServer = httptest.NewTLSServer(proxyHandler)
		} else {
			proxyServer = httptest.NewServer(proxyHandler)
		}
		t.Cleanup(proxyServer.Close)
		proxyURL, err = url.Parse(proxyServer.URL)
		if err != nil {
			t.Fatalf("parse local HTTP proxy URL: %v", err)
		}
	case "socks5", "socks5h":
		proxyListener, listenErr := net.Listen("tcp", "127.0.0.1:0")
		if listenErr != nil {
			t.Fatalf("listen for local SOCKS proxy: %v", listenErr)
		}
		t.Cleanup(func() { _ = proxyListener.Close() })
		proxyURL = &url.URL{Scheme: proxyScheme, Host: proxyListener.Addr().String()}
		socksResults = make(chan localECHSOCKSResult, 1)
		go serveLocalECHSOCKSProxy(proxyListener, listener, socksResults)
	}
	return proxyURL, socksResults
}

type echHTTPServerResult struct {
	accepted bool
	uri      string
	err      error
}

func serveAcceptedECHHTTP(
	listener net.Listener,
	cert tls.Certificate,
	provider ctls.ECHProvider,
	serverResults chan<- echHTTPServerResult,
) {
	conn, acceptErr := listener.Accept()
	if acceptErr != nil {
		serverResults <- echHTTPServerResult{err: acceptErr}
		return
	}
	defer func() { _ = conn.Close() }()
	server := ctls.Server(conn, &ctls.Config{
		Certificates: []ctls.Certificate{
			{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey, Leaf: cert.Leaf},
		},
		MinVersion:        ctls.VersionTLS13,
		ECHEnabled:        true,
		ServerECHProvider: provider,
	})
	if handshakeErr := server.Handshake(); handshakeErr != nil {
		serverResults <- echHTTPServerResult{err: fmt.Errorf("server TLS handshake: %w", handshakeErr)}
		return
	}
	request, readErr := http.ReadRequest(bufio.NewReader(server))
	if readErr != nil {
		serverResults <- echHTTPServerResult{accepted: server.ConnectionState().ECHAccepted, err: fmt.Errorf("read HTTP request: %w", readErr)}
		return
	}
	_ = request.Body.Close()
	_, writeErr := io.WriteString(
		server,
		"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nech-accepted",
	)
	serverResults <- echHTTPServerResult{accepted: server.ConnectionState().ECHAccepted, uri: request.RequestURI, err: writeErr}
}

func serveECHHTTPSRecord(
	w dns.ResponseWriter,
	request *dns.Msg,
	targetHost string,
	echConfig []byte,
	dnsRequests chan<- string,
) {
	response := new(dns.Msg)
	response.SetReply(request)
	if len(request.Question) > 0 && request.Question[0].Qtype == dns.TypeHTTPS &&
		strings.EqualFold(request.Question[0].Name, dns.Fqdn(targetHost)) {
		response.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(targetHost),
				Rrtype: dns.TypeHTTPS,
				Class:  dns.ClassINET,
				Ttl:    1,
			},
			Priority: 1,
			Target:   ".",
			Value:    []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: echConfig}},
		}}}
		select {
		case dnsRequests <- request.Question[0].Name:
		default:
		}
	}
	_ = w.WriteMsg(response)
}

func assertECHProxyRoute(
	t *testing.T,
	proxyScheme, targetHost, targetPort string,
	proxyRequests <-chan string,
	socksResults <-chan localECHSOCKSResult,
) {
	t.Helper()
	switch proxyScheme {
	case "http", "https":
		select {
		case authority := <-proxyRequests:
			if authority != net.JoinHostPort(targetHost, targetPort) {
				t.Fatalf(
					"%s proxy CONNECT authority = %q, want %q",
					proxyScheme,
					authority,
					net.JoinHostPort(targetHost, targetPort),
				)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for local %s proxy CONNECT", proxyScheme)
		}
	case "socks5", "socks5h":
		select {
		case result := <-socksResults:
			if result.err != nil {
				t.Fatalf("local SOCKS proxy: %v", result.err)
			}
			wantATYP := byte(1)
			if proxyScheme == "socks5h" {
				wantATYP = 3
			}
			if result.atyp != wantATYP {
				t.Fatalf("SOCKS ATYP = %d, want %d for %s", result.atyp, wantATYP, proxyScheme)
			}
			if proxyScheme == "socks5h" && result.address != targetHost {
				t.Fatalf("SOCKS5H target = %q, want %q", result.address, targetHost)
			}
			if proxyScheme == "socks5" && net.ParseIP(result.address) == nil {
				t.Fatalf("SOCKS5 target = %q, want a locally resolved IP", result.address)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for %s CONNECT", proxyScheme)
		}
	}
}

func assertImportedTLSStrictMismatch(
	t *testing.T,
	clientProfile utlsengine.ClientProfile,
	profile *utlsengine.Profile,
	requestURL *url.URL,
	serverURL string,
	out *output.Output,
) {
	t.Helper()
	strictProfile := clientProfile
	var err error
	strictProfile.Expected.JA4 = "not-the-observed-fingerprint"
	strictCfg := &config.Config{
		RequestURL: requestURL, Insecure: true, TLSProfile: profile,
		TLSProfileDocument: &strictProfile, TLSProfileCheck: true, TLSProfileStrict: true,
	}
	strictTransport, err := NewTransport(strictCfg, out)
	if err != nil {
		t.Fatalf("NewTransport(strict) error = %v", err)
	}
	strictReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serverURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strictResp, roundTripErr := strictTransport.RoundTrip(strictReq); roundTripErr == nil {
		if strictResp != nil {
			_ = strictResp.Body.Close()
		}
		t.Fatal("strict RoundTrip() succeeded despite an expected JA4 mismatch")
	} else if !strings.Contains(roundTripErr.Error(), "strict TLS profile check failed: MISMATCH") {
		t.Fatalf("strict RoundTrip() error = %v, want strict MISMATCH", roundTripErr)
	}
}

func assertImportedTLSHTTP2Profile(
	t *testing.T,
	clientProfile utlsengine.ClientProfile,
	requestURL *url.URL,
	serverURL string,
	out *output.Output,
	jsonOutput *bytes.Buffer,
) {
	t.Helper()
	clientProfile.Fields.ALPN = []string{"h2"}
	clientProfile.Fields.CustomALPN = []string{"h2"}
	profileH2, _, err := clientProfile.Materialize()
	if err != nil {
		t.Fatal(err)
	}
	profileH2Document := clientProfile
	cfgH2 := &config.Config{
		RequestURL: requestURL, Insecure: true, ForceHTTP2: true, TLSProfile: &profileH2,
		TLSProfileDocument: &profileH2Document, TLSProfileCheck: true, OutputJSON: true,
	}
	transportH2, err := NewTransport(cfgH2, out)
	if err != nil {
		t.Fatalf("NewTransport(HTTP/2) error = %v", err)
	}
	reqH2, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serverURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	respH2, err := transportH2.RoundTrip(reqH2)
	if err != nil {
		t.Fatalf("RoundTrip(HTTP/2) error = %v", err)
	}
	defer respH2.Body.Close()
	if respH2.StatusCode != http.StatusNoContent || respH2.ProtoMajor != 2 || respH2.TLS == nil ||
		respH2.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf(
			"HTTP/2 response = %s %d, TLS state = %+v; want HTTP/2 204 with negotiated h2",
			respH2.Proto,
			respH2.StatusCode,
			respH2.TLS,
		)
	}
	jsonOutput.Reset()
	if err = out.Write(respH2, respH2.Body, cfgH2); err != nil {
		t.Fatalf("write HTTP/2 JSON response: %v", err)
	}
	_ = respH2.Body.Close()
	var h2JSONResponse output.ResponseData
	if err = json.Unmarshal(jsonOutput.Bytes(), &h2JSONResponse); err != nil {
		t.Fatalf("decode HTTP/2 JSON response: %v; body=%s", err, jsonOutput.String())
	}
	if len(h2JSONResponse.Connections) != 1 || h2JSONResponse.Connections[0].Actual == nil ||
		len(h2JSONResponse.Connections[0].Actual.ALPN) == 0 ||
		h2JSONResponse.Connections[0].Actual.ALPN[0] != "h2" {
		t.Fatalf("HTTP/2 connection report = %+v, want one report with observed h2 ALPN", h2JSONResponse.Connections)
	}
}

func acceptECHSOCKSGreeting(client net.Conn, reader *bufio.Reader) error {
	var err error
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(reader, greeting); err != nil {
		return err
	}
	methods := make([]byte, int(greeting[1]))
	if _, err = io.ReadFull(reader, methods); err != nil {
		return err
	}
	if greeting[0] != 5 || len(methods) != 1 || methods[0] != 0 {
		return fmt.Errorf("unsupported SOCKS greeting %v methods %v", greeting, methods)
	}
	if _, err = client.Write([]byte{5, 0}); err != nil {
		return err
	}
	return nil
}

func servePQTestResponse(w http.ResponseWriter, r *http.Request, response string, requireHTTP2 bool) {
	if requireHTTP2 && r.ProtoMajor != 2 {
		http.Error(w, fmt.Sprintf("protocol = %s, want HTTP/2", r.Proto), http.StatusUpgradeRequired)
		return
	}
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
	_, _ = io.WriteString(w, response)
}

func servePQHTTPProxy(
	t *testing.T,
	proxyScheme, targetAddress string,
	proxyRequests chan<- string,
	w http.ResponseWriter,
	r *http.Request,
) {
	if proxyScheme == "https" && (r.TLS == nil || !r.TLS.HandshakeComplete) {
		t.Error("HTTPS proxy did not complete its TLS handshake")
	}
	if r.Method != http.MethodConnect {
		http.Error(w, "expected CONNECT", http.StatusMethodNotAllowed)
		return
	}
	select {
	case proxyRequests <- r.Host:
	default:
	}
	tunnel, rw, hijackErr := w.(http.Hijacker).Hijack()
	if hijackErr != nil {
		t.Errorf("hijack HTTP CONNECT: %v", hijackErr)
		return
	}
	defer func() { _ = tunnel.Close() }()
	upstreamConn, dialErr := net.Dial("tcp", targetAddress)
	if dialErr != nil {
		t.Errorf("dial local PQ target: %v", dialErr)
		return
	}
	defer func() { _ = upstreamConn.Close() }()
	if _, writeErr := io.WriteString(rw, "HTTP/1.1 200 Connection Established\r\n\r\n"); writeErr != nil {
		t.Errorf("write CONNECT response: %v", writeErr)
		return
	}
	if flushErr := rw.Flush(); flushErr != nil {
		t.Errorf("flush CONNECT response: %v", flushErr)
		return
	}
	go func() { _, _ = io.Copy(upstreamConn, tunnel) }()
	_, _ = io.Copy(tunnel, upstreamConn)
}

func assertPQSOCKSRoute(
	ctx context.Context,
	t *testing.T,
	scheme, targetHost string,
	proxyResult <-chan localECHSOCKSResult,
) {
	t.Helper()
	select {
	case result := <-proxyResult:
		wantATYP := byte(1)
		if scheme == "socks5h" {
			wantATYP = 3
		}
		if result.err != nil || result.atyp != wantATYP {
			t.Fatalf("%s CONNECT = %+v, want ATYP %d", scheme, result, wantATYP)
		}
		if scheme == "socks5h" && result.address != targetHost {
			t.Fatalf("SOCKS5H target = %q, want %q", result.address, targetHost)
		}
		if scheme == "socks5" && net.ParseIP(result.address) == nil {
			t.Fatalf("SOCKS5 target = %q, want a locally resolved IP", result.address)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s CONNECT observation", scheme)
	}
}

func assertImportedTLSJSONReport(t *testing.T, jsonResponse output.ResponseData, logs *bytes.Buffer) {
	t.Helper()
	if jsonResponse.StatusCode != http.StatusNoContent || jsonResponse.Proto == "" ||
		len(jsonResponse.Connections) != 1 {
		t.Fatalf("JSON response = %+v, want preserved response fields and one connection report", jsonResponse)
	}
	connection := jsonResponse.Connections[0]
	if connection.ConnectionID == "" || connection.Leg != "target" || connection.Attempt != 1 ||
		connection.HelloIndex != 1 || connection.Actual == nil || connection.CaptureStatus == "" {
		t.Fatalf("JSON connection report = %+v, want complete observed handshake metadata", connection)
	}
	if !bytes.Contains(logs.Bytes(), []byte("TLS_PROFILE_CHECK {\"status\":")) ||
		!bytes.Contains(logs.Bytes(), []byte("\"actual\":{\"ja3_string\":")) {
		t.Fatalf("profile check log does not contain structured actual fingerprint: %s", logs.String())
	}
}

func assertAcceptedECHServer(
	t *testing.T,
	targetHost string,
	dnsRequests <-chan string,
	serverResults <-chan echHTTPServerResult,
) {
	t.Helper()
	select {
	case name := <-dnsRequests:
		if !strings.EqualFold(name, dns.Fqdn(targetHost)) {
			t.Fatalf("DNS HTTPS query name = %q, want %q", name, dns.Fqdn(targetHost))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for local DNS HTTPS/SVCB ECH query")
	}
	select {
	case result := <-serverResults:
		if result.err != nil || !result.accepted || result.uri != "/ech-accepted" {
			t.Fatalf("local ECH server result = %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for local ECH server")
	}
}
