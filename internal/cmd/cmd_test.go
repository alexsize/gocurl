package cmd_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/gocurl/internal/cmd"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/chris-wood/ohttp-go"
	"github.com/cloudflare/circl/hpke"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/mccutchen/go-httpbin/v2/httpbin"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failedResponseWriter struct{}

func (failedResponseWriter) Write([]byte) (int, error)       { return 0, io.ErrClosedPipe }
func (failedResponseWriter) WriteString(string) (int, error) { return 0, io.ErrClosedPipe }

func TestRunReportsResponseWriteFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	cfg, err := config.ParseConfig([]string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Run(cfg, output.NewOutputWithWriters(failedResponseWriter{}, &bytes.Buffer{}, false, false))
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Run() error = %v, want io.ErrClosedPipe", err)
	}
}

func TestRunWebSocketUpgradeAndTextExchange(t *testing.T) {
	type websocketResult struct {
		request string
		err     error
	}
	serverResults := make(chan websocketResult, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/socket" ||
			r.Header.Get("Connection") != "Upgrade" || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
			r.Header.Get("Sec-WebSocket-Version") != "13" {
			http.Error(w, "invalid WebSocket upgrade request", http.StatusBadRequest)
			serverResults <- websocketResult{err: fmt.Errorf("unexpected request: %s %s, headers %v", r.Method, r.URL.Path, r.Header)}
			return
		}
		conn, buffered, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			serverResults <- websocketResult{err: fmt.Errorf("upgrade WebSocket: %w", err)}
			return
		}
		defer func() { _ = conn.Close() }()
		message, opcode, err := wsutil.ReadClientData(buffered)
		if err != nil {
			serverResults <- websocketResult{err: fmt.Errorf("read client WebSocket message: %w", err)}
			return
		}
		if opcode != ws.OpText || string(message) != "ping" {
			serverResults <- websocketResult{err: fmt.Errorf("client WebSocket message = opcode %d, %q; want text ping", opcode, message)}
			return
		}
		if err = wsutil.WriteServerText(buffered, []byte("pong")); err == nil {
			err = wsutil.WriteServerMessage(buffered, ws.OpClose, nil)
		}
		if err == nil {
			err = buffered.Flush()
		}
		serverResults <- websocketResult{request: string(message), err: err}
	}))
	defer server.Close()

	wssURL := "wss" + strings.TrimPrefix(server.URL, "https") + "/socket"
	cfg, err := config.ParseConfig([]string{"--insecure", "--data=ping", wssURL})
	if err != nil {
		t.Fatalf("parse WebSocket config: %v", err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	if err = cmd.Run(cfg, output.NewOutputWithWriters(stdout, stderr, false, false)); err != nil {
		t.Fatalf("run WebSocket request: %v (stderr: %s)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "pong") {
		t.Fatalf("WebSocket output = %q, want server text response pong", stdout.String())
	}
	select {
	case result := <-serverResults:
		if result.err != nil || result.request != "ping" {
			t.Fatalf("WebSocket server result = %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for WebSocket server exchange")
	}
}

func TestRunWebSocketUpgradeAndTextExchangeThroughHTTPProxy(t *testing.T) {
	results := make(chan webSocketExchangeResult, 1)
	target := newWebSocketExchangeTarget(t, results, false)
	defer target.Close()
	targetAddress := strings.TrimPrefix(target.URL, "https://")
	proxyTargets := make(chan string, 1)
	proxy := newConnectTestProxy(target.Listener.Addr().String(), proxyTargets, false)
	defer proxy.Close()

	wssURL := "wss://" + targetAddress + "/socket"
	cfg, err := config.ParseConfig([]string{"--insecure", "--data=ping", "--proxy=" + proxy.URL, wssURL})
	if err != nil {
		t.Fatalf("parse proxied WebSocket config: %v", err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	if err = cmd.Run(cfg, output.NewOutputWithWriters(stdout, stderr, false, false)); err != nil {
		t.Fatalf("run proxied WebSocket request: %v (stderr: %s)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "pong") {
		t.Fatalf("proxied WebSocket output = %q, want pong", stdout.String())
	}
	select {
	case got := <-proxyTargets:
		if got != targetAddress {
			t.Fatalf("HTTP CONNECT target = %q, want %q", got, targetAddress)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HTTP CONNECT")
	}
	select {
	case result := <-results:
		if result.err != nil || result.message != "ping" {
			t.Fatalf("WebSocket server exchange = %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for WebSocket server exchange")
	}
}

func TestRunWebSocketUpgradeAndTextExchangeThroughHTTPSProxy(t *testing.T) {
	results := make(chan webSocketExchangeResult, 1)
	target := newWebSocketExchangeTarget(t, results, true)
	defer target.Close()
	targetAddress := strings.TrimPrefix(target.URL, "https://")
	proxyTargets := make(chan string, 1)
	proxyServer := newConnectTestProxy(target.Listener.Addr().String(), proxyTargets, true)
	defer proxyServer.Close()

	wssURL := "wss://" + targetAddress + "/socket"
	cfg, err := config.ParseConfig([]string{
		"--insecure", "--proxy-insecure", "--data=ping", "--proxy=" + proxyServer.URL, wssURL,
	})
	if err != nil {
		t.Fatalf("parse WSS through HTTPS proxy config: %v", err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	if err = cmd.Run(cfg, output.NewOutputWithWriters(stdout, stderr, false, false)); err != nil {
		t.Fatalf("run WSS through HTTPS proxy: %v (stderr: %s)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "pong") {
		t.Fatalf("WSS output = %q, want pong", stdout.String())
	}
	select {
	case got := <-proxyTargets:
		if got != targetAddress {
			t.Fatalf("HTTPS CONNECT target = %q, want %q", got, targetAddress)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HTTPS CONNECT")
	}
	select {
	case result := <-results:
		if result.err != nil || result.message != "ping" {
			t.Fatalf("WebSocket server exchange = %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for WebSocket server exchange")
	}
}

func TestRunWebSocketUpgradeAndTextExchangeThroughSOCKS5(t *testing.T) {
	runWebSocketUpgradeAndTextExchangeThroughSOCKSProxy(t, "socks5", "127.0.0.1", 1)
}

func TestRunWebSocketUpgradeAndTextExchangeThroughSOCKS5H(t *testing.T) {
	runWebSocketUpgradeAndTextExchangeThroughSOCKSProxy(t, "socks5h", "localhost", 3)
}

func runWebSocketUpgradeAndTextExchangeThroughSOCKSProxy(t *testing.T, proxyScheme, targetHost string, wantATYP byte) {
	t.Helper()
	results := make(chan webSocketExchangeResult, 1)
	target := newWebSocketExchangeTarget(t, results, false)
	defer target.Close()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxyListener.Close() }()
	_, targetPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	targetAddress := net.JoinHostPort(targetHost, targetPort)
	targetAddr := target.Listener.Addr().String()
	proxyResults := make(chan cliWebSocketSOCKSResult, 1)
	go serveCLIWebSocketSOCKSProxy(proxyListener, targetAddr, wantATYP, proxyResults)

	wssURL := "wss://" + targetAddress + "/socket"
	cfg, err := config.ParseConfig(
		[]string{"--insecure", "--data=ping", "--proxy=" + proxyScheme + "://" + proxyListener.Addr().String(), wssURL},
	)
	if err != nil {
		t.Fatalf("parse %s WebSocket config: %v", proxyScheme, err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	if err = cmd.Run(cfg, output.NewOutputWithWriters(stdout, stderr, false, false)); err != nil {
		t.Fatalf("run %s WebSocket request: %v (stderr: %s)", proxyScheme, err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "pong") {
		t.Fatalf("%s WebSocket output = %q, want pong", proxyScheme, stdout.String())
	}
	select {
	case got := <-proxyResults:
		if got.err != nil || got.atyp != wantATYP || got.connectTarget != targetAddress {
			t.Fatalf("%s CONNECT result = %+v, want ATYP %d target %q", proxyScheme, got, wantATYP, targetAddress)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SOCKS5 CONNECT")
	}
	select {
	case got := <-results:
		if got.err != nil || got.message != "ping" {
			t.Fatalf("%s WebSocket server exchange = %+v", proxyScheme, got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SOCKS5 WebSocket exchange")
	}
}

func TestRunStreamsBinaryStdinWithoutVerboseLogConsumingIt(t *testing.T) {
	want := []byte{0x00, 0x01, 0xff, 0x00, 'x'}
	stdinFile, err := os.CreateTemp(t.TempDir(), "stdin-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stdinFile.Write(want); err != nil {
		t.Fatal(err)
	}
	if _, err = stdinFile.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	previousStdin := os.Stdin
	os.Stdin = stdinFile
	defer func() {
		os.Stdin = previousStdin
		_ = stdinFile.Close()
	}()

	got := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read request body: %v", readErr)
		}
		got <- body
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cfg, err := config.ParseConfig([]string{"--verbose", "--data-binary", "@-", server.URL})
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	err = cmd.Run(cfg, output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, true, false))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if actual := <-got; !bytes.Equal(actual, want) {
		t.Fatalf("server received body %v, want %v", actual, want)
	}
}

// TestRunBasicGET tests a basic HTTP GET request.
func TestRunBasicGET(t *testing.T) {
	// Create httpbin test server
	handler := httpbin.New()
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// Create buffers for output
	dataBuffer := &bytes.Buffer{}
	logBuffer := &bytes.Buffer{}

	// Parse config with test arguments
	args := []string{
		server.URL + "/get",
	}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	// Create output with mock writers
	out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

	// Run the command
	err = cmd.Run(cfg, out)
	require.NoError(t, err)

	// Verify the output
	data := dataBuffer.String()

	// httpbin /get returns JSON with the request details
	assert.Contains(t, data, server.URL+"/get")
}

// TestRunBasicPOST tests a basic HTTP POST request with data.
func TestRunBasicPOST(t *testing.T) {
	// Create httpbin test server
	handler := httpbin.New()
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// Create buffers for output
	dataBuffer := &bytes.Buffer{}
	logBuffer := &bytes.Buffer{}

	testData := "key1=value1&key2=value2"

	// Parse config with test arguments
	args := []string{
		"-X", "POST",
		"-d", testData,
		server.URL + "/post",
	}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	// Create output with mock writers
	out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

	// Run the command
	err = cmd.Run(cfg, out)
	require.NoError(t, err)

	// Verify the output contains the posted data
	data := dataBuffer.String()

	// httpbin /post returns JSON with the request details including the posted data
	assert.Contains(t, data, testData)
}

// TestRunWithHeaders tests a request with custom headers.
func TestRunWithHeaders(t *testing.T) {
	// Create httpbin test server
	handler := httpbin.New()
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// Create buffers for output
	dataBuffer := &bytes.Buffer{}
	logBuffer := &bytes.Buffer{}

	customHeaderValue := "test-value-12345"

	// Parse config with test arguments
	args := []string{
		"-H", "X-Custom-Header:" + customHeaderValue,
		server.URL + "/headers",
	}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	// Create output with mock writers
	out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

	// Run the command
	err = cmd.Run(cfg, out)
	require.NoError(t, err)

	// Verify the output contains our custom header
	data := dataBuffer.String()

	// httpbin /headers returns JSON with all request headers
	assert.Contains(t, data, customHeaderValue)
}

// TestRunWithJSONOutput tests the --json-output flag.
func TestRunWithJSONOutput(t *testing.T) {
	// Create httpbin test server
	handler := httpbin.New()
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// Create buffers for output
	dataBuffer := &bytes.Buffer{}
	logBuffer := &bytes.Buffer{}

	// Parse config with test arguments
	args := []string{
		"--json-output",
		server.URL + "/get",
	}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	// Create output with mock writers
	out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

	// Run the command
	err = cmd.Run(cfg, out)
	require.NoError(t, err)

	// Verify the output is valid JSON
	data := dataBuffer.Bytes()

	// Parse as JSON to verify it's valid
	var result output.ResponseData
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Verify the structure
	assert.Equal(t, 200, result.StatusCode)
	assert.Equal(t, "200 OK", result.Status)
	assert.NotEmpty(t, result.Headers)

	// Verify the body is base64 encoded
	decodedBody, err := base64.StdEncoding.DecodeString(result.BodyBase64)
	require.NoError(t, err)
	assert.Contains(t, string(decodedBody), server.URL+"/get")
}

// TestRunWithInMemoryOutput tests with in-memory output buffers.
func TestRunWithInMemoryOutput(t *testing.T) {
	// Create httpbin test server
	handler := httpbin.New()
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// Create buffers for output
	dataBuffer := &bytes.Buffer{}
	logBuffer := &bytes.Buffer{}

	// Parse config with test arguments (no output file, will use stdout)
	args := []string{
		server.URL + "/status/200",
	}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	// Create output with mock writers
	out := output.NewOutputWithWriters(dataBuffer, logBuffer, false, false)

	// Run the command
	err = cmd.Run(cfg, out)
	require.NoError(t, err)

	// Verify output exists (httpbin /status/200 returns no response body, just headers)
	data := dataBuffer.Bytes()

	// For status endpoint, body should be empty or minimal
	assert.NotNil(t, data)
}

// TestRunHTTPMethods tests various HTTP methods.
func TestRunHTTPMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			// Create httpbin test server
			handler := httpbin.New()
			server := httptest.NewServer(handler.Handler())
			defer server.Close()

			// Create buffers for output
			dataBuffer := &bytes.Buffer{}
			logBuffer := &bytes.Buffer{}

			// Parse config with test arguments
			endpoint := "/" + strings.ToLower(method)
			args := []string{
				"-X", method,
				server.URL + endpoint,
			}
			cfg, err := config.ParseConfig(args)
			require.NoError(t, err)

			// Create output with mock writers
			out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

			// Run the command
			err = cmd.Run(cfg, out)
			require.NoError(t, err)

			// Verify the output
			data := dataBuffer.String()

			// Verify we got a response
			assert.NotEmpty(t, data)
		})
	}
}

// TestRunStatusCodes tests handling of different HTTP status codes.
func TestRunStatusCodes(t *testing.T) {
	testCases := []struct {
		statusCode int
		expectErr  bool
	}{
		{200, false},
		{201, false},
		{301, false},
		{404, false},
		{500, false},
	}

	for _, tc := range testCases {
		//nolint:gosec // G115: statusCode is always 100-599, no overflow possible
		statusStr := string([]byte{
			byte(tc.statusCode/100 + '0'),
			byte((tc.statusCode%100)/10 + '0'),
			byte(tc.statusCode%10 + '0'),
		})
		t.Run("status_"+statusStr, func(t *testing.T) {
			// Create httpbin test server
			handler := httpbin.New()
			server := httptest.NewServer(handler.Handler())
			defer server.Close()

			// Create buffers for output
			dataBuffer := &bytes.Buffer{}
			logBuffer := &bytes.Buffer{}

			// Parse config with test arguments
			args := []string{
				server.URL + "/status/" + statusStr,
			}
			cfg, err := config.ParseConfig(args)
			require.NoError(t, err)

			// Create output with mock writers
			out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

			// Run the command
			err = cmd.Run(cfg, out)

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestRunUserAgent tests that a custom user agent can be set.
func TestRunUserAgent(t *testing.T) {
	// Create httpbin test server
	handler := httpbin.New()
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// Create buffers for output
	dataBuffer := &bytes.Buffer{}
	logBuffer := &bytes.Buffer{}

	customUA := "gocurl-test/1.0"

	// Parse config with test arguments
	args := []string{
		"-H", "User-Agent:" + customUA,
		server.URL + "/user-agent",
	}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	// Create output with mock writers
	out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

	// Run the command
	err = cmd.Run(cfg, out)
	require.NoError(t, err)

	// Verify the output contains our custom user agent
	data := dataBuffer.String()

	// httpbin /user-agent returns JSON with the user agent
	assert.Contains(t, data, customUA)
}

// TestRunVerboseOutput tests verbose mode (shouldn't crash, output goes to stderr).
func TestRunVerboseOutput(t *testing.T) {
	// Create httpbin test server
	handler := httpbin.New()
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// Create buffers for output
	dataBuffer := &bytes.Buffer{}
	logBuffer := &bytes.Buffer{}

	// Parse config with test arguments (with verbose flag)
	args := []string{
		"-v",
		server.URL + "/get",
	}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	// Create output with verbose enabled and mock writers
	out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

	// Run the command
	err = cmd.Run(cfg, out)
	require.NoError(t, err)

	// In verbose mode, we should see debug output in the log buffer
	assert.NotEmpty(t, logBuffer.String())
}

// TestRunConnectTimeout tests the --connect-timeout flag.
func TestRunConnectTimeout(t *testing.T) {
	// Create httpbin test server for the actual target
	handler := httpbin.New()
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// Create a listener that doesn't accept connections to simulate a timeout
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer log.OnCloserError(listener, log.DEBUG)

	// Get the actual port the listener is bound to
	listenerAddr := listener.Addr().(*net.TCPAddr)
	socksProxyAddr := fmt.Sprintf("socks5://127.0.0.1:%d", listenerAddr.Port)

	// Create buffers for output
	dataBuffer := &bytes.Buffer{}
	logBuffer := &bytes.Buffer{}

	// Parse config with test arguments
	// Use a short timeout to make the test faster
	args := []string{
		"--connect-timeout", "1",
		"-x", socksProxyAddr,
		server.URL + "/get",
	}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	// Create output with mock writers
	out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

	// Run the command - it should fail with a timeout error
	err = cmd.Run(cfg, out)
	require.Error(t, err)

	// Check the standard timeout cause, not implementation-specific wording.
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestRunOHTTP tests the Oblivious HTTP support.
func TestRunOHTTP(t *testing.T) {
	server, observations := createLocalOHTTPServer(t)
	const targetURL = "https://hidden-target.example.test/get?source=cli"

	// Create buffers for output
	dataBuffer := &bytes.Buffer{}
	logBuffer := &bytes.Buffer{}

	args := []string{
		"--ohttp-gateway-url", server.URL + "/gateway",
		"--ohttp-keys-url", server.URL + "/keys",
		targetURL,
	}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	// Create output with mock writers
	out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

	// Run the command
	err = cmd.Run(cfg, out)
	require.NoError(t, err)

	assert.Equal(t, "local-ohttp-ok", dataBuffer.String())
	select {
	case observation := <-observations:
		assert.Equal(t, http.MethodGet, observation.method)
		assert.Equal(t, targetURL, observation.targetURL)
	case <-time.After(2 * time.Second):
		t.Fatal("local OHTTP gateway did not receive the encapsulated request")
	}
}

// TestOHTTPInvalidOptions tests that invalid OHTTP option combinations are rejected.
func TestOHTTPInvalidOptions(t *testing.T) {
	testCases := []struct {
		name        string
		args        []string
		expectedErr string
	}{
		{
			name: "only_gateway_url",
			args: []string{
				"--ohttp-gateway-url", "https://example.com/gateway",
				"https://example.com/get",
			},
			expectedErr: "both --ohttp-gateway-url and --ohttp-keys-url must be specified",
		},
		{
			name: "only_keys_url",
			args: []string{
				"--ohttp-keys-url", "https://example.com/config",
				"https://example.com/get",
			},
			expectedErr: "both --ohttp-gateway-url and --ohttp-keys-url must be specified",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse config with invalid arguments
			_, err := config.ParseConfig(tc.args)

			// Verify that an error is returned
			require.Error(t, err)

			// Verify the error message contains the expected text
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

// TestOHTTPValidOptions tests that valid OHTTP option combinations are accepted.
func TestOHTTPValidOptions(t *testing.T) {
	// Parse config with both OHTTP arguments specified
	args := []string{
		"--ohttp-gateway-url", "https://example.com/gateway",
		"--ohttp-keys-url", "https://example.com/config",
		"https://example.com/get",
	}
	cfg, err := config.ParseConfig(args)

	// Verify that no error is returned
	require.NoError(t, err)

	// Verify that both URLs are parsed correctly
	assert.NotNil(t, cfg.OHTTPGatewayURL)
	assert.Equal(t, "https://example.com/gateway", cfg.OHTTPGatewayURL.String())
	assert.NotNil(t, cfg.OHTTPKeysURL)
	assert.Equal(t, "https://example.com/config", cfg.OHTTPKeysURL.String())
}

// TestRunWithProxy tests that the proxy argument works correctly.
func TestRunWithProxy(t *testing.T) {
	// Create httpbin test server (our target)
	handler := httpbin.New()
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// Create a test proxy server
	proxy, proxyReceived := createTestProxy()
	defer proxy.Close()

	// Create buffers for output
	dataBuffer := &bytes.Buffer{}
	logBuffer := &bytes.Buffer{}

	// Parse config with proxy argument
	args := []string{
		"-x", proxy.URL,
		server.URL + "/get",
	}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	// Create output with mock writers
	out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

	// Run the command
	err = cmd.Run(cfg, out)
	require.NoError(t, err)

	// Verify the request went through the proxy
	assert.True(t, *proxyReceived, "Request should have gone through the proxy")

	// Verify the output contains the expected response from httpbin
	data := dataBuffer.String()
	assert.Contains(t, data, server.URL+"/get")
}

// TestRunOHTTPWithProxy tests that OHTTP works correctly with a proxy.
func TestRunOHTTPWithProxy(t *testing.T) {
	server, observations := createLocalOHTTPServer(t)
	const targetURL = "https://hidden-target.example.test/get?source=proxy"

	// Create a test proxy server
	proxy, proxyReceived := createTestProxy()
	defer proxy.Close()

	// Create buffers for output
	dataBuffer := &bytes.Buffer{}
	logBuffer := &bytes.Buffer{}

	args := []string{
		"-x", proxy.URL,
		"--ohttp-gateway-url", server.URL + "/gateway",
		"--ohttp-keys-url", server.URL + "/keys",
		targetURL,
	}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	// Create output with mock writers
	out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

	// Run the command
	err = cmd.Run(cfg, out)
	require.NoError(t, err)

	// Verify the request went through the proxy
	assert.True(t, *proxyReceived, "OHTTP request should have gone through the proxy")

	assert.Equal(t, "local-ohttp-ok", dataBuffer.String())
	select {
	case observation := <-observations:
		assert.Equal(t, http.MethodGet, observation.method)
		assert.Equal(t, targetURL, observation.targetURL)
	case <-time.After(2 * time.Second):
		t.Fatal("local OHTTP gateway did not receive the proxied encapsulated request")
	}
}

type localOHTTPObservation struct {
	method    string
	targetURL string
}

func createLocalOHTTPServer(t *testing.T) (*httptest.Server, <-chan localOHTTPObservation) {
	t.Helper()
	privateConfig, err := ohttp.NewConfig(
		1,
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KDF_HKDF_SHA256,
		hpke.AEAD_AES128GCM,
	)
	require.NoError(t, err)
	gateway := ohttp.NewDefaultGateway([]ohttp.PrivateConfig{privateConfig})
	observations := make(chan localOHTTPObservation, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/keys":
			w.Header().Set("Content-Type", "application/ohttp-keys")
			_, _ = w.Write(privateConfig.Config().Marshal())
		case "/gateway":
			payload, readErr := io.ReadAll(request.Body)
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
			observations <- localOHTTPObservation{
				method:    decodedRequest.Method,
				targetURL: decodedRequest.URL.String(),
			}
			binaryResponse, marshalErr := (*ohttp.BinaryResponse)(&http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("local-ohttp-ok")),
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
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	return server, observations
}

// TestRunWithConnectTo tests the --connect-to flag functionality.
func TestRunWithConnectTo(t *testing.T) {
	// Create httpbin test server (our actual target)
	handler := httpbin.New()
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// Parse the server URL to extract host and port
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	// Create buffers for output
	dataBuffer := &bytes.Buffer{}
	logBuffer := &bytes.Buffer{}

	// Create a fake hostname that will be redirected to the real server
	fakeHost := "fake.example.com:80"

	// Parse config with --connect-to argument
	// Format: HOST1:PORT1:HOST2:PORT2
	// We redirect fake.example.com:80 to the actual test server
	connectToValue := fmt.Sprintf("fake.example.com:80:%s", serverURL.Host)
	args := []string{
		"--connect-to", connectToValue,
		"http://fake.example.com:80/get",
	}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	// Verify the connect-to mapping was parsed correctly
	require.NotNil(t, cfg.ConnectTo)
	require.Equal(t, serverURL.Host, cfg.ConnectTo[fakeHost])

	// Create output with mock writers
	out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

	// Run the command
	err = cmd.Run(cfg, out)
	require.NoError(t, err)

	// Verify the output contains the expected response from httpbin
	data := dataBuffer.String()

	// The response should contain data from httpbin's /get endpoint
	assert.Contains(t, data, "fake.example.com")
}

// TestRunWithHTTP3 tests the --http3 flag with an actual HTTP/3 server.
func TestRunWithHTTP3(t *testing.T) {
	// Create an HTTP/3 test server
	h3Server, serverAddr := createTestHTTP3Server(t)
	defer func() {
		_ = h3Server.Close()
	}()

	// Create buffers for output
	dataBuffer := &bytes.Buffer{}
	logBuffer := &bytes.Buffer{}

	// Parse config with --http3 flag
	// Use --insecure to skip certificate verification for the test server
	args := []string{
		"--http3",
		"--insecure",
		"https://" + serverAddr + "/get",
	}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	// Verify that ForceHTTP3 is set to true
	assert.True(t, cfg.ForceHTTP3, "ForceHTTP3 should be set to true when --http3 flag is used")

	// Create output with mock writers
	out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

	// Run the command
	err = cmd.Run(cfg, out)
	require.NoError(t, err)

	// Verify the output contains the expected response
	data := dataBuffer.String()
	assert.Contains(t, data, "HTTP/3 test response", "Response should contain HTTP/3 test data")
}

// TestRunWithHTTP3AndConnectTo tests the --http3 flag combined with --connect-to.
func TestRunWithHTTP3AndConnectTo(t *testing.T) {
	// Create an HTTP/3 test server (our actual target)
	h3Server, serverAddr := createTestHTTP3Server(t)
	defer func() {
		_ = h3Server.Close()
	}()

	// Create buffers for output
	dataBuffer := &bytes.Buffer{}
	logBuffer := &bytes.Buffer{}

	// Create a fake hostname that will be redirected to the real server
	fakeHost := "fake-http3.example.com:443"

	// Parse config with --http3 and --connect-to arguments
	// Format: HOST1:PORT1:HOST2:PORT2
	// We redirect fake-http3.example.com:443 to the actual test server
	connectToValue := fmt.Sprintf("fake-http3.example.com:443:%s", serverAddr)
	args := []string{
		"--http3",
		"--insecure",
		"--connect-to", connectToValue,
		"https://fake-http3.example.com:443/get",
	}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	// Verify the connect-to mapping was parsed correctly
	require.NotNil(t, cfg.ConnectTo)
	require.Equal(t, serverAddr, cfg.ConnectTo[fakeHost])

	// Verify that ForceHTTP3 is set to true
	assert.True(t, cfg.ForceHTTP3, "ForceHTTP3 should be set to true when --http3 flag is used")

	// Create output with mock writers
	out := output.NewOutputWithWriters(dataBuffer, logBuffer, cfg.Verbose, cfg.OutputJSON)

	// Run the command
	err = cmd.Run(cfg, out)
	require.NoError(t, err)

	// If the request succeeded (connect-to worked), verify the output
	data := dataBuffer.String()
	assert.Contains(t, data, "HTTP/3 test response", "Response should contain HTTP/3 test data")
}

// createTestProxy creates a test HTTP CONNECT proxy server that tracks requests.
// Returns the proxy server and a pointer to a boolean that indicates if the proxy
// received a request.
func createTestProxy() (*httptest.Server, *bool) {
	proxyReceived := false

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mark that proxy received a request
		proxyReceived = true

		// Only handle CONNECT method (tunnel)
		if r.Method != http.MethodConnect {
			http.Error(w, "Only CONNECT is supported", http.StatusMethodNotAllowed)
			return
		}

		// Extract target address from the request
		targetAddr := r.Host

		// Connect to the target server
		//nolint:gosec // G704: This is test code, targetAddr comes from test setup
		targetConn, err := net.Dial("tcp", targetAddr)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to connect to target: %v", err), http.StatusBadGateway)
			return
		}
		defer func() {
			_ = targetConn.Close()
		}()

		// Hijack the connection to handle the tunnel
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
			return
		}

		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to hijack connection: %v", err), http.StatusInternalServerError)
			return
		}
		defer func() {
			_ = clientConn.Close()
		}()

		// Send 200 Connection Established response
		_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if err != nil {
			return
		}

		// Start bidirectional copying between client and target
		done := make(chan struct{}, 2)

		go func() {
			_, _ = io.Copy(targetConn, clientConn)
			done <- struct{}{}
		}()

		go func() {
			_, _ = io.Copy(clientConn, targetConn)
			done <- struct{}{}
		}()

		// Wait for either direction to complete
		<-done
	}))

	return proxy, &proxyReceived
}

// createTestHTTP3Server creates a test HTTP/3 server using quic-go.
// Returns the server and its address.
func createTestHTTP3Server(t *testing.T) (server *http3.Server, addr string) {
	// Create a simple handler that returns test data
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		//nolint:gosec // G705: This is test code, not exposed to real users
		_, _ = w.Write([]byte(`{"message": "HTTP/3 test response", "url": "` + r.URL.String() + `"}`))
	})

	// Generate self-signed certificate for testing
	tlsConfig := generateTestTLSConfig(t)

	// Create HTTP/3 server
	server = &http3.Server{
		Handler:   handler,
		Addr:      "127.0.0.1:0", // Use port 0 to get a random available port
		TLSConfig: tlsConfig,
	}

	// Start listening
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	// Get the actual address the server is listening on
	addr = udpConn.LocalAddr().String()

	// Start the server in a goroutine
	go func() {
		_ = server.Serve(udpConn)
	}()

	return server, addr
}

// generateTestTLSConfig generates a self-signed certificate dynamically for testing.
func generateTestTLSConfig(t *testing.T) *tls.Config {
	// Generate a private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	// Encode certificate and key to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// Create TLS certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
}

type cliWebSocketSOCKSResult struct {
	connectTarget string
	atyp          byte
	err           error
}

func serveCLIWebSocketSOCKSProxy(
	proxyListener net.Listener,
	targetAddr string,
	wantATYP byte,
	proxyResults chan<- cliWebSocketSOCKSResult,
) {
	client, acceptErr := proxyListener.Accept()
	if acceptErr != nil {
		proxyResults <- cliWebSocketSOCKSResult{err: acceptErr}
		return
	}
	defer func() { _ = client.Close() }()
	reader := bufio.NewReader(client)
	if acceptErr = acceptCLIWebSocketSOCKSGreeting(client, reader); acceptErr != nil {
		proxyResults <- cliWebSocketSOCKSResult{err: acceptErr}
		return
	}
	request := make([]byte, 4)
	if _, acceptErr = io.ReadFull(reader, request); acceptErr != nil {
		proxyResults <- cliWebSocketSOCKSResult{err: acceptErr}
		return
	}
	if request[0] != 5 || request[1] != 1 || request[3] != wantATYP {
		proxyResults <- cliWebSocketSOCKSResult{atyp: request[3], err: fmt.Errorf("SOCKS5 request = %v, want CONNECT ATYP %d", request, wantATYP)}
		return
	}
	var host string
	var addressSize int
	switch request[3] {
	case 1:
		addressSize = net.IPv4len
	case 3:
		length, readErr := reader.ReadByte()
		if readErr != nil {
			proxyResults <- cliWebSocketSOCKSResult{atyp: request[3], err: readErr}
			return
		}
		addressSize = int(length)
	case 4:
		addressSize = net.IPv6len
	default:
		proxyResults <- cliWebSocketSOCKSResult{atyp: request[3], err: fmt.Errorf("unexpected SOCKS5 ATYP %d", request[3])}
		return
	}
	addressAndPort := make([]byte, addressSize+2)
	if _, acceptErr = io.ReadFull(reader, addressAndPort); acceptErr != nil {
		proxyResults <- cliWebSocketSOCKSResult{err: acceptErr}
		return
	}
	if request[3] == 1 || request[3] == 4 {
		host = net.IP(addressAndPort[:addressSize]).String()
	} else {
		host = string(addressAndPort[:addressSize])
	}
	connectTarget := net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(addressAndPort[addressSize:])))
	upstream, dialErr := net.Dial("tcp", targetAddr)
	if dialErr != nil {
		proxyResults <- cliWebSocketSOCKSResult{connectTarget: connectTarget, atyp: request[3], err: dialErr}
		return
	}
	defer func() { _ = upstream.Close() }()
	if _, acceptErr = client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); acceptErr != nil {
		proxyResults <- cliWebSocketSOCKSResult{connectTarget: connectTarget, atyp: request[3], err: acceptErr}
		return
	}
	proxyResults <- cliWebSocketSOCKSResult{connectTarget: connectTarget, atyp: request[3]}
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, reader)
		if closeWriter, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
		close(copyDone)
	}()
	_, _ = io.Copy(client, upstream)
	<-copyDone
}

func acceptCLIWebSocketSOCKSGreeting(client net.Conn, reader *bufio.Reader) error {
	var acceptErr error
	greeting := make([]byte, 2)
	if _, acceptErr = io.ReadFull(reader, greeting); acceptErr != nil {
		return acceptErr
	}
	methods := make([]byte, int(greeting[1]))
	if _, acceptErr = io.ReadFull(reader, methods); acceptErr != nil {
		return acceptErr
	}
	if greeting[0] != 5 || len(methods) != 1 || methods[0] != 0 {
		return fmt.Errorf("unexpected SOCKS5 greeting/methods: %v %v", greeting, methods)
	}
	if _, acceptErr = client.Write([]byte{5, 0}); acceptErr != nil {
		return acceptErr
	}
	return nil
}
