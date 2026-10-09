package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/cmd"
	"github.com/chris-wood/ohttp-go"
	"github.com/cloudflare/circl/hpke"
)

const cliHelperProcessEnv = "GO_WANT_GOCURL_HELPER_PROCESS"

func TestCLIUnsupportedProfileJSONExitCodeBeforeDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	profilePath, err := filepath.Abs("internal/client/utlsengine/testdata/profile-v1-unsupported.json")
	if err != nil {
		t.Fatalf("resolve unsupported profile fixture: %v", err)
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}

	// #nosec G204 -- Trusted test executable from os.Executable in fixed helper mode; no shell.
	command := exec.Command(
		testBinary,
		"-test.run=^TestCLIHelperProcess$",
		"--",
		"--json-output",
		"--tls-profile", profilePath,
		"https://"+listener.Addr().String()+"/unsupported-profile",
	)
	command.Env = append(os.Environ(), cliHelperProcessEnv+"=1")
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}
	command.Stdout = stdout
	command.Stderr = stderr

	err = command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf(
			"CLI error = %v, exit code = %d, want exit code 2; stdout=%q stderr=%q",
			err,
			command.ProcessState.ExitCode(),
			stdout.String(),
			stderr.String(),
		)
	}
	if stderr.Len() != 0 {
		t.Fatalf("CLI stderr = %q, want empty stderr for JSON output", stderr.String())
	}

	var result struct {
		Error    string `json:"error"`
		Status   string `json:"status"`
		ExitCode int    `json:"exit_code"`
	}
	if err = json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		t.Fatalf("decode CLI JSON %q: %v", stdout.String(), err)
	}
	if result.Status != "UNSUPPORTED" || result.ExitCode != 2 || !strings.Contains(result.Error, "UNSUPPORTED") {
		t.Fatalf("CLI JSON = %+v, want UNSUPPORTED and exit code 2", result)
	}

	if tcpListener, ok := listener.(*net.TCPListener); ok {
		if err = tcpListener.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatalf("set listener deadline: %v", err)
		}
	}
	connection, acceptErr := listener.Accept()
	if acceptErr == nil {
		_ = connection.Close()
		t.Fatal("CLI connected to the target before rejecting the unsupported profile")
	}
	if timeoutErr, ok := acceptErr.(net.Error); !ok || !timeoutErr.Timeout() {
		t.Fatalf("listener Accept() error = %v, want timeout proving no dial", acceptErr)
	}
}

func TestCLIConnectionErrorJSONExitCodeAfterDial(t *testing.T) {
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

	profilePath, err := filepath.Abs("internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatalf("resolve valid profile fixture: %v", err)
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}

	// #nosec G204 -- Trusted test executable from os.Executable in fixed helper mode; no shell.
	command := exec.Command(
		testBinary,
		"-test.run=^TestCLIHelperProcess$",
		"--",
		"--json-output",
		"--tls-profile", profilePath,
		"--tls-profile-check",
		"https://"+listener.Addr().String()+"/connection-error",
	)
	command.Env = append(os.Environ(), cliHelperProcessEnv+"=1")
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}
	command.Stdout = stdout
	command.Stderr = stderr

	err = command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf(
			"CLI error = %v, exit code = %d, want exit code 3; stdout=%q stderr=%q",
			err,
			command.ProcessState.ExitCode(),
			stdout.String(),
			stderr.String(),
		)
	}
	if !strings.Contains(stderr.String(), "TLS_PROFILE_CHECK") || !strings.Contains(stderr.String(), "PARTIAL_MATCH") {
		t.Fatalf("CLI stderr = %q, want the captured TLS_PROFILE_CHECK diagnostic", stderr.String())
	}

	var result struct {
		Error    string `json:"error"`
		Status   string `json:"status"`
		ExitCode int    `json:"exit_code"`
	}
	if err = json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		t.Fatalf("decode CLI JSON %q: %v", stdout.String(), err)
	}
	if result.Status != "CONNECTION_ERROR" || result.ExitCode != 3 {
		t.Fatalf("CLI JSON = %+v, want CONNECTION_ERROR and exit code 3", result)
	}
	select {
	case acceptErr := <-accepted:
		if acceptErr != nil {
			t.Fatalf("accept and close TLS connection: %v", acceptErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CLI did not establish the TCP connection before reporting CONNECTION_ERROR")
	}
}

func TestCLIIncompleteClientHelloJSONAndExitCode(t *testing.T) {
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

	profilePath, err := filepath.Abs("internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatalf("resolve valid profile fixture: %v", err)
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	// #nosec G204 -- Trusted test executable from os.Executable in fixed helper mode; no shell.
	command := exec.Command(
		testBinary,
		"-test.run=^TestCLIHelperProcess$",
		"--",
		"--json-output",
		"--tls-profile", profilePath,
		"--tls-profile-check",
		"--tls-split-hello=5:250",
		"https://"+listener.Addr().String()+"/incomplete-client-hello",
	)
	command.Env = append(os.Environ(), cliHelperProcessEnv+"=1")
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}
	command.Stdout = stdout
	command.Stderr = stderr

	err = command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 5 {
		t.Fatalf(
			"CLI error = %v, exit code = %d, want exit code 5; stdout=%q stderr=%q",
			err,
			command.ProcessState.ExitCode(),
			stdout.String(),
			stderr.String(),
		)
	}
	if !strings.Contains(stderr.String(), "TLS_PROFILE_CHECK") || !strings.Contains(stderr.String(), "INCOMPLETE") {
		t.Fatalf("CLI stderr = %q, want INCOMPLETE TLS_PROFILE_CHECK diagnostic", stderr.String())
	}

	var result struct {
		Error    string `json:"error"`
		Status   string `json:"status"`
		ExitCode int    `json:"exit_code"`
	}
	if err = json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		t.Fatalf("decode CLI JSON %q: %v", stdout.String(), err)
	}
	if result.Status != "INCOMPLETE" || result.ExitCode != 5 || !strings.Contains(result.Error, "INCOMPLETE") {
		t.Fatalf("CLI JSON = %+v, want INCOMPLETE and exit code 5", result)
	}
	select {
	case readErr := <-firstChunkRead:
		if readErr != nil {
			t.Fatalf("read and abort first ClientHello chunk: %v", readErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CLI did not send the first ClientHello chunk")
	}
}

func TestCLIStrictPartialMatchJSONAndExitCode(t *testing.T) {
	requestReachedServer := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestReachedServer <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	profilePath, err := filepath.Abs("internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatalf("resolve valid profile fixture: %v", err)
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	// #nosec G204 -- Trusted test executable from os.Executable in fixed helper mode; no shell.
	command := exec.Command(
		testBinary,
		"-test.run=^TestCLIHelperProcess$",
		"--",
		"--json-output",
		"--insecure",
		"--tls-profile", profilePath,
		"--tls-profile-strict",
		server.URL+"/partial-match",
	)
	command.Env = append(os.Environ(), cliHelperProcessEnv+"=1")
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}
	command.Stdout = stdout
	command.Stderr = stderr

	err = command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 4 {
		t.Fatalf(
			"CLI error = %v, exit code = %d, want exit code 4; stdout=%q stderr=%q",
			err,
			command.ProcessState.ExitCode(),
			stdout.String(),
			stderr.String(),
		)
	}
	if !strings.Contains(stderr.String(), "TLS_PROFILE_CHECK") || !strings.Contains(stderr.String(), "PARTIAL_MATCH") {
		t.Fatalf("CLI stderr = %q, want PARTIAL_MATCH TLS_PROFILE_CHECK diagnostic", stderr.String())
	}

	var result struct {
		Error    string `json:"error"`
		Status   string `json:"status"`
		ExitCode int    `json:"exit_code"`
	}
	if err = json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		t.Fatalf("decode CLI JSON %q: %v", stdout.String(), err)
	}
	if result.Status != "PARTIAL_MATCH" || result.ExitCode != 4 || !strings.Contains(result.Error, "PARTIAL_MATCH") {
		t.Fatalf("CLI JSON = %+v, want PARTIAL_MATCH and exit code 4", result)
	}
	select {
	case <-requestReachedServer:
		t.Fatal("strict PARTIAL_MATCH sent an HTTP request after rejecting the TLS connection")
	default:
	}
}

func TestCLIStrictMismatchJSONAndExitCode(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	profileData, err := os.ReadFile("internal/client/utlsengine/testdata/profile-v1-valid.json")
	if err != nil {
		t.Fatalf("read TLS profile fixture: %v", err)
	}
	profileJSON := strings.Replace(string(profileData), `"value": 771`, `"value": 770`, 1)
	if profileJSON == string(profileData) {
		t.Fatal("TLS profile fixture did not contain the expected version constraint")
	}
	profilePath := filepath.Join(t.TempDir(), "mismatch-profile.json")
	if err = os.WriteFile(profilePath, []byte(profileJSON), 0o600); err != nil {
		t.Fatalf("write mismatch profile fixture: %v", err)
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	// #nosec G204 -- Trusted test executable from os.Executable in fixed helper mode; no shell.
	command := exec.Command(
		testBinary,
		"-test.run=^TestCLIHelperProcess$",
		"--",
		"--json-output",
		"--insecure",
		"--tls-profile", profilePath,
		"--tls-profile-strict",
		server.URL+"/mismatch",
	)
	command.Env = append(os.Environ(), cliHelperProcessEnv+"=1")
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 4 {
		t.Fatalf(
			"CLI error = %v, exit code = %d, want exit code 4; stdout=%q stderr=%q",
			err,
			command.ProcessState.ExitCode(),
			stdout.String(),
			stderr.String(),
		)
	}
	if !strings.Contains(stderr.String(), "TLS_PROFILE_CHECK") || !strings.Contains(stderr.String(), "MISMATCH") {
		t.Fatalf("CLI stderr = %q, want MISMATCH TLS_PROFILE_CHECK diagnostic", stderr.String())
	}
	var result struct {
		Error    string `json:"error"`
		Status   string `json:"status"`
		ExitCode int    `json:"exit_code"`
	}
	if err = json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		t.Fatalf("decode CLI JSON %q: %v", stdout.String(), err)
	}
	if result.Status != "MISMATCH" || result.ExitCode != 4 || !strings.Contains(result.Error, "MISMATCH") {
		t.Fatalf("CLI JSON = %+v, want MISMATCH and exit code 4", result)
	}
	if got := requestCount.Load(); got != 0 {
		t.Fatalf("strict MISMATCH reached HTTP handler %d times, want zero", got)
	}
}

func TestCLISuccessJSONIncludesObservedTLSFingerprint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	// #nosec G204 -- Trusted test executable from os.Executable in fixed helper mode; no shell.
	command := exec.Command(
		testBinary,
		"-test.run=^TestCLIHelperProcess$",
		"--",
		"--json-output",
		"--insecure",
		server.URL+"/observed",
	)
	command.Env = append(os.Environ(), cliHelperProcessEnv+"=1")
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}
	command.Stdout = stdout
	command.Stderr = stderr
	if err = command.Run(); err != nil {
		t.Fatalf("CLI error = %v; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("CLI stderr = %q, want empty stderr", stderr.String())
	}
	var result struct {
		StatusCode  int `json:"status_code"`
		Connections []struct {
			Leg           string `json:"leg"`
			CaptureStatus string `json:"capture_status"`
			Actual        *struct {
				JA3 string `json:"ja3_hash"`
				JA4 string `json:"ja4"`
			} `json:"actual"`
		} `json:"connections"`
	}
	if err = json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		t.Fatalf("decode CLI JSON %q: %v", stdout.String(), err)
	}
	if result.StatusCode != http.StatusNoContent || len(result.Connections) != 1 {
		t.Fatalf("CLI JSON = %+v, want 204 response and one TLS report", result)
	}
	report := result.Connections[0]
	if report.Leg != "target" || report.CaptureStatus != "OBSERVED" || report.Actual == nil ||
		report.Actual.JA3 == "" || report.Actual.JA4 == "" {
		t.Fatalf("CLI TLS report = %+v, want actual target JA3/JA4 and OBSERVED status", report)
	}
}

func TestCLIECHGreaseJSONReportsNotObserved(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	// #nosec G204 -- Trusted test executable from os.Executable in fixed helper mode; no shell.
	command := exec.Command(
		testBinary,
		"-test.run=^TestCLIHelperProcess$",
		"--",
		"--json-output",
		"--insecure",
		"--echgrease",
		server.URL+"/ech-grease",
	)
	command.Env = append(os.Environ(), cliHelperProcessEnv+"=1")
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}
	command.Stdout = stdout
	command.Stderr = stderr
	if err = command.Run(); err != nil {
		t.Fatalf("CLI error = %v; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("CLI stderr = %q, want empty stderr", stderr.String())
	}
	var result struct {
		StatusCode  int `json:"status_code"`
		Connections []struct {
			Leg           string `json:"leg"`
			CaptureStatus string `json:"capture_status"`
			Actual        *struct {
				JA3 string `json:"ja3_hash"`
				JA4 string `json:"ja4"`
			} `json:"actual"`
		} `json:"connections"`
	}
	if err = json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		t.Fatalf("decode CLI JSON %q: %v", stdout.String(), err)
	}
	if result.StatusCode != http.StatusNoContent || len(result.Connections) != 1 {
		t.Fatalf("CLI JSON = %+v, want 204 response and one TLS report", result)
	}
	report := result.Connections[0]
	if report.Leg != "target" || report.CaptureStatus != "NOT_OBSERVED" || report.Actual != nil {
		t.Fatalf("CLI TLS report = %+v, want target NOT_OBSERVED without actual fingerprint", report)
	}
}

func TestCLIDataBinaryReturnsFirstRedirectWithoutRetry(t *testing.T) {
	type observedRequest struct {
		method        string
		path          string
		body          []byte
		contentLength int64
	}
	payload := []byte{'g', 'o', 'c', 'u', 'r', 'l', 0, 0xff, '\r', '\n'}

	for _, test := range []struct {
		name              string
		dataArgument      func(*testing.T) string
		stdin             []byte
		wantContentLength int64
	}{
		{
			name: "stdin",
			dataArgument: func(*testing.T) string {
				return "@-"
			},
			stdin:             payload,
			wantContentLength: -1,
		},
		{
			name: "file",
			dataArgument: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "body.bin")
				if err := os.WriteFile(path, payload, 0o600); err != nil {
					t.Fatalf("write binary request body: %v", err)
				}
				return "@" + path
			},
			wantContentLength: int64(len(payload)),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := make(chan observedRequest, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				body, readErr := io.ReadAll(request.Body)
				if readErr != nil {
					http.Error(w, readErr.Error(), http.StatusInternalServerError)
					return
				}
				requests <- observedRequest{
					method:        request.Method,
					path:          request.URL.Path,
					body:          body,
					contentLength: request.ContentLength,
				}
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(http.StatusTemporaryRedirect)
				_, _ = w.Write([]byte("first response"))
			}))
			defer server.Close()

			testBinary, err := os.Executable()
			if err != nil {
				t.Fatalf("resolve test executable: %v", err)
			}
			// #nosec G204 -- Trusted test executable from os.Executable in fixed helper mode; no shell.
			command := exec.Command(
				testBinary,
				"-test.run=^TestCLIHelperProcess$",
				"--",
				"--json-output",
				"--data-binary", test.dataArgument(t),
				server.URL+"/initial",
			)
			command.Env = append(os.Environ(), cliHelperProcessEnv+"=1")
			if test.stdin != nil {
				command.Stdin = bytes.NewReader(test.stdin)
			}
			stdout := &strings.Builder{}
			stderr := &strings.Builder{}
			command.Stdout = stdout
			command.Stderr = stderr

			if err = command.Run(); err != nil {
				t.Fatalf("CLI error = %v; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("CLI stderr = %q, want empty stderr", stderr.String())
			}
			var response struct {
				StatusCode int `json:"status_code"`
			}
			if err = json.Unmarshal([]byte(stdout.String()), &response); err != nil {
				t.Fatalf("decode CLI JSON %q: %v", stdout.String(), err)
			}
			if response.StatusCode != http.StatusTemporaryRedirect {
				t.Fatalf("CLI status = %d, want first response 307", response.StatusCode)
			}

			select {
			case request := <-requests:
				if request.method != http.MethodPost || request.path != "/initial" ||
					!bytes.Equal(request.body, payload) ||
					request.contentLength != test.wantContentLength {
					t.Fatalf(
						"request = %+v, want POST /initial, exact binary body and content length %d",
						request,
						test.wantContentLength,
					)
				}
			default:
				t.Fatal("server did not receive the initial request")
			}
			select {
			case request := <-requests:
				t.Fatalf("CLI followed redirect or retried request: %+v", request)
			default:
			}
		})
	}
}

func TestCLIHelperProcess(t *testing.T) {
	if os.Getenv(cliHelperProcessEnv) != "1" {
		return
	}
	separator := -1
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		t.Fatal("missing CLI argument separator")
	}
	os.Args = append([]string{"gocurl"}, os.Args[separator+1:]...)
	cmd.Main()
	os.Exit(0)
}

func TestCLIOHTTPJSONReportsRealReusedConnection(t *testing.T) {
	privateConfig, err := ohttp.NewConfig(1, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	if err != nil {
		t.Fatalf("create OHTTP config: %v", err)
	}
	gateway := ohttp.NewDefaultGateway([]ohttp.PrivateConfig{privateConfig})
	var connectionCount atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/keys":
			w.Header().Set("Content-Type", "application/ohttp-keys")
			_, _ = w.Write(privateConfig.Config().Marshal())
		case "/gateway":
			encapsulatedRequestBytes, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				http.Error(w, readErr.Error(), http.StatusBadRequest)
				return
			}
			encapsulatedRequest, decodeErr := ohttp.UnmarshalEncapsulatedRequest(encapsulatedRequestBytes)
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
				Body:       io.NopCloser(strings.NewReader("cli-ohttp-ok")),
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
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connectionCount.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()

	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	// #nosec G204 -- Trusted test executable from os.Executable in fixed helper mode; no shell.
	command := exec.Command(
		testBinary,
		"-test.run=^TestCLIHelperProcess$",
		"--",
		"--json-output",
		"--http1.1",
		"--insecure",
		"--ohttp-gateway-url="+server.URL+"/gateway",
		"--ohttp-keys-url="+server.URL+"/keys",
		"https://hidden-target.example.test/cli",
	)
	command.Env = append(os.Environ(), cliHelperProcessEnv+"=1")
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}
	command.Stdout = stdout
	command.Stderr = stderr
	if err = command.Run(); err != nil {
		t.Fatalf("CLI error = %v; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("CLI stderr = %q, want empty stderr for JSON output", stderr.String())
	}
	var result struct {
		BodyBase64  string `json:"body_base64"`
		Connections []struct {
			Leg           string `json:"leg"`
			CaptureStatus string `json:"capture_status"`
		} `json:"connections"`
	}
	if err = json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		t.Fatalf("decode CLI JSON %q: %v", stdout.String(), err)
	}
	if got := connectionCount.Load(); got != 1 {
		t.Fatalf("OHTTP TLS connections = %d, want one connection shared by keys and gateway", got)
	}
	foundReuse := false
	for _, report := range result.Connections {
		if report.Leg == "gateway" && report.CaptureStatus == "REUSED_CONNECTION" {
			foundReuse = true
		}
	}
	if !foundReuse {
		t.Fatalf("CLI connections = %+v, want real gateway REUSED_CONNECTION", result.Connections)
	}
}
