// Package cmd is the entry point of the tool.
package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/ameshkov/gocurl/internal/appversion"
	"github.com/ameshkov/gocurl/internal/client"
	"github.com/ameshkov/gocurl/internal/client/websocket"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	publicgocurl "github.com/ameshkov/gocurl/pkg/gocurl"
	goFlags "github.com/jessevdk/go-flags"
)

// Main is the entry point for the command-line tool.
func Main() {
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("gocurl version: %s\n", appversion.Version())

		os.Exit(0)
	}

	cfg, err := config.ParseConfig(os.Args[1:])
	var flagErr *goFlags.Error
	if errors.As(err, &flagErr) && flagErr.Type == goFlags.ErrHelp {
		// This is a special case when we exit process here as we received
		// --help.
		os.Exit(0)
	}

	if err != nil {
		parseErr := fmt.Errorf("failed to parse args: %w", err)
		if jsonOutputRequested(os.Args[1:]) {
			out := output.NewOutputWithWriters(os.Stdout, os.Stderr, false, true)
			out.Error("%v", &ExitCodeError{code: 2, err: parseErr})
		} else {
			_, _ = fmt.Fprintln(os.Stderr, parseErr)
		}

		os.Exit(2)
	}

	out, err := output.NewOutput(cfg.OutputPath, cfg.Verbose, cfg.OutputJSON)
	if err != nil {
		panic(err)
	}

	if err := Run(cfg, out); err != nil {
		err = withExitCode(err, 3)
		out.Error("%v", err)
		var coded interface{ ExitCode() int }
		if errors.As(err, &coded) {
			os.Exit(coded.ExitCode())
		}
		os.Exit(3)
	}
}

// Run executes the main logic of the gocurl command with the provided config
// and output. This function is extracted to make it testable.
func Run(cfg *config.Config, out *output.Output) error {
	out.Debug("Starting gocurl %s with arguments:\n%s", appversion.Version(), cfg.RawOptions)

	transport, err := client.NewTransport(cfg, out)
	if err != nil {
		return fmt.Errorf("failed to create HTTP transport: %w", err)
	}
	defer func() {
		if conn := transport.Conn(); conn != nil {
			_ = conn.Close()
		}
	}()

	req, err := client.NewRequest(cfg)
	if err != nil {
		return &ExitCodeError{code: 2, err: fmt.Errorf("failed to create request: %w", err)}
	}

	if cfg.Verbose {
		debugRequest(req, out)
	}

	result, err := publicgocurl.DoWithTransport(req.Context(), req, transport)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer result.Close()
	resp := result.Response

	// Response body is only written when we're sure that it is there and can
	// be fully read.
	var responseBody io.Reader
	if resp.ProtoMajor >= 2 ||
		// Content length guarantees that the response can be fully read.
		resp.ContentLength > 0 ||
		// Transfer-Encoding also guarantees that it's clear when body is
		// finished.
		len(resp.TransferEncoding) > 0 ||
		// OHTTP responses may not have any headers apart from content-type,
		// but they contain the full body right away.
		cfg.OHTTPGatewayURL != nil ||
		// When Connection: close we must read the body until the connection is
		// closed.
		resp.Header.Get("Connection") == "close" {
		responseBody = resp.Body
	}
	if req.Method == http.MethodHead {
		responseBody = nil
	}

	out.DebugResponse(resp)

	// WebSocket is processed differently. If request body is supplied with the
	// "data" command-line argument, it is sent as a text frame, and then it
	// waits until the response comes from the server.
	if websocket.IsWebSocketResponse(resp) {
		stream, ok := resp.Body.(io.ReadWriteCloser)
		if !ok {
			return fmt.Errorf("WebSocket response has no full-duplex stream")
		}
		wsConn := websocket.NewWebSocketStream(stream, out)
		defer func() {
			_ = wsConn.Close()
		}()

		if cfg.Data != "" {
			if _, wsErr := wsConn.Write([]byte(cfg.Data)); wsErr != nil {
				return fmt.Errorf("write WebSocket message: %w", wsErr)
			}
			b, wsErr := io.ReadAll(wsConn)
			if wsErr != nil {
				return fmt.Errorf("read WebSocket message: %w", wsErr)
			}
			responseBody = io.NopCloser(bytes.NewReader(b))
		}
	}

	// Write the response contents to the output.
	return out.Write(resp, responseBody, cfg)
}

// debugRequest preserves the actual request headers and never consumes a live
// file/stdin stream. Only bodies with a replay factory are copied for logging.
func debugRequest(req *http.Request, out *output.Output) {
	clone := req.Clone(req.Context())
	clone.Body = http.NoBody
	clone.ContentLength = 0
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			out.Debug("Cannot copy request body for debug logging: %v", err)
		} else {
			clone.Body = body
			clone.ContentLength = req.ContentLength
			if body != nil {
				defer func() { _ = body.Close() }()
			}
		}
	}
	out.DebugRequest(clone)
}

// ExitCodeError carries a process exit code while preserving the original error.
type ExitCodeError struct {
	code int
	err  error
}

func (e *ExitCodeError) Error() string { return e.err.Error() }
func (e *ExitCodeError) Unwrap() error { return e.err }

// ExitCode returns the process status associated with the wrapped error.
func (e *ExitCodeError) ExitCode() int { return e.code }

func withExitCode(err error, fallback int) error {
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		return err
	}
	return &ExitCodeError{code: fallback, err: err}
}

func jsonOutputRequested(args []string) bool {
	for _, arg := range args {
		if arg == "--json-output" || arg == "--json-output=true" || arg == "--json-output=1" {
			return true
		}
	}
	return false
}
