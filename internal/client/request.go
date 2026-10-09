package client

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/ameshkov/gocurl/internal/appversion"
	"github.com/ameshkov/gocurl/internal/client/websocket"
	"github.com/ameshkov/gocurl/internal/config"
)

// NewRequest creates a new *http.Request based on *cmd.Options.
func NewRequest(cfg *config.Config) (req *http.Request, err error) {
	if cfg.DataBinary != "" && websocket.IsWebSocket(cfg.RequestURL) {
		return nil, fmt.Errorf("--data-binary is not supported for WebSocket requests")
	}
	bodyStream, bodyLength, err := prepareRequestBody(cfg)
	if err != nil {
		return nil, err
	}

	method := getMethod(cfg)

	req, err = http.NewRequest(method, cfg.RequestURL.String(), bodyStream)
	if err != nil {
		if closer, ok := bodyStream.(io.Closer); ok {
			_ = closer.Close()
		}
		return nil, err
	}
	if bodyLength >= 0 {
		req.ContentLength = bodyLength
	}

	addHeaders(req, cfg)
	if cfg.NoDefaultHeaders {
		if err := applyExactFraming(req); err != nil {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return nil, err
		}
	}
	if values, ok := req.Header["Host"]; ok {
		if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return nil, fmt.Errorf("request Host header requires one non-empty value")
		}
		req.Host = strings.TrimSpace(values[0])
		delete(req.Header, "Host")
	}
	addBodyHeaders(req, cfg)

	// Only set default User-Agent if it was not set by the user.
	if _, ok := req.Header["User-Agent"]; !ok {
		if cfg.NoDefaultHeaders {
			req.Header.Set("User-Agent", "")
		} else {
			req.Header.Set("User-Agent", fmt.Sprintf("gocurl/%s", appversion.Version()))
		}
	}

	ur, upgradeErr := websocket.UpgradeWebSocket(req)
	if upgradeErr != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, upgradeErr
	}
	if ur != nil {
		req = ur
	}

	return req, err
}

// prepareRequestBody leaves WebSocket data for the post-upgrade exchange and
// discovers regular-file lengths without consuming a binary request stream.
func prepareRequestBody(cfg *config.Config) (io.Reader, int64, error) {
	if websocket.IsWebSocket(cfg.RequestURL) {
		return nil, -1, nil
	}
	body, err := createBody(cfg)
	if err != nil {
		return nil, -1, err
	}
	file, ok := body.(*os.File)
	if !ok || cfg.DataBinary == "" {
		return body, -1, nil
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, -1, fmt.Errorf("inspect binary request body: %w", err)
	}
	if info.Mode().IsRegular() {
		return body, info.Size(), nil
	}
	return body, -1, nil
}

func applyExactFraming(req *http.Request) error {
	if values := req.Header.Values("Content-Length"); len(values) != 0 {
		if len(values) != 1 {
			return fmt.Errorf("--no-default-headers: repeated Content-Length is unsupported")
		}
		length, err := strconv.ParseInt(strings.TrimSpace(values[0]), 10, 64)
		if err != nil || length < 0 {
			return fmt.Errorf("--no-default-headers: invalid Content-Length")
		}
		if req.ContentLength < 0 || req.ContentLength != length {
			return fmt.Errorf(
				"--no-default-headers: Content-Length %d does not match the known body length %d",
				length,
				req.ContentLength,
			)
		}
		if req.Body == nil && (req.Method == http.MethodGet || req.Method == http.MethodHead) {
			return fmt.Errorf(
				"--no-default-headers: explicit Content-Length on %s cannot be sent by this transport",
				req.Method,
			)
		}
	}
	if values := req.Header.Values("Transfer-Encoding"); len(values) != 0 {
		if len(values) != 1 || !strings.EqualFold(strings.TrimSpace(values[0]), "chunked") ||
			req.Header.Get("Content-Length") != "" {
			return fmt.Errorf("--no-default-headers: unsupported or conflicting Transfer-Encoding")
		}
		if req.Body == nil {
			return fmt.Errorf("--no-default-headers: chunked encoding requires a request body")
		}
		req.TransferEncoding = []string{"chunked"}
		req.ContentLength = -1
	}
	return nil
}

// createBody creates body stream if it's required by the command-line
// arguments.
func createBody(cfg *config.Config) (body io.Reader, err error) {
	if cfg.DataBinary != "" {
		return createBinaryBody(cfg.DataBinary, os.Stdin)
	}
	if cfg.Data == "" {
		return nil, nil
	}

	return bytes.NewBufferString(cfg.Data), nil
}

func createBinaryBody(source string, stdin io.Reader) (io.Reader, error) {
	if !strings.HasPrefix(source, "@") || len(source) == 1 {
		return nil, fmt.Errorf("binary body source must be @<file> or @-")
	}
	path := strings.TrimPrefix(source, "@")
	if path == "-" {
		return io.NopCloser(stdin), nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open binary request body %q: %w", path, err)
	}
	return file, nil
}

// addBodyHeaders adds necessary HTTP headers if it's required by the
// command-line arguments. For instance, -d/--data requires adding the
// Content-Type: application/x-www-form-urlencoded header.
func addBodyHeaders(req *http.Request, cfg *config.Config) {
	if cfg.Data != "" && !cfg.NoDefaultHeaders && !websocket.IsWebSocket(cfg.RequestURL) &&
		req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
}

// addHeaders adds HTTP headers that are specified in command-line arguments.
func addHeaders(req *http.Request, cfg *config.Config) {
	for k, l := range cfg.Headers {
		for _, v := range l {
			req.Header.Add(k, v)
		}
	}
}
