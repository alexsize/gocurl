package cmd_test

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- Local fixture encodes the standard WebSocket handshake proof.
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/cmd"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

func TestRunWebSocketReportsFrameErrorsAndLogsActualKey(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
		want  error
		early bool
	}{
		{"truncated header", []byte{0x81}, io.ErrUnexpectedEOF, false},
		{"truncated payload", []byte{0x81, 4, 'o', 'k'}, io.ErrUnexpectedEOF, false},
		{"masked server frame", []byte{0x81, 0x80, 0, 0, 0, 0}, ws.ErrProtocolMaskUnexpected, false},
		{"valid response", []byte{0x81, 2, 'o', 'k'}, nil, false},
		{"buffered response", []byte{0x81, 2, 'o', 'k'}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, serverResults, keys := websocketFrameServer(t, tc.frame, tc.early)
			defer server.Close()
			cfg, err := config.ParseConfig([]string{
				"--verbose", "--data", "ping", "ws" + strings.TrimPrefix(server.URL, "http") + "/socket",
			})
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			err = cmd.Run(cfg, output.NewOutputWithWriters(&stdout, &stderr, true, false))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Run() = %v, want %v", err, tc.want)
			}
			select {
			case serverErr := <-serverResults:
				if serverErr != nil {
					t.Fatal(serverErr)
				}
			case <-time.After(time.Second):
				t.Fatal("WebSocket fixture did not finish")
			}
			select {
			case key := <-keys:
				if key == "" || !strings.Contains(stderr.String(), "Sec-Websocket-Key: "+key) {
					t.Fatalf("verbose log does not contain the actual WebSocket key %q", key)
				}
			case <-time.After(time.Second):
				t.Fatal("fixture did not observe the WebSocket key")
			}
			if tc.want == nil && !strings.Contains(stdout.String(), "ok") {
				t.Fatalf("successful WebSocket output = %q, want ok", stdout.String())
			}
		})
	}
}

func websocketFrameServer(t *testing.T, frame []byte, early bool) (*httptest.Server, <-chan error, <-chan string) {
	t.Helper()
	results, keys := make(chan error, 1), make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		key := req.Header.Get("Sec-WebSocket-Key")
		keys <- key
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			results <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			results <- err
			return
		}
		digest := sha1.Sum(
			[]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"),
		) // #nosec G401 -- WebSocket handshake encoding, not a security hash choice.
		response := []byte(
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
				base64.StdEncoding.EncodeToString(digest[:]) + "\r\n\r\n",
		)
		if early {
			response = append(response, frame...)
		}
		if _, err = conn.Write(response); err != nil {
			results <- err
			return
		}
		message, opcode, err := wsutil.ReadClientData(buffered)
		if err != nil || opcode != ws.OpText || string(message) != "ping" {
			if err == nil {
				err = errors.New("unexpected client message")
			}
			results <- err
			return
		}
		if !early {
			_, err = conn.Write(frame)
		}
		results <- err
	}))
	return server, results, keys
}
