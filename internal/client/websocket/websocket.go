// Package websocket is responsible for handling WebSocket connections.
package websocket

import (
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- WebSocket server proof uses SHA-1 for protocol compatibility, not password hashing.
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/ameshkov/gocurl/internal/output"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// NewWebSocket returns an io.ReadWriterCloser that can be used to send and
// receive data to/from a websocket.
func NewWebSocket(conn net.Conn, out *output.Output) (rwc io.ReadWriteCloser) {
	return NewWebSocketStream(conn, out)
}

// NewWebSocketStream preserves bytes already buffered by an HTTP upgrade.
// It accepts the full-duplex response body as well as a raw connection.
func NewWebSocketStream(stream io.ReadWriteCloser, out *output.Output) io.ReadWriteCloser {
	r := wsutil.NewReader(stream, ws.StateClientSide)

	// TODO(ameshkov): Add support of OpBinary when POSTing binary data is
	// supported (for now --data is for text data only).
	w := wsutil.NewWriter(stream, ws.StateClientSide, ws.OpText)

	return &wsConn{
		conn: stream,
		r:    r,
		w:    w,
		out:  out,
	}
}

// wsConn represents a WebSocket connection that's been already initialized.
type wsConn struct {
	conn io.ReadWriteCloser
	r    *wsutil.Reader
	w    *wsutil.Writer
	out  *output.Output
}

// type check
var _ io.ReadWriteCloser = (*wsConn)(nil)

// Read implements the io.ReadWriteCloser interface for *wsConn. Returning
// io.EOF error does not mean that the reader is closed, it just means that all
// messages from the current frame has been read, so it should be safe to use
// io.ReadAll several times with this reader.
func (w *wsConn) Read(b []byte) (n int, err error) {
	n, err = w.r.Read(b)
	if err == wsutil.ErrNoFrameAdvance {
		w.out.Debug("Reading next WebSocket frame")

		hdr, fErr := w.r.NextFrame()
		if fErr != nil {
			return 0, fErr
		}

		w.out.Debug("Received frame with opcode=%d len=%d fin=%v", hdr.OpCode, hdr.Length, hdr.Fin)

		// Reading again in this case
		n, err = w.r.Read(b)
	}

	return n, err
}

// Write implements the io.ReadWriteCloser interface for *wsConn.
func (w *wsConn) Write(b []byte) (n int, err error) {
	w.out.Debug("Writing data of len=%d to the WebSocket", len(b))

	n, err = w.w.Write(b)
	if err != nil {
		return n, err
	}

	err = w.w.Flush()

	return n, err
}

// Close implements the io.ReadWriteCloser interface for *wsConn.
func (w *wsConn) Close() (err error) {
	return w.conn.Close()
}

// IsWebSocketResponse checks if the response is a valid 101 Switching Protocols
// response and the following data should follow the WebSocket protocol.
func IsWebSocketResponse(resp *http.Response) (ok bool) {
	if resp == nil || resp.Request == nil {
		return false
	}
	key := resp.Request.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return false
	}
	accept := sha1.Sum(
		[]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"),
	) // #nosec G401 -- Required WebSocket handshake encoding, not a security hash choice.
	return resp.StatusCode == http.StatusSwitchingProtocols &&
		headerHasToken(resp.Header.Values("Connection"), "upgrade") &&
		headerHasToken(resp.Header.Values("Upgrade"), "websocket") &&
		resp.Header.Get("Sec-WebSocket-Accept") == base64.StdEncoding.EncodeToString(accept[:])
}

func headerHasToken(values []string, token string) bool {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// IsWebSocket returns true if the request is to WebSocket.
func IsWebSocket(u *url.URL) (ok bool) {
	return u.Scheme == "ws" || u.Scheme == "wss"
}

// UpgradeWebSocket checks if the request r is a WebSocket requests and adds
// Upgrade header if needed.
func UpgradeWebSocket(r *http.Request) (upgradeReq *http.Request, err error) {
	if !IsWebSocket(r.URL) {
		return nil, nil
	}

	upgradeReq = r.Clone(r.Context())

	if upgradeReq.URL.Scheme == "ws" {
		upgradeReq.URL.Scheme = "http"
	}

	if upgradeReq.URL.Scheme == "wss" {
		upgradeReq.URL.Scheme = "https"
	}

	upgradeReq.Method = http.MethodGet
	upgradeReq.Header.Set("Connection", "Upgrade")
	upgradeReq.Header.Set("Upgrade", "websocket")
	upgradeReq.Header.Set("Sec-WebSocket-Version", "13")

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate WebSocket key: %w", err)
	}
	upgradeReq.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(nonce[:]))

	return upgradeReq, nil
}
