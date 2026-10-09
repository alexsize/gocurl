package cmd_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

type webSocketExchangeResult struct {
	message string
	err     error
}

func newWebSocketExchangeTarget(t *testing.T, results chan<- webSocketExchangeResult, checkPath bool) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if checkPath && r.URL.Path != "/socket" {
			t.Errorf("WebSocket target path = %q, want /socket", r.URL.Path)
		}
		conn, buffered, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			results <- webSocketExchangeResult{err: fmt.Errorf("upgrade WebSocket: %w", err)}
			return
		}
		defer func() { _ = conn.Close() }()
		message, opcode, err := wsutil.ReadClientData(buffered)
		if err != nil {
			results <- webSocketExchangeResult{err: fmt.Errorf("read client WebSocket message: %w", err)}
			return
		}
		if opcode != ws.OpText || string(message) != "ping" {
			results <- webSocketExchangeResult{err: fmt.Errorf("client message = opcode %d, %q; want text ping", opcode, message)}
			return
		}
		if err = wsutil.WriteServerText(buffered, []byte("pong")); err == nil {
			err = wsutil.WriteServerMessage(buffered, ws.OpClose, nil)
		}
		if err == nil {
			err = buffered.Flush()
		}
		results <- webSocketExchangeResult{message: string(message), err: err}
	}))
}

func newConnectTestProxy(targetAddress string, targets chan<- string, secure bool) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusMethodNotAllowed)
			return
		}
		targets <- r.Host
		upstream, err := net.Dial("tcp", targetAddress)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		defer func() { _ = client.Close() }()
		defer func() { _ = upstream.Close() }()
		if _, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err = buffered.Flush(); err != nil {
			return
		}
		copyDone := make(chan struct{})
		go func() {
			_, _ = io.Copy(upstream, buffered)
			if closeWriter, ok := upstream.(interface{ CloseWrite() error }); ok {
				_ = closeWriter.CloseWrite()
			}
			close(copyDone)
		}()
		_, _ = io.Copy(client, upstream)
		<-copyDone
	})
	if secure {
		return httptest.NewTLSServer(handler)
	}
	return httptest.NewServer(handler)
}
