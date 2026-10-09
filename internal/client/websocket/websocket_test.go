package websocket

import (
	"encoding/base64"
	"net/http"
	"testing"
)

func TestUpgradeWebSocketUsesFreshKey(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "ws://example.test/socket", nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := UpgradeWebSocket(req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := UpgradeWebSocket(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, upgraded := range []*http.Request{first, second} {
		decoded, err := base64.StdEncoding.DecodeString(upgraded.Header.Get("Sec-WebSocket-Key"))
		if err != nil || len(decoded) != 16 {
			t.Fatalf("WebSocket nonce = %q, err = %v", upgraded.Header.Get("Sec-WebSocket-Key"), err)
		}
	}
	if first.Header.Get("Sec-WebSocket-Key") == second.Header.Get("Sec-WebSocket-Key") {
		t.Fatal("WebSocket nonce was reused")
	}
}

func TestIsWebSocketResponseChecksServerProof(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.test/socket", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	resp := &http.Response{StatusCode: http.StatusSwitchingProtocols, Request: req, Header: http.Header{
		"Connection":           {"keep-alive, Upgrade"},
		"Upgrade":              {"websocket"},
		"Sec-Websocket-Accept": {"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
	}}
	if !IsWebSocketResponse(resp) {
		t.Fatal("valid WebSocket handshake was rejected")
	}
	resp.Header.Set("Sec-WebSocket-Accept", "invalid")
	if IsWebSocketResponse(resp) {
		t.Fatal("invalid WebSocket server proof was accepted")
	}
	resp.Header.Set("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
	resp.Header.Del("Upgrade")
	if IsWebSocketResponse(resp) {
		t.Fatal("missing Upgrade header was accepted")
	}
}
