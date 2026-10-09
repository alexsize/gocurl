package gocurl

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientDoManualTLSClientHelloFieldsOnWire(t *testing.T) {
	const serverName = "manual-profile.example.test"
	const cipherSuite = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("request did not use TLS")
			return
		}
		if got, want := r.TLS.ServerName, serverName; got != want {
			t.Errorf("negotiated SNI = %q, want %q", got, want)
		}
		if got, want := r.TLS.Version, uint16(tls.VersionTLS12); got != want {
			t.Errorf("negotiated TLS version = %#x, want %#x", got, want)
		}
		if got, want := r.TLS.CipherSuite, cipherSuite; got != want {
			t.Errorf("negotiated cipher suite = %#x, want %#x", got, want)
		}
		if got, want := r.TLS.NegotiatedProtocol, "http/1.1"; got != want {
			t.Errorf("negotiated ALPN = %q, want %q", got, want)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{cipherSuite},
		NextProtos:   []string{"http/1.1"},
	}
	server.StartTLS()
	defer server.Close()

	result, err := NewClient().Do(context.Background(), Request{
		URL:         server.URL,
		HTTPVersion: "1.1",
		Insecure:    true,
		TLSProfile: &TLSProfile{ClientHello: &TLSClientHello{
			Preset:            "chrome-120",
			ServerName:        serverName,
			CipherSuites:      []uint16{cipherSuite},
			SupportedVersions: []uint16{tls.VersionTLS12},
			ALPN:              []string{"http/1.1"},
		}},
	})
	if err != nil {
		t.Fatalf("Client.Do() with manual TLS ClientHello: %v", err)
	}
	defer result.Close()
	if got, want := result.Response.StatusCode, http.StatusNoContent; got != want {
		t.Fatalf("response status = %d, want %d", got, want)
	}
}
