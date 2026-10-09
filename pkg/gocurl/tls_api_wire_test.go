package gocurl

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientDoTLSCipherSuitesOnWire(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("request did not use TLS")
			return
		}
		if got, want := r.TLS.Version, uint16(tls.VersionTLS12); got != want {
			t.Errorf("negotiated TLS version = %x, want %x", got, want)
		}
		if got, want := r.TLS.CipherSuite, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; got != want {
			t.Errorf("negotiated cipher suite = %x, want %x", got, want)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{}
	server.TLS.MinVersion = tls.VersionTLS12
	server.TLS.MaxVersion = tls.VersionTLS12
	server.TLS.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	server.StartTLS()
	defer server.Close()

	response, err := (&Client{}).Do(context.Background(), Request{
		URL:             server.URL,
		HTTPVersion:     "1.1",
		TLSMinVersion:   "1.2",
		TLSMaxVersion:   "1.2",
		TLSCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		Insecure:        true,
	})
	if err != nil {
		t.Fatalf("Client.Do() error = %v", err)
	}
	defer response.Close()
	if got, want := response.Response.StatusCode, http.StatusNoContent; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

func TestClientDoTLSRandomOnWire(t *testing.T) {
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := seed.TLS.Certificates[0]
	seed.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	capturing := &clientHelloCaptureListener{Listener: listener, random: make(chan []byte, 1)}
	// #nosec G112 -- Loopback-only fixture closed by test cleanup, not a deployed HTTP server.
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(tls.NewListener(capturing, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{"http/1.1"},
		}))
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = capturing.Close()
		<-serveDone
	}()

	want := make([]byte, 32)
	for i := range want {
		want[i] = byte(i*7 + 3)
	}
	response, err := (&Client{}).Do(context.Background(), Request{
		URL:         "https://" + listener.Addr().String() + "/",
		HTTPVersion: "1.1",
		TLSRandom:   want,
		Insecure:    true,
	})
	if err != nil {
		t.Fatalf("Client.Do() error = %v", err)
	}
	defer response.Close()
	if got := <-capturing.random; !bytes.Equal(got, want) {
		t.Fatalf("ClientHello random = %x, want %x", got, want)
	}
}

type clientHelloCaptureListener struct {
	net.Listener
	random chan []byte
}

func (l *clientHelloCaptureListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	var header [5]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		conn.Close()
		return nil, err
	}
	record := make([]byte, int(header[3])<<8|int(header[4]))
	if _, err = io.ReadFull(conn, record); err != nil {
		conn.Close()
		return nil, err
	}
	if header[0] != 22 || len(record) < 38 || record[0] != 1 {
		conn.Close()
		return nil, io.ErrUnexpectedEOF
	}
	select {
	case l.random <- bytes.Clone(record[6:38]):
	default:
	}
	return &clientHelloReplayConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(header[:]), bytes.NewReader(record), conn),
	}, nil
}

type clientHelloReplayConn struct {
	net.Conn
	reader io.Reader
}

func (c *clientHelloReplayConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
