package gocurl

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

func TestClientDoHTTP3SettingsOnWire(t *testing.T) {
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := seed.TLS.Certificates[0]
	seed.Close()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"h3"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	observed := make(chan apiHTTP3SettingsCapture, 1)
	serverErr := make(chan error, 1)
	serverDone := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseServer := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseServer()
	go serveAPIHTTP3Settings(ctx, listener, observed, serverErr, serverDone, release)

	resultCh := make(chan error, 1)
	go func() {
		result, doErr := NewClient().Do(ctx, Request{
			URL:         "https://" + listener.Addr().String() + "/",
			HTTPVersion: "3",
			Insecure:    true,
			HTTP3AdditionalSettings: map[uint64]uint64{
				64: 127,
				65: 0,
			},
			HTTP3Datagrams: true,
		})
		if result != nil {
			_ = result.Close()
		}
		resultCh <- doErr
	}()

	select {
	case got := <-observed:
		for id, want := range map[uint64]uint64{6: 10 * 1024 * 1024, 0x33: 1, 64: 127, 65: 0} {
			if value, ok := got.values[id]; !ok || value != want {
				t.Errorf("HTTP/3 SETTINGS[%#x] = %d, present %t; want %d; all = %v", id, value, ok, want, got.values)
			}
		}
		for _, id := range []uint64{1, 7, 8} {
			if _, ok := got.values[id]; ok {
				t.Errorf("HTTP/3 SETTINGS[%#x] is present; expected protocol default", id)
			}
		}
		wantOrder := []uint64{6, 0x33, 64, 65}
		if fmt.Sprint(got.order) != fmt.Sprint(wantOrder) {
			t.Errorf("HTTP/3 SETTINGS order = %v, want %v", got.order, wantOrder)
		}
	case err := <-serverErr:
		t.Fatalf("HTTP/3 test server: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	cancel()
	releaseServer()
	select {
	case doErr := <-resultCh:
		if doErr == nil {
			t.Error("Client.Do() succeeded although the test server did not send response SETTINGS or headers")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Client.Do() did not stop after its context was cancelled")
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP/3 test server did not stop")
	}
}

type apiHTTP3SettingsCapture struct {
	values map[uint64]uint64
	order  []uint64
}

func serveAPIHTTP3Settings(
	ctx context.Context,
	listener *quic.Listener,
	observed chan<- apiHTTP3SettingsCapture,
	serverErr chan<- error,
	serverDone chan<- struct{},
	release <-chan struct{},
) {
	defer close(serverDone)
	conn, acceptErr := listener.Accept(ctx)
	if acceptErr != nil {
		serverErr <- acceptErr
		return
	}
	defer func() { _ = conn.CloseWithError(0, "test complete") }()
	stream, streamErr := conn.AcceptUniStream(ctx)
	if streamErr != nil {
		serverErr <- streamErr
		return
	}
	reader := bufio.NewReader(stream)
	streamType, readErr := quicvarint.Read(reader)
	if readErr != nil || streamType != 0 {
		serverErr <- fmt.Errorf("HTTP/3 control stream type = %d, error = %v", streamType, readErr)
		return
	}
	frameType, readErr := quicvarint.Read(reader)
	if readErr != nil || frameType != 4 {
		serverErr <- fmt.Errorf("first HTTP/3 control frame type = %d, error = %v; want SETTINGS (4)", frameType, readErr)
		return
	}
	length, readErr := quicvarint.Read(reader)
	if readErr != nil || length > 8192 {
		serverErr <- fmt.Errorf("HTTP/3 SETTINGS length = %d, error = %v", length, readErr)
		return
	}
	payload := make([]byte, length)
	if _, readErr = io.ReadFull(reader, payload); readErr != nil {
		serverErr <- readErr
		return
	}
	got := apiHTTP3SettingsCapture{values: make(map[uint64]uint64)}
	settings := bytes.NewReader(payload)
	for settings.Len() > 0 {
		id, idErr := quicvarint.Read(settings)
		value, valueErr := quicvarint.Read(settings)
		if idErr != nil || valueErr != nil {
			serverErr <- fmt.Errorf("parse HTTP/3 SETTINGS: id error %v, value error %v", idErr, valueErr)
			return
		}
		got.values[id] = value
		got.order = append(got.order, id)
	}
	observed <- got
	<-release
}
