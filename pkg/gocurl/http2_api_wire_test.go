package gocurl

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestClientDoHTTP2SettingsAndOrderOnWire(t *testing.T) {
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := seed.TLS.Certificates[0]
	seed.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"h2"},
	})
	observed := make(chan apiHTTP2SettingsCapture, 1)
	serverErr := make(chan error, 1)
	releaseServer := make(chan struct{})
	defer close(releaseServer)
	go serveAPIHTTP2Settings(server, observed, serverErr, releaseServer)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	result, err := NewClient().Do(ctx, Request{
		URL:         "https://" + listener.Addr().String() + "/",
		HTTPVersion: "2",
		Insecure:    true,
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:   8192,
			MaxFrameSize:      32768,
			MaxHeaderListSize: 65536,
		},
		HTTP2SettingsOrder: []string{
			"MAX_FRAME_SIZE",
			"ENABLE_PUSH",
			"INITIAL_WINDOW_SIZE",
			"MAX_HEADER_LIST_SIZE",
			"HEADER_TABLE_SIZE",
		},
	})
	if err != nil {
		select {
		case serverErr := <-serverErr:
			t.Fatalf("Client.Do() = %v; HTTP/2 test server = %v", err, serverErr)
		default:
			t.Fatalf("Client.Do() = %v", err)
		}
	}
	defer result.Close()
	if result.Response.StatusCode != http.StatusOK || result.Response.ProtoMajor != 2 {
		t.Fatalf("response = %s %s, want HTTP/2 200", result.Response.Proto, result.Response.Status)
	}
	if _, err = io.Copy(io.Discard, result.Response.Body); err != nil {
		t.Fatalf("read response body: %v", err)
	}

	select {
	case got := <-observed:
		wantOrder := []http2.SettingID{
			http2.SettingMaxFrameSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
			http2.SettingHeaderTableSize,
		}
		if fmt.Sprint(got.order) != fmt.Sprint(wantOrder) {
			t.Errorf("client SETTINGS order = %v, want %v", got.order, wantOrder)
		}
		for id, want := range map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   8192,
			http2.SettingMaxFrameSize:      32768,
			http2.SettingMaxHeaderListSize: 65536,
		} {
			if value := got.values[id]; value != want {
				t.Errorf("client SETTINGS %v = %d, want %d; all = %+v", id, value, want, got.values)
			}
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("HTTP/2 test server: %v", err)
	}
}

type apiHTTP2SettingsCapture struct {
	values map[http2.SettingID]uint32
	order  []http2.SettingID
}

func serveAPIHTTP2Settings(
	server net.Listener,
	observed chan<- apiHTTP2SettingsCapture,
	serverErr chan<- error,
	releaseServer <-chan struct{},
) {
	conn, acceptErr := server.Accept()
	if acceptErr != nil {
		serverErr <- acceptErr
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		serverErr <- fmt.Errorf("accepted connection type is %T, want *tls.Conn", conn)
		return
	}
	if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
		serverErr <- handshakeErr
		return
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, readErr := io.ReadFull(conn, preface); readErr != nil || string(preface) != http2.ClientPreface {
		serverErr <- fmt.Errorf("HTTP/2 preface = %q, error = %v", preface, readErr)
		return
	}
	framer := http2.NewFramer(conn, conn)
	frame, readErr := framer.ReadFrame()
	if readErr != nil {
		serverErr <- readErr
		return
	}
	settings, ok := frame.(*http2.SettingsFrame)
	if !ok {
		serverErr <- fmt.Errorf("first client frame = %T, want SETTINGS", frame)
		return
	}
	got := apiHTTP2SettingsCapture{values: make(map[http2.SettingID]uint32)}
	if settingsErr := settings.ForeachSetting(func(setting http2.Setting) error {
		got.values[setting.ID] = setting.Val
		got.order = append(got.order, setting.ID)
		return nil
	}); settingsErr != nil {
		serverErr <- settingsErr
		return
	}
	observed <- got

	if writeErr := framer.WriteSettings(); writeErr != nil {
		serverErr <- writeErr
		return
	}
	for {
		frame, readErr = framer.ReadFrame()
		if readErr != nil {
			serverErr <- readErr
			return
		}
		if headers, isHeaders := frame.(*http2.HeadersFrame); isHeaders && headers.StreamID == 1 {
			break
		}
	}
	if writeErr := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: []byte{0x88}, // HPACK static-table entry for :status: 200.
		EndHeaders:    true,
		EndStream:     true,
	}); writeErr != nil {
		serverErr <- writeErr
		return
	}
	serverErr <- nil
	<-releaseServer
}
