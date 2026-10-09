package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
)

func localTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer seed.Close()
	return seed.TLS.Certificates[0]
}

func TestHTTP2SettingsOnWire(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := tls.NewListener(
		listener,
		&tls.Config{Certificates: []tls.Certificate{localTestCertificate(t)}, NextProtos: []string{"h2"}},
	)
	type h2Capture struct {
		values map[http2.SettingID]uint32
		order  []http2.SettingID
	}
	observed := make(chan h2Capture, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := server.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		preface := make([]byte, len(http2.ClientPreface))
		if _, readErr := io.ReadFull(conn, preface); readErr != nil || string(preface) != http2.ClientPreface {
			serverErr <- fmt.Errorf("HTTP/2 preface = %q, error = %v", preface, readErr)
			return
		}
		frame, readErr := http2.NewFramer(nil, conn).ReadFrame()
		if readErr != nil {
			serverErr <- readErr
			return
		}
		settings, ok := frame.(*http2.SettingsFrame)
		if !ok {
			serverErr <- fmt.Errorf("first frame = %T, want SETTINGS", frame)
			return
		}
		values := map[http2.SettingID]uint32{}
		var order []http2.SettingID
		if settingsErr := settings.ForeachSetting(func(s http2.Setting) error {
			values[s.ID] = s.Val
			order = append(order, s.ID)
			return nil
		}); settingsErr != nil {
			serverErr <- settingsErr
			return
		}
		observed <- h2Capture{values: values, order: order}
	}()

	cfg, err := config.ParseConfig(
		[]string{
			"--http2",
			"--insecure",
			"--h2-header-table-size=8192",
			"--h2-max-frame-size=32768",
			"--h2-max-header-list-size=65536",
			"--h2-settings-order=MAX_FRAME_SIZE,ENABLE_PUSH,INITIAL_WINDOW_SIZE,MAX_HEADER_LIST_SIZE,HEADER_TABLE_SIZE",
			"https://" + listener.Addr().String() + "/",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	out := output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false)
	transport, err := NewTransport(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.RequestURL.String(), nil)
	if resp, roundErr := transport.RoundTrip(req); roundErr == nil {
		_ = resp.Body.Close()
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
			t.Errorf("SETTINGS order = %v, want %v", got.order, wantOrder)
		}
		for id, want := range map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   8192,
			http2.SettingMaxFrameSize:      32768,
			http2.SettingMaxHeaderListSize: 65536,
		} {
			if value := got.values[id]; value != want {
				t.Errorf("SETTINGS %v = %d, want %d; all = %+v", id, value, want, got.values)
			}
		}
	case err := <-serverErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestHTTP3AdditionalSettingsOnWire(t *testing.T) {
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{localTestCertificate(t)}, NextProtos: []string{"h3"}}
	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observed := make(chan http3SettingsWireCapture, 1)
	serverErr := make(chan error, 1)
	go captureHTTP3Settings(ctx, listener, observed, serverErr)

	cfg, err := config.ParseConfig(
		[]string{
			"--http3",
			"--insecure",
			"--h3-datagrams",
			"--h3-setting=0x40=127",
			"--h3-setting=65=0",
			"https://" + listener.Addr().String() + "/",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	out := output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false)
	transport, err := NewTransport(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.RequestURL.String(), nil)
	if resp, roundErr := transport.RoundTrip(req); roundErr == nil {
		_ = resp.Body.Close()
	}
	select {
	case got := <-observed:
		values := got.values
		if values[6] != 10*1024*1024 {
			t.Errorf("SETTINGS_MAX_FIELD_SECTION_SIZE = %d, want 10 MiB default", values[6])
		}
		for _, id := range []uint64{1, 7, 8} {
			if _, ok := values[id]; ok {
				t.Errorf("HTTP/3 setting %d is present; this client should leave it at the protocol default", id)
			}
		}
		if got := values[64]; got != 127 || values[0x33] != 1 {
			t.Fatalf("HTTP/3 SETTINGS = %+v, want extension 0x40=127 and datagrams 0x33=1", values)
		}
		if got, ok := values[65]; !ok || got != 0 {
			t.Fatalf("HTTP/3 SETTINGS extension 65 = %d, present %t; want explicitly encoded zero", got, ok)
		}
		if want := []uint64{6, 0x33, 64, 65}; fmt.Sprint(got.order) != fmt.Sprint(want) {
			t.Fatalf("HTTP/3 SETTINGS wire order = %v, want %v", got.order, want)
		}
	case err := <-serverErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

type http3SettingsWireCapture struct {
	values map[uint64]uint64
	order  []uint64
}

func captureHTTP3Settings(
	ctx context.Context,
	listener *quic.Listener,
	observed chan<- http3SettingsWireCapture,
	serverErr chan<- error,
) {
	conn, acceptErr := listener.Accept(ctx)
	if acceptErr != nil {
		serverErr <- acceptErr
		return
	}
	defer func() { _ = conn.CloseWithError(0, "done") }()
	stream, streamErr := conn.AcceptUniStream(ctx)
	if streamErr != nil {
		serverErr <- streamErr
		return
	}
	reader := bufio.NewReader(stream)
	streamType, readErr := quicvarint.Read(reader)
	if readErr != nil || streamType != 0 {
		serverErr <- fmt.Errorf("control stream type = %d: %v", streamType, readErr)
		return
	}
	frameType, readErr := quicvarint.Read(reader)
	if readErr != nil || frameType != 4 {
		serverErr <- fmt.Errorf("first control frame = %d: %v", frameType, readErr)
		return
	}
	length, readErr := quicvarint.Read(reader)
	if readErr != nil || length > 8192 {
		serverErr <- fmt.Errorf("SETTINGS length = %d: %v", length, readErr)
		return
	}
	payload := make([]byte, length)
	if _, readErr = io.ReadFull(reader, payload); readErr != nil {
		serverErr <- readErr
		return
	}
	values := map[uint64]uint64{}
	var order []uint64
	settings := bytes.NewReader(payload)
	for settings.Len() > 0 {
		id, idErr := quicvarint.Read(settings)
		value, valueErr := quicvarint.Read(settings)
		if idErr != nil || valueErr != nil {
			serverErr <- fmt.Errorf("parse SETTINGS: %v, %v", idErr, valueErr)
			return
		}
		values[id] = value
		order = append(order, id)
	}
	observed <- http3SettingsWireCapture{values: values, order: order}
}
