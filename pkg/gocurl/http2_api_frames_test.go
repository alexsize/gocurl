package gocurl

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestClientDoHTTP2FrameControlsOnWire(t *testing.T) {
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
	observed := make(chan apiHTTP2FrameCapture, 1)
	serverErr := make(chan error, 1)
	releaseServer := make(chan struct{})
	defer close(releaseServer)
	go serveAPIHTTP2FrameControls(server, observed, serverErr, releaseServer)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	const body = "abcdefgh"
	result, err := NewClient().Do(ctx, Request{
		URL:                  "https://" + listener.Addr().String() + "/",
		Method:               http.MethodPost,
		HTTPVersion:          "2",
		Insecure:             true,
		Body:                 strings.NewReader(body),
		ContentLength:        int64(len(body)),
		HTTP2DataFrameSize:   3,
		HTTP2FramePadding:    8,
		HTTP2HeaderFrameSize: 1024,
		HTTP2PseudoOrder:     []string{"authority", "method", "path", "scheme"},
		HTTP2HeaderOrder:     []string{"x-b", "x-a"},
		Headers: []Header{
			{Name: "X-Large", Value: strings.Repeat("z", 40000)},
			{Name: "X-A", Value: "first"},
			{Name: "X-A", Value: "second"},
			{Name: "X-B", Value: "value"},
		},
		HTTP2Priority: &HTTP2Priority{Dependency: 0, Weight: 16, Exclusive: true},
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
		assertAPIHTTP2DataFrames(t, got, body)
		assertAPIHTTP2HeaderFrames(t, got)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("HTTP/2 test server: %v", err)
	}
}

type apiHTTP2FrameCapture struct {
	body           string
	dataSizes      []int
	dataPadding    []int
	headerPadding  int
	headerFrames   []int
	continuations  int
	pseudoHeaders  []string
	regularHeaders []string
	headerBlock    []byte
	priority       *http2.PriorityFrame
}

func serveAPIHTTP2FrameControls(
	server net.Listener,
	observed chan<- apiHTTP2FrameCapture,
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
	if writeErr := framer.WriteSettings(); writeErr != nil {
		serverErr <- writeErr
		return
	}
	got := apiHTTP2FrameCapture{}
	for {
		frame, readErr := framer.ReadFrame()
		if readErr != nil {
			serverErr <- readErr
			return
		}
		done, frameErr := got.consumeFrame(frame)
		if frameErr != nil {
			serverErr <- frameErr
			return
		}
		if !done {
			continue
		}
		observed <- got
		if writeErr := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: []byte{0x88},
			EndHeaders:    true,
			EndStream:     true,
		}); writeErr != nil {
			serverErr <- writeErr
			return
		}
		serverErr <- nil
		<-releaseServer
		return
	}
}

func (got *apiHTTP2FrameCapture) consumeFrame(frame http2.Frame) (bool, error) {
	switch frame := frame.(type) {
	case *http2.PriorityFrame:
		if got.priority != nil {
			return false, fmt.Errorf("duplicate HTTP/2 PRIORITY frame")
		}
		got.priority = frame
	case *http2.HeadersFrame:
		if frame.StreamID != 1 {
			return false, fmt.Errorf("HEADERS stream ID = %d, want 1", frame.StreamID)
		}
		if frame.Flags.Has(http2.FlagHeadersPadded) {
			got.headerPadding = int(frame.Length) - len(frame.HeaderBlockFragment()) - 1
		}
		got.headerFrames = append(got.headerFrames, int(frame.Length))
		return false, got.appendHeaderBlock(frame.HeaderBlockFragment(), frame.HeadersEnded())
	case *http2.ContinuationFrame:
		got.continuations++
		got.headerFrames = append(got.headerFrames, int(frame.Length))
		return false, got.appendHeaderBlock(frame.HeaderBlockFragment(), frame.HeadersEnded())
	case *http2.DataFrame:
		got.body += string(frame.Data())
		got.dataSizes = append(got.dataSizes, len(frame.Data()))
		padding := 0
		if frame.Flags.Has(http2.FlagDataPadded) {
			padding = int(frame.Length) - len(frame.Data()) - 1
		}
		got.dataPadding = append(got.dataPadding, padding)
		return frame.StreamEnded(), nil
	}
	return false, nil
}

func (got *apiHTTP2FrameCapture) appendHeaderBlock(fragment []byte, ended bool) error {
	got.headerBlock = append(got.headerBlock, fragment...)
	if !ended {
		return nil
	}
	fields, err := hpack.NewDecoder(4096, nil).DecodeFull(got.headerBlock)
	if err != nil {
		return err
	}
	for _, field := range fields {
		if strings.HasPrefix(field.Name, ":") {
			got.pseudoHeaders = append(got.pseudoHeaders, field.Name)
		} else {
			got.regularHeaders = append(got.regularHeaders, field.Name)
		}
	}
	return nil
}

func assertAPIHTTP2DataFrames(t *testing.T, got apiHTTP2FrameCapture, body string) {
	t.Helper()
	if got.body != body {
		t.Errorf("captured request body = %q, want %q", got.body, body)
	}
	if len(got.dataSizes) != 3 {
		t.Errorf("DATA frame sizes = %v, want three frames capped at 3 bytes", got.dataSizes)
	}
	for i, size := range got.dataSizes {
		if size > 3 {
			t.Errorf("DATA frame %d payload = %d bytes, want <= 3", i, size)
		}
	}
	for i, padding := range got.dataPadding {
		if padding != 8 {
			t.Errorf("DATA frame %d padding = %d, want 8", i, padding)
		}
	}
}

func assertAPIHTTP2HeaderFrames(t *testing.T, got apiHTTP2FrameCapture) {
	t.Helper()
	if got.headerPadding != 8 {
		t.Errorf("HEADERS padding = %d, want 8", got.headerPadding)
	}
	if got.continuations == 0 || len(got.headerFrames) < 2 {
		t.Errorf(
			"HEADERS frame sequence = %v with %d CONTINUATION frames, want fragmentation",
			got.headerFrames,
			got.continuations,
		)
	}
	for i, size := range got.headerFrames {
		if size > 1024 {
			t.Errorf("header frame %d payload = %d, want <= 1024", i, size)
		}
	}
	wantPseudo := []string{":authority", ":method", ":path", ":scheme"}
	if fmt.Sprint(got.pseudoHeaders) != fmt.Sprint(wantPseudo) {
		t.Errorf("pseudo-header order = %v, want %v", got.pseudoHeaders, wantPseudo)
	}
	if len(got.regularHeaders) < 3 ||
		fmt.Sprint(got.regularHeaders[:3]) != fmt.Sprint([]string{"x-b", "x-a", "x-a"}) {
		t.Errorf("regular header order = %v, want x-b, x-a, x-a first", got.regularHeaders)
	}
	if got.priority == nil || got.priority.StreamID != 1 ||
		got.priority.StreamDep != 0 || got.priority.Weight != 15 ||
		!got.priority.Exclusive {
		t.Errorf("PRIORITY frame = %+v, want stream 1 dependency 0 wire weight 15 exclusive", got.priority)
	}
}
