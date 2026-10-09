package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"golang.org/x/net/http2"
)

func TestHTTP2DataFrameSizeOnWire(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := tls.NewListener(
		listener,
		&tls.Config{Certificates: []tls.Certificate{localTestCertificate(t)}, NextProtos: []string{"h2"}},
	)
	observed := make(chan dataFrameWireCapture, 1)
	serverErr := make(chan error, 1)
	go captureHTTP2DataFrames(server, observed, serverErr)

	cfg, err := config.ParseConfig(
		[]string{
			"--http2",
			"--insecure",
			"--h2-data-frame-size=7",
			"--h2-frame-padding=5",
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
	want := strings.Repeat("payload", 15)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, cfg.RequestURL.String(), strings.NewReader(want))
	if resp, roundErr := transport.RoundTrip(req); roundErr == nil {
		_ = resp.Body.Close()
	}
	select {
	case got := <-observed:
		if got.body != want || len(got.sizes) < 2 {
			t.Fatalf("captured body length = %d, DATA sizes = %v", len(got.body), got.sizes)
		}
		for _, size := range got.sizes {
			if size > 7 {
				t.Fatalf("DATA frame size = %d, want <= 7; all = %v", size, got.sizes)
			}
		}
		for i, padding := range got.padding {
			if padding != 5 || !got.paddedFlag[i] {
				t.Fatalf(
					"DATA padding = %v, flags = %v; want 5-byte padding on each frame",
					got.padding,
					got.paddedFlag,
				)
			}
		}
	case err := <-serverErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestHTTP2PriorityFrameOnWire(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := tls.NewListener(
		listener,
		&tls.Config{Certificates: []tls.Certificate{localTestCertificate(t)}, NextProtos: []string{"h2"}},
	)
	observed := make(chan priorityFrameWireCapture, 1)
	serverErr := make(chan error, 1)
	releaseServer := make(chan struct{})
	defer close(releaseServer)
	go captureHTTP2PriorityFrames(server, observed, serverErr, releaseServer)

	cfg, err := config.ParseConfig(
		[]string{"--http2", "--insecure", "--h2-priority=0:16:true", "https://" + listener.Addr().String() + "/"},
	)
	if err != nil {
		t.Fatal(err)
	}
	out := output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false)
	transport, err := NewTransport(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if conn := transport.Conn(); conn != nil {
			_ = conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.RequestURL.String(), nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("HTTP/2 request did not receive a response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || resp.ProtoMajor != 2 {
		t.Fatalf("HTTP/2 response = %s (%s)", resp.Status, resp.Proto)
	}
	select {
	case got := <-observed:
		if got.streamID != 1 || got.param.StreamDep != 0 || got.param.Weight != 15 || !got.param.Exclusive {
			t.Fatalf(
				"captured PRIORITY = stream %d, %+v; want stream 1, dependency 0, weight 15 (wire encoding of 16), exclusive",
				got.streamID,
				got.param,
			)
		}
	case err := <-serverErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

type dataFrameWireCapture struct {
	body       string
	sizes      []int
	padding    []int
	paddedFlag []bool
}

func captureHTTP2DataFrames(server net.Listener, observed chan<- dataFrameWireCapture, serverErr chan<- error) {
	conn, acceptErr := server.Accept()
	if acceptErr != nil {
		serverErr <- acceptErr
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	preface := make([]byte, len(http2.ClientPreface))
	if _, readErr := io.ReadFull(conn, preface); readErr != nil || string(preface) != http2.ClientPreface {
		serverErr <- fmt.Errorf("HTTP/2 preface = %q: %v", preface, readErr)
		return
	}
	framer := http2.NewFramer(conn, conn)
	if writeErr := framer.WriteSettings(); writeErr != nil {
		serverErr <- writeErr
		return
	}
	var got dataFrameWireCapture
	for {
		frame, readErr := framer.ReadFrame()
		if readErr != nil {
			serverErr <- readErr
			return
		}
		data, ok := frame.(*http2.DataFrame)
		if !ok {
			continue
		}
		got.body += string(data.Data())
		got.sizes = append(got.sizes, len(data.Data()))
		got.paddedFlag = append(got.paddedFlag, data.Flags.Has(http2.FlagDataPadded))
		if data.Flags.Has(http2.FlagDataPadded) {
			got.padding = append(got.padding, int(data.Length)-len(data.Data())-1)
		} else {
			got.padding = append(got.padding, 0)
		}
		if data.StreamEnded() {
			observed <- got
			return
		}
	}
}

type priorityFrameWireCapture struct {
	streamID uint32
	param    http2.PriorityParam
}

func captureHTTP2PriorityFrames(
	server net.Listener,
	observed chan<- priorityFrameWireCapture,
	serverErr chan<- error,
	releaseServer <-chan struct{},
) {
	conn, acceptErr := server.Accept()
	if acceptErr != nil {
		serverErr <- acceptErr
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	preface := make([]byte, len(http2.ClientPreface))
	if _, readErr := io.ReadFull(conn, preface); readErr != nil || string(preface) != http2.ClientPreface {
		serverErr <- fmt.Errorf("HTTP/2 preface = %q: %v", preface, readErr)
		return
	}
	framer := http2.NewFramer(conn, conn)
	if writeErr := framer.WriteSettings(); writeErr != nil {
		serverErr <- writeErr
		return
	}
	var gotPriority *priorityFrameWireCapture
	for {
		frame, readErr := framer.ReadFrame()
		if readErr != nil {
			serverErr <- readErr
			return
		}
		switch f := frame.(type) {
		case *http2.PriorityFrame:
			if gotPriority != nil {
				serverErr <- fmt.Errorf("duplicate HTTP/2 PRIORITY frame")
				return
			}
			gotPriority = &priorityFrameWireCapture{streamID: f.StreamID, param: f.PriorityParam}
		case *http2.HeadersFrame:
			if gotPriority == nil || gotPriority.streamID != f.StreamID || !f.HeadersEnded() {
				serverErr <- fmt.Errorf("request HEADERS arrived without complete preceding PRIORITY")
				return
			}
			if writeErr := framer.WriteHeaders(
				http2.HeadersFrameParam{
					StreamID:      f.StreamID,
					BlockFragment: []byte{0x89},
					EndHeaders:    true,
					EndStream:     true,
				},
			); writeErr != nil {
				serverErr <- writeErr
				return
			}
			observed <- *gotPriority
			<-releaseServer
			return
		}
	}
}
