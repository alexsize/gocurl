package client

import (
	"bytes"
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

	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestHTTP2PseudoHeaderOrderOnWire(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := tls.NewListener(
		listener,
		&tls.Config{Certificates: []tls.Certificate{localTestCertificate(t)}, NextProtos: []string{"h2"}},
	)
	observed := make(chan pseudoHeaderWireCapture, 1)
	serverErr := make(chan error, 1)
	go captureHTTP2PseudoHeaders(server, observed, serverErr)

	cfg, err := config.ParseConfig(
		[]string{
			"--http2",
			"--insecure",
			"--h2-pseudo-order=authority,method,path,scheme",
			"--h2-header-order=x-b,x-a",
			"--h2-header-frame-size=1024",
			"--h2-frame-padding=16",
			"https://" + listener.Addr().String() + "/wire",
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
	req.Header.Set("X-Large", strings.Repeat("z", 40000))
	req.Header.Add("X-A", "first")
	req.Header.Add("X-A", "second")
	req.Header.Set("X-B", "value")
	if resp, roundErr := transport.RoundTrip(req); roundErr == nil {
		_ = resp.Body.Close()
	}
	select {
	case got := <-observed:
		want := []string{":authority", ":method", ":path", ":scheme"}
		if fmt.Sprint(got.names) != fmt.Sprint(want) || got.continuations == 0 || got.maxFragment > 1024 ||
			!got.headerPadded ||
			got.headerPadding != 16 {
			t.Fatalf("pseudo-header pseudoHeaderWireCapture = %+v, want %v and CONTINUATION", got, want)
		}
		if len(got.regular) < 3 || fmt.Sprint(got.regular[:3]) != fmt.Sprint([]string{"x-b", "x-a", "x-a"}) {
			t.Fatalf("regular header order = %v", got.regular)
		}
	case err := <-serverErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestHTTP2PseudoHeaderOrderGetsResponse(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, bodyErr := io.ReadAll(r.Body)
		if bodyErr != nil || string(body) != "payload" || r.Method != http.MethodPost ||
			r.URL.Path != "/wire" || r.Header.Get("X-Probe") != "yes" ||
			r.Header.Get("X-Large") != strings.Repeat("z", 40000) {
			t.Errorf("request = %s %s, headers = %v", r.Method, r.URL, r.Header)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	cfg, err := config.ParseConfig(
		[]string{
			"--http2",
			"--insecure",
			"--h2-pseudo-order=authority,method,path,scheme",
			"--h2-header-order=x-probe,x-large",
			"--h2-header-frame-size=1024",
			"--h2-frame-padding=7",
			"--h2-settings-order=MAX_FRAME_SIZE,ENABLE_PUSH",
			"--h2-data-frame-size=3",
			"-H",
			"X-Probe: yes",
			server.URL + "/wire",
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
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, cfg.RequestURL.String(), strings.NewReader("payload"))
	req.Header.Set("X-Probe", "yes")
	req.Header.Set("X-Large", strings.Repeat("z", 40000))
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || resp.ProtoMajor != 2 {
		t.Fatalf("response = %s, %s", resp.Status, resp.Proto)
	}
}

func TestHTTP2HeaderFrameSizeWithoutHeaderRewriteGetsResponse(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Header.Get("X-Large") != strings.Repeat("z", 40000) {
			t.Errorf("request protocol = %s, large header length = %d", r.Proto, len(r.Header.Get("X-Large")))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	cfg, err := config.ParseConfig([]string{"--http2", "--insecure", "--h2-header-frame-size=1024", server.URL})
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.RequestURL.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Large", strings.Repeat("z", 40000))
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || resp.ProtoMajor != 2 {
		t.Fatalf("response = %s, %s", resp.Status, resp.Proto)
	}
}

type pseudoHeaderWireCapture struct {
	names         []string
	regular       []string
	continuations int
	maxFragment   int
	headerPadded  bool
	headerPadding int
}

func captureHTTP2PseudoHeaders(server net.Listener, observed chan<- pseudoHeaderWireCapture, serverErr chan<- error) {
	conn, acceptErr := server.Accept()
	if acceptErr != nil {
		serverErr <- acceptErr
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	preface := make([]byte, len(http2.ClientPreface))
	if _, readErr := io.ReadFull(conn, preface); readErr != nil {
		serverErr <- readErr
		return
	}
	framer := http2.NewFramer(conn, conn)
	var block []byte
	continuations := 0
	maxFragment := 0
	headerPadded := false
	headerPadding := 0
	for {
		frame, readErr := framer.ReadFrame()
		if readErr != nil {
			serverErr <- readErr
			return
		}
		switch f := frame.(type) {
		case *http2.HeadersFrame:
			block = append(block, f.HeaderBlockFragment()...)
			maxFragment = max(maxFragment, len(f.HeaderBlockFragment()))
			if f.Flags.Has(http2.FlagHeadersPadded) {
				headerPadding = int(f.Length) - len(f.HeaderBlockFragment()) - 1
				headerPadded = true
			}
			if !f.HeadersEnded() {
				continue
			}
		case *http2.ContinuationFrame:
			continuations++
			block = append(block, f.HeaderBlockFragment()...)
			maxFragment = max(maxFragment, len(f.HeaderBlockFragment()))
			if !f.HeadersEnded() {
				continue
			}
		default:
			continue
		}
		fields, decodeErr := hpack.NewDecoder(4096, nil).DecodeFull(block)
		if decodeErr != nil {
			serverErr <- decodeErr
			return
		}
		var names []string
		var regular []string
		for _, field := range fields {
			if len(field.Name) > 0 && field.Name[0] == ':' {
				names = append(names, field.Name)
			} else {
				regular = append(regular, field.Name)
			}
		}
		observed <- pseudoHeaderWireCapture{names: names, regular: regular, continuations: continuations, maxFragment: maxFragment, headerPadded: headerPadded, headerPadding: headerPadding}
		return
	}
}
