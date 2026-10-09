package client

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
)

func TestExactHTTP11FramingOnTransportWire(t *testing.T) {
	for _, tt := range []struct {
		name       string
		header     string
		wantHeader string
		wantBody   string
	}{
		{"content length", "Content-Length: 3", "Content-Length: 3", "abc"},
		{"chunked", "Transfer-Encoding: chunked", "Transfer-Encoding: chunked", "3\r\nabc\r\n0\r\n\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			observed := make(chan error, 1)
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					observed <- acceptErr
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				var headers []string
				for {
					line, readErr := reader.ReadString('\n')
					if readErr != nil {
						observed <- readErr
						return
					}
					if line == "\r\n" {
						break
					}
					headers = append(headers, strings.TrimRight(line, "\r\n"))
				}
				body := make([]byte, len(tt.wantBody))
				if _, readErr := io.ReadFull(reader, body); readErr != nil {
					observed <- readErr
					return
				}
				if !strings.Contains(strings.Join(headers, "\n"), tt.wantHeader) || string(body) != tt.wantBody {
					observed <- fmt.Errorf("wire headers/body = %q / %q, want %q / %q", headers, body, tt.wantHeader, tt.wantBody)
					return
				}
				_, _ = fmt.Fprint(conn, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
				observed <- nil
			}()

			cfg, err := config.ParseConfig(
				[]string{
					"--http1.1",
					"--no-default-headers",
					"--data=abc",
					"-H",
					tt.header,
					"http://" + listener.Addr().String() + "/",
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			out := output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false)
			rt, err := NewTransport(cfg, out)
			if err != nil {
				t.Fatal(err)
			}
			req, err := NewRequest(cfg)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := rt.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if err := <-observed; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReorderRequestHeaderBlockPreservesRequestedOrderCaseAndRepeats(t *testing.T) {
	input := []byte(
		"GET / HTTP/1.1\r\nAccept: */*\r\nX-Repeat: first\r\nUser-Agent: gocurl/test\r\nx-other: value\r\nX-Repeat: second\r\n\r\n",
	)
	order := []string{"x-Other: value", "X-Repeat: second", "X-Repeat: first"}
	want := []byte(
		"GET / HTTP/1.1\r\nx-Other: value\r\nX-Repeat: second\r\nX-Repeat: first\r\nAccept: */*\r\nUser-Agent: gocurl/test\r\n\r\n",
	)
	if got := reorderRequestHeaderBlock(input, order); !bytes.Equal(got, want) {
		t.Fatalf("reordered request =\n%s\nwant =\n%s", got, want)
	}
}

func TestReorderRequestHeaderBlockLeavesUnlistedHeaders(t *testing.T) {
	input := []byte("GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n")
	if got := reorderRequestHeaderBlock(
		input,
		[]string{"B: 2"},
	); !bytes.Equal(
		got,
		[]byte("GET / HTTP/1.1\r\nB: 2\r\nA: 1\r\n\r\n"),
	) {
		t.Fatalf("reordered request = %q", got)
	}
}

func TestOrderedHeaderConnHandlesFragmentedHeadersAndStreamsBody(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := &orderedHeaderConn{Conn: client, headers: []string{"X-B: b", "X-A: a"}}
	want := []byte("POST / HTTP/1.1\r\nX-B: b\r\nX-A: a\r\n\r\n" + strings.Repeat("z", 1024))
	readErr := make(chan error, 1)
	go func() {
		got := make([]byte, len(want))
		_, err := io.ReadFull(server, got)
		if err == nil && !bytes.Equal(got, want) {
			err = fmt.Errorf("wire bytes differ: got %q", got)
		}
		readErr <- err
	}()
	if _, err := conn.Write([]byte("POST / HTTP/1.1\r\nX-A: a\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("X-B: b\r\n\r\n" + strings.Repeat("z", 1024))); err != nil {
		t.Fatal(err)
	}
	if err := <-readErr; err != nil {
		t.Fatal(err)
	}
}

func TestHTTP11TransportWritesCustomHeadersInConfiguredOrder(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	gotHeaders := make(chan []string, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		var headers []string
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				serverErr <- readErr
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			headers = append(headers, line)
		}
		gotHeaders <- headers
		serverErr <- nil
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}()

	url := "http://" + listener.Addr().String() + "/"
	cfg, err := config.ParseConfig(
		[]string{"--http1.1", "--header-file", writeTestHeaderFile(t), "-H", "X-Third: three", url},
	)
	if err != nil {
		t.Fatal(err)
	}
	out := output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false)
	rt, err := NewTransport(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := rt.(interface{ CloseIdleConnections() }); ok {
		defer closer.CloseIdleConnections()
	}
	req, err := NewRequest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	fields := <-gotHeaders
	var custom []string
	for _, field := range fields {
		if strings.HasPrefix(strings.ToLower(field), "x-") {
			custom = append(custom, field)
		}
	}
	want := []string{"X-Second: two", "X-First: one", "X-Third: three"}
	if !bytes.Equal([]byte(strings.Join(custom, "\n")), []byte(strings.Join(want, "\n"))) {
		t.Fatalf("custom wire headers = %#v, want %#v; all headers: %#v", custom, want, fields)
	}
}

func TestHTTP11WireHostOverrideAndEmptyUserAgent(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	gotRequest := make(chan string, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		var request strings.Builder
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				serverErr <- readErr
				return
			}
			request.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		gotRequest <- request.String()
		_, serverErrValue := fmt.Fprint(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
		serverErr <- serverErrValue
	}()

	url := "http://" + listener.Addr().String() + "/probe"
	cfg, err := config.ParseConfig([]string{
		"--http1.1", "-H", "X-First: one", "-H", "Host: virtual.test:8080", "-H", "User-Agent:", url,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewRequest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if req.Host != "virtual.test:8080" || req.URL.Host != listener.Addr().String() {
		t.Fatalf("request Host = %q, dial URL = %q", req.Host, req.URL.Host)
	}
	out := output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false)
	rt, err := NewTransport(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	got := <-gotRequest
	if !strings.HasPrefix(got, "GET /probe HTTP/1.1\r\nX-First: one\r\nHost: virtual.test:8080\r\n") ||
		strings.Contains(strings.ToLower(got), "user-agent:") {
		t.Fatalf("unexpected HTTP/1.1 wire request: %q", got)
	}
}

func TestHTTP11RequestTargetOverridesWireOnly(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	gotLine := make(chan string, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			return
		}
		gotLine <- line
		for {
			line, readErr = reader.ReadString('\n')
			if readErr != nil || line == "\r\n" {
				break
			}
		}
		_, _ = fmt.Fprint(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	}()
	url := "http://" + listener.Addr().String() + "/original"
	cfg, err := config.ParseConfig([]string{"--http1.1", "--request-target=/changed%2Fpath?x=a%2Bb", url})
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewRequest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Path != "/original" {
		t.Fatalf("request URL path = %q, want original routing URL", req.URL.Path)
	}
	out := output.NewOutputWithWriters(&bytes.Buffer{}, &bytes.Buffer{}, false, false)
	rt, err := NewTransport(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := <-gotLine; got != "GET /changed%2Fpath?x=a%2Bb HTTP/1.1\r\n" {
		t.Fatalf("wire request line = %q", got)
	}
}

func writeTestHeaderFile(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/headers.txt"
	if err := os.WriteFile(path, []byte("X-Second: two\nX-First: one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
