package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	utls "github.com/refraction-networking/utls"
)

func TestSOCKS5DialCapturesTargetClientHello(t *testing.T) {
	target := newTLSTestTarget(t)
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SOCKS5 proxy: %v", err)
	}
	t.Cleanup(func() { _ = proxyListener.Close() })
	go serveSOCKS5ConnectProxy(proxyListener)

	proxyURL := &url.URL{Scheme: "socks5", Host: proxyListener.Addr().String()}
	dialer, err := createSOCKS5ProxyDialer(proxyURL, 3)
	if err != nil {
		t.Fatalf("createSOCKS5ProxyDialer() error = %v", err)
	}
	conn, err := dialer.Dial("tcp", target.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SOCKS5 Dial() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	tlsConn, capture, err := utlsengine.Handshake(ctx, conn, &utls.Config{
		ServerName:         "example.test",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}, utlsengine.Profile{Preset: "chrome-120", ALPN: []string{"http/1.1"}})
	if err != nil {
		t.Fatalf("target TLS handshake through SOCKS5: %v", err)
	}
	t.Cleanup(func() { _ = tlsConn.Close() })

	got, err := capture.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint() through SOCKS5: %v", err)
	}
	hello, err := capture.ClientHelloBytes()
	if err != nil {
		t.Fatalf("ClientHelloBytes() through SOCKS5: %v", err)
	}
	if len(got.JA3) != 32 || len(got.JA4) == 0 || len(hello) == 0 {
		t.Fatalf("SOCKS5 tunnel did not produce wire-derived fingerprints: %+v", got)
	}
	if len(got.ALPN) != 1 || got.ALPN[0] != "http/1.1" {
		t.Fatalf("SOCKS5 ClientHello ALPN = %v, want [http/1.1]", got.ALPN)
	}
}

func TestSOCKS5AndSOCKS5HUseDifferentTargetDNSModes(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		wantDomain string
	}{
		{name: "socks5 resolves locally", target: "localhost:443"},
		{name: "socks5h resolves remotely", target: "target.invalid:443", wantDomain: "target.invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen for SOCKS5 proxy: %v", err)
			}
			t.Cleanup(func() { _ = listener.Close() })

			requests := make(chan socksDNSWireRequest, 1)
			serverErr := make(chan error, 1)
			go captureSOCKS5DNSRequest(listener, requests, serverErr)

			scheme := "socks5"
			if tt.wantDomain != "" {
				scheme = "socks5h"
			}
			proxyURL := &url.URL{Scheme: scheme, Host: listener.Addr().String()}
			dialer, err := createSOCKS5ProxyDialer(proxyURL, 3)
			if err != nil {
				t.Fatalf("createSOCKS5ProxyDialer() error = %v", err)
			}
			conn, err := dialer.Dial("tcp", tt.target)
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			_ = conn.Close()

			select {
			case got := <-requests:
				if tt.wantDomain == "" {
					if got.addressType == 3 || net.ParseIP(got.host) == nil {
						t.Fatalf(
							"SOCKS5 request = type %d host %q; want locally resolved IP",
							got.addressType,
							got.host,
						)
					}
				} else if got.addressType != 3 || got.host != tt.wantDomain {
					t.Fatalf(
						"SOCKS5H request = type %d host %q; want domain %q",
						got.addressType,
						got.host,
						tt.wantDomain,
					)
				}
			case err := <-serverErr:
				t.Fatalf("read SOCKS5 request: %v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for SOCKS5 request")
			}
		})
	}
}

func TestSOCKS5AndSOCKS5HCarryHTTP11TargetSessions(t *testing.T) {
	for _, tt := range []struct {
		name       string
		scheme     string
		targetHost string
		wantATYP   byte
	}{
		{name: "socks5 local DNS", scheme: "socks5", targetHost: "127.0.0.1", wantATYP: 1},
		{name: "socks5h remote DNS", scheme: "socks5h", targetHost: "hidden-target.test", wantATYP: 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			targetRequests := make(chan string, 1)
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetRequests <- r.Proto + " " + r.URL.Path
				_, _ = io.WriteString(w, "socks-http11-ok")
			}))
			defer target.Close()
			_, port, err := net.SplitHostPort(target.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			targetAddress := net.JoinHostPort(tt.targetHost, port)

			proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen for SOCKS5 proxy: %v", err)
			}
			defer func() { _ = proxyListener.Close() }()
			observedATYP := make(chan byte, 1)
			proxyErrors := make(chan error, 1)
			go serveSOCKS5HTTP11Target(proxyListener, target.Listener.Addr().String(), observedATYP, proxyErrors)

			proxyURL := &url.URL{Scheme: tt.scheme, Host: proxyListener.Addr().String()}
			dialer, err := createSOCKS5ProxyDialer(proxyURL, 5)
			if err != nil {
				t.Fatalf("create SOCKS5 dialer: %v", err)
			}
			conn, err := dialer.Dial("tcp", targetAddress)
			if err != nil {
				t.Fatalf("SOCKS5 CONNECT: %v", err)
			}
			defer func() { _ = conn.Close() }()
			targetTLS := tls.Client(conn, &tls.Config{
				ServerName:         tt.targetHost,
				InsecureSkipVerify: true,
				NextProtos:         []string{"http/1.1"},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err = targetTLS.HandshakeContext(ctx); err != nil {
				t.Fatalf("target TLS handshake through %s: %v", tt.scheme, err)
			}
			if _, err = io.WriteString(
				targetTLS,
				"GET /through-socks HTTP/1.1\r\nHost: "+tt.targetHost+"\r\nConnection: close\r\n\r\n",
			); err != nil {
				t.Fatalf("write HTTP/1.1 request: %v", err)
			}
			response, err := http.ReadResponse(bufio.NewReader(targetTLS), nil)
			if err != nil {
				t.Fatalf("read target response: %v", err)
			}
			defer func() { _ = response.Body.Close() }()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read target body: %v", err)
			}
			if response.Proto != "HTTP/1.1" || response.StatusCode != http.StatusOK ||
				string(body) != "socks-http11-ok" {
				t.Fatalf("response = %s %d body %q", response.Proto, response.StatusCode, body)
			}
			select {
			case got := <-observedATYP:
				if got != tt.wantATYP {
					t.Fatalf("SOCKS5 target ATYP = %d, want %d", got, tt.wantATYP)
				}
			case proxyErr := <-proxyErrors:
				t.Fatalf("SOCKS5 proxy request failed: %v", proxyErr)
			case <-ctx.Done():
				t.Fatal("timed out waiting for SOCKS5 request details")
			}
			select {
			case got := <-targetRequests:
				if got != "HTTP/1.1 /through-socks" {
					t.Fatalf("target request = %q", got)
				}
			case <-ctx.Done():
				t.Fatal("timed out waiting for target request")
			}
		})
	}
}

func newTLSTestTarget(t *testing.T) *testTLSTarget {
	t.Helper()
	server := httptest.NewTLSServer(nil)
	t.Cleanup(server.Close)
	return &testTLSTarget{Listener: server.Listener}
}

type testTLSTarget struct {
	Listener net.Listener
}

func serveSOCKS5ConnectProxy(listener net.Listener) {
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		go handleSOCKS5Connect(client)
	}
}

func handleSOCKS5Connect(client net.Conn) {
	defer func() { _ = client.Close() }()
	reader := bufio.NewReader(client)
	version, err := reader.ReadByte()
	if err != nil || version != 5 {
		return
	}
	methodsCount, err := reader.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, int(methodsCount))
	if _, err = io.ReadFull(reader, methods); err != nil {
		return
	}
	if _, err = client.Write([]byte{5, 0}); err != nil {
		return
	}

	request := make([]byte, 4)
	if _, err = io.ReadFull(reader, request); err != nil || request[0] != 5 || request[1] != 1 {
		return
	}
	var host string
	switch request[3] {
	case 1:
		address := make([]byte, net.IPv4len)
		if _, err = io.ReadFull(reader, address); err != nil {
			return
		}
		host = net.IP(address).String()
	case 3:
		length, readErr := reader.ReadByte()
		if readErr != nil {
			return
		}
		address := make([]byte, int(length))
		if _, err = io.ReadFull(reader, address); err != nil {
			return
		}
		host = string(address)
	case 4:
		address := make([]byte, net.IPv6len)
		if _, err = io.ReadFull(reader, address); err != nil {
			return
		}
		host = net.IP(address).String()
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(reader, portBytes); err != nil {
		return
	}
	// #nosec G704 -- Local proxy fixture deliberately dials the loopback target supplied by its test client.
	target, err := net.DialTimeout(
		"tcp",
		net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(portBytes))),
		3*time.Second,
	)
	if err != nil {
		_, _ = client.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() { _ = target.Close() }()
	if _, err = client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go func() { _, _ = io.Copy(target, reader) }()
	_, _ = io.Copy(client, target)
}

type socksDNSWireRequest struct {
	addressType byte
	host        string
}

func captureSOCKS5DNSRequest(listener net.Listener, requests chan<- socksDNSWireRequest, serverErr chan<- error) {
	conn, acceptErr := listener.Accept()
	if acceptErr != nil {
		serverErr <- acceptErr
		return
	}
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	greeting := make([]byte, 2)
	if _, acceptErr = io.ReadFull(reader, greeting); acceptErr != nil {
		serverErr <- acceptErr
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, acceptErr = io.ReadFull(reader, methods); acceptErr != nil {
		serverErr <- acceptErr
		return
	}
	if _, acceptErr = conn.Write([]byte{5, 0}); acceptErr != nil {
		serverErr <- acceptErr
		return
	}
	header := make([]byte, 4)
	if _, acceptErr = io.ReadFull(reader, header); acceptErr != nil {
		serverErr <- acceptErr
		return
	}
	var host string
	switch header[3] {
	case 1:
		ip := make([]byte, net.IPv4len)
		if _, acceptErr = io.ReadFull(reader, ip); acceptErr == nil {
			host = net.IP(ip).String()
		}
	case 3:
		var length byte
		length, acceptErr = reader.ReadByte()
		if acceptErr == nil {
			name := make([]byte, int(length))
			_, acceptErr = io.ReadFull(reader, name)
			host = string(name)
		}
	case 4:
		ip := make([]byte, net.IPv6len)
		if _, acceptErr = io.ReadFull(reader, ip); acceptErr == nil {
			host = net.IP(ip).String()
		}
	default:
		acceptErr = fmt.Errorf("unexpected SOCKS5 address type %d", header[3])
	}
	if acceptErr == nil {
		port := make([]byte, 2)
		_, acceptErr = io.ReadFull(reader, port)
	}
	if acceptErr == nil {
		requests <- socksDNSWireRequest{addressType: header[3], host: host}
		_, acceptErr = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	}
	if acceptErr != nil {
		serverErr <- acceptErr
	}
}

func serveSOCKS5HTTP11Target(
	proxyListener net.Listener,
	targetAddress string,
	observedATYP chan<- byte,
	proxyErrors chan<- error,
) {
	client, acceptErr := proxyListener.Accept()
	if acceptErr != nil {
		proxyErrors <- acceptErr
		return
	}
	defer func() { _ = client.Close() }()
	reader := bufio.NewReader(client)
	greeting := make([]byte, 2)
	if _, acceptErr = io.ReadFull(reader, greeting); acceptErr != nil {
		proxyErrors <- acceptErr
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, acceptErr = io.ReadFull(reader, methods); acceptErr != nil {
		proxyErrors <- acceptErr
		return
	}
	if _, acceptErr = client.Write([]byte{5, 0}); acceptErr != nil {
		proxyErrors <- acceptErr
		return
	}
	request := make([]byte, 4)
	if _, acceptErr = io.ReadFull(reader, request); acceptErr != nil || request[1] != 1 {
		if acceptErr == nil {
			acceptErr = fmt.Errorf("SOCKS5 command = %d, want CONNECT", request[1])
		}
		proxyErrors <- acceptErr
		return
	}
	var addressLength int
	switch request[3] {
	case 1:
		addressLength = net.IPv4len
	case 3:
		length, readErr := reader.ReadByte()
		if readErr != nil {
			proxyErrors <- readErr
			return
		}
		addressLength = int(length)
	case 4:
		addressLength = net.IPv6len
	default:
		proxyErrors <- fmt.Errorf("unexpected SOCKS5 ATYP %d", request[3])
		return
	}
	address := make([]byte, addressLength+2)
	if _, acceptErr = io.ReadFull(reader, address); acceptErr != nil {
		proxyErrors <- acceptErr
		return
	}
	observedATYP <- request[3]
	upstream, dialErr := net.Dial("tcp", targetAddress)
	if dialErr != nil {
		proxyErrors <- dialErr
		return
	}
	defer func() { _ = upstream.Close() }()
	if _, acceptErr = client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); acceptErr != nil {
		proxyErrors <- acceptErr
		return
	}
	go func() { _, _ = io.Copy(upstream, reader) }()
	_, _ = io.Copy(client, upstream)
}
