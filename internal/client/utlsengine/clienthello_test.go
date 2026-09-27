package utlsengine

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestHandshakeCapturesPresetClientHello(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	t.Cleanup(server.Close)

	tlsConn, capture := runHandshake(t, server.Listener.Addr().String(), Profile{
		Preset: "chrome-120",
		ALPN:   []string{"http/1.1"},
	})
	t.Cleanup(func() { _ = tlsConn.Close() })

	hello, err := capture.ClientHelloBytes()
	if err != nil {
		t.Fatalf("ClientHelloBytes() error = %v", err)
	}
	extensions, alpn := parseClientHelloForTest(t, hello)
	if len(extensions) == 0 {
		t.Fatal("ClientHello has no extensions")
	}
	if len(alpn) != 1 || alpn[0] != "http/1.1" {
		t.Fatalf("captured ALPN = %v, want [http/1.1]", alpn)
	}
	if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("negotiated ALPN = %q, want http/1.1", got)
	}
	if _, err = tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")); err != nil {
		t.Fatalf("write post-handshake request: %v", err)
	}
	afterRequest, err := capture.ClientHelloBytes()
	if err != nil {
		t.Fatalf("ClientHelloBytes() after request: %v", err)
	}
	if string(afterRequest) != string(hello) {
		t.Fatal("wire capture changed after ClientHello was completed")
	}
	fingerprint, err := capture.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if len(fingerprint.JA3) != 32 || !strings.HasPrefix(fingerprint.JA4, "t13") {
		t.Fatalf("wire-derived fingerprints are incomplete: %+v", fingerprint)
	}
}

func TestHandshakeAppliesCustomExtensionOrder(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	t.Cleanup(server.Close)

	id, err := presetID("chrome-120")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		t.Fatal(err)
	}
	order := make([]uint16, 0, len(spec.Extensions))
	for _, extension := range spec.Extensions {
		if padding, ok := extension.(*utls.UtlsPaddingExtension); ok && !padding.WillPad {
			continue
		}
		extensionType, typeErr := extensionID(extension)
		if typeErr != nil {
			t.Fatalf("extensionID() error = %v", typeErr)
		}
		order = append(order, extensionType)
	}
	for left, right := 0, len(order)-1; left < right; left, right = left+1, right-1 {
		order[left], order[right] = order[right], order[left]
	}

	_, capture := runHandshake(t, server.Listener.Addr().String(), Profile{
		Preset:         "chrome-120",
		ExtensionOrder: order,
		ALPN:           []string{"http/1.1"},
	})
	hello, err := capture.ClientHelloBytes()
	if err != nil {
		t.Fatalf("ClientHelloBytes() error = %v", err)
	}
	got, _ := parseClientHelloForTest(t, hello)
	if len(got) != len(order) {
		t.Fatalf("captured %d extensions %v, want %d in order %v", len(got), got, len(order), order)
	}
	for i, want := range order {
		if got[i] != normalizeGREASE(want) {
			t.Fatalf("extension[%d] = 0x%04x, want 0x%04x", i, got[i], normalizeGREASE(want))
		}
	}
}

func TestHandshakeCapturesTargetClientHelloThroughHTTPConnect(t *testing.T) {
	target := httptest.NewTLSServer(nil)
	t.Cleanup(target.Close)
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxyListener.Close() })
	go serveConnectProxy(proxyListener, target.Listener.Addr().String())

	conn, err := net.DialTimeout("tcp", proxyListener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	connectRequest := "CONNECT " + target.Listener.Addr().String() + " HTTP/1.1\r\nHost: " +
		target.Listener.Addr().String() + "\r\n\r\n"
	if _, err = io.WriteString(conn, connectRequest); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", response.StatusCode)
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	_, capture, err := Handshake(ctx, &bufferedConn{Conn: conn, reader: reader}, &utls.Config{
		ServerName:         "example.test",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}, Profile{Preset: "chrome-120", ALPN: []string{"http/1.1"}})
	if err != nil {
		t.Fatalf("target TLS handshake through CONNECT: %v", err)
	}
	hello, err := capture.ClientHelloBytes()
	if err != nil {
		t.Fatalf("ClientHelloBytes() after CONNECT: %v", err)
	}
	if types, _ := parseClientHelloForTest(t, hello); len(types) == 0 {
		t.Fatal("CONNECT tunnel captured no target ClientHello extensions")
	}
	fingerprint, err := capture.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint() through CONNECT: %v", err)
	}
	if len(fingerprint.JA3) != 32 || !strings.HasPrefix(fingerprint.JA4, "t13") {
		t.Fatalf("CONNECT wire-derived fingerprints are incomplete: %+v", fingerprint)
	}
}

func TestExtractClientHelloAcrossTLSRecords(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	t.Cleanup(server.Close)
	tlsConn, capture := runHandshake(t, server.Listener.Addr().String(), Profile{Preset: "chrome-120"})
	t.Cleanup(func() { _ = tlsConn.Close() })
	hello, err := capture.ClientHelloBytes()
	if err != nil {
		t.Fatalf("ClientHelloBytes() error = %v", err)
	}
	if len(hello) < 16 {
		t.Fatalf("captured ClientHello unexpectedly short: %d", len(hello))
	}

	split := len(hello) / 2
	fragments := [][]byte{hello[:split], hello[split:]}
	var records []byte
	for _, fragment := range fragments {
		record := []byte{22, 3, 1, byte(len(fragment) >> 8), byte(len(fragment))}
		records = append(records, record...)
		records = append(records, fragment...)
	}
	got, err := extractClientHello(records)
	if err != nil {
		t.Fatalf("extractClientHello() fragmented records error = %v", err)
	}
	if string(got) != string(hello) {
		t.Fatal("reassembled ClientHello differs from captured handshake bytes")
	}
}

func TestApplyProfileRejectsIncompleteOrDuplicateExtensionOrder(t *testing.T) {
	id, err := presetID("chrome")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		t.Fatal(err)
	}

	if err = applyProfile(&spec, "example.test", Profile{Preset: "chrome", ExtensionOrder: []uint16{0}}); err == nil {
		t.Fatal("applyProfile() accepted an incomplete extension order")
	}

	spec, err = utls.UTLSIdToSpec(id)
	if err != nil {
		t.Fatal(err)
	}
	first, err := extensionID(spec.Extensions[0])
	if err != nil {
		t.Fatal(err)
	}
	order := make([]uint16, len(spec.Extensions))
	for i, extension := range spec.Extensions {
		order[i], err = extensionID(extension)
		if err != nil {
			t.Fatal(err)
		}
	}
	order[len(order)-1] = first
	if err = applyProfile(&spec, "example.test", Profile{Preset: "chrome", ExtensionOrder: order}); err == nil {
		t.Fatal("applyProfile() accepted a duplicate extension ID")
	}
}

func runHandshake(t *testing.T, address string, profile Profile) (*utls.UConn, *CaptureConn) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("net.DialTimeout() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	tlsConn, capture, err := Handshake(ctx, conn, &utls.Config{
		ServerName:         "example.test",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}, profile)
	if err != nil {
		t.Fatalf("Handshake() error = %v", err)
	}

	return tlsConn, capture
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (n int, err error) {
	return c.reader.Read(p)
}

func serveConnectProxy(listener net.Listener, targetAddress string) {
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return
		}
		go handleConnect(clientConn, targetAddress)
	}
}

func handleConnect(clientConn net.Conn, targetAddress string) {
	defer func() { _ = clientConn.Close() }()
	reader := bufio.NewReader(clientConn)
	request, err := http.ReadRequest(reader)
	if err != nil || request.Method != http.MethodConnect {
		return
	}
	targetConn, err := net.DialTimeout("tcp", targetAddress, time.Second)
	if err != nil {
		_, _ = io.WriteString(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer func() { _ = targetConn.Close() }()
	if _, err = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	go func() { _, _ = io.Copy(targetConn, reader) }()
	_, _ = io.Copy(clientConn, targetConn)
}

func parseClientHelloForTest(t *testing.T, hello []byte) (extensionIDs []uint16, alpn []string) {
	t.Helper()
	if len(hello) < 4+2+32+1 || hello[0] != 1 {
		t.Fatalf("invalid ClientHello handshake message")
	}
	position := 4 + 2 + 32
	sessionIDLength := int(hello[position])
	position++
	position += sessionIDLength
	if position+2 > len(hello) {
		t.Fatal("truncated ClientHello cipher suites length")
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(hello[position : position+2]))
	position += 2 + cipherSuitesLength
	if position+1 > len(hello) {
		t.Fatal("truncated ClientHello compression methods length")
	}
	compressionMethodsLength := int(hello[position])
	position += 1 + compressionMethodsLength
	if position+2 > len(hello) {
		t.Fatal("truncated ClientHello extensions length")
	}
	extensionsLength := int(binary.BigEndian.Uint16(hello[position : position+2]))
	position += 2
	end := position + extensionsLength
	if end > len(hello) {
		t.Fatal("truncated ClientHello extensions")
	}
	for position < end {
		if position+4 > end {
			t.Fatal("truncated ClientHello extension header")
		}
		id := normalizeGREASE(binary.BigEndian.Uint16(hello[position : position+2]))
		length := int(binary.BigEndian.Uint16(hello[position+2 : position+4]))
		position += 4
		if position+length > end {
			t.Fatal("truncated ClientHello extension body")
		}
		data := hello[position : position+length]
		position += length
		extensionIDs = append(extensionIDs, id)
		if id == 16 {
			alpn = parseALPNForTest(t, data)
		}
	}

	return extensionIDs, alpn
}

func parseALPNForTest(t *testing.T, data []byte) (protocols []string) {
	t.Helper()
	if len(data) < 2 || int(binary.BigEndian.Uint16(data[:2])) != len(data)-2 {
		t.Fatal("invalid ALPN extension length")
	}
	data = data[2:]
	for len(data) > 0 {
		length := int(data[0])
		data = data[1:]
		if length == 0 || length > len(data) {
			t.Fatal("invalid ALPN protocol length")
		}
		protocols = append(protocols, string(data[:length]))
		data = data[length:]
	}

	return protocols
}

var _ net.Conn = (*CaptureConn)(nil)
