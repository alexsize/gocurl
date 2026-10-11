package gocurl

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
)

func TestClientDoManualTLSClientHelloExtensionFieldsOnWire(t *testing.T) {
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := seed.TLS.Certificates[0]
	seed.Close()

	const serverName = "manual-fields.example.test"
	const cipherSuite = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	baseProfile := TLSClientHello{
		Preset:              "chrome-120",
		ServerName:          serverName,
		CipherSuites:        []uint16{cipherSuite},
		SupportedVersions:   []uint16{tls.VersionTLS12},
		SupportedGroups:     []uint16{uint16(tls.CurveP256)},
		SignatureAlgorithms: []uint16{uint16(tls.PKCS1WithSHA256)},
		ALPN:                []string{"http/1.1"},
	}

	baseline := runManualClientHelloAPIRequest(t, certificate, baseProfile)
	assertManualTLSWireVectors(t, baseline.fingerprint, baseProfile)
	wantGroups := []uint16{uint16(tls.CurveP256)}
	wantSignatures := []uint16{uint16(tls.PKCS1WithSHA256)}
	if !slices.Equal(baseline.groups, wantGroups) {
		t.Fatalf("ClientHello supported groups = %v, want %v", baseline.groups, wantGroups)
	}
	if !slices.Equal(baseline.signatures, wantSignatures) {
		t.Fatalf("ClientHello signature algorithms = %v, want %v", baseline.signatures, wantSignatures)
	}
	if len(baseline.extensions) < 2 {
		t.Fatalf("captured only %d ClientHello extensions", len(baseline.extensions))
	}

	// The preset's padding extension is conditional: the wire ClientHello can
	// include it for padding but applyProfile excludes a non-active padding
	// extension from the required permutation.
	wantOrder := make([]uint16, 0, len(baseline.extensions))
	for _, id := range baseline.extensions {
		if id != 21 { // TLS padding extension.
			wantOrder = append(wantOrder, id)
		}
	}
	slices.Reverse(wantOrder)
	orderedProfile := baseProfile
	orderedProfile.ExtensionOrder = wantOrder
	got := runManualClientHelloAPIRequest(t, certificate, orderedProfile)
	assertManualTLSWireVectors(t, got.fingerprint, orderedProfile)
	if !slices.Equal(normalizeTLSGREASEExtensions(got.extensions), normalizeTLSGREASEExtensions(wantOrder)) {
		t.Fatalf("ClientHello extension order = %v, want %v", got.extensions, wantOrder)
	}
	if !slices.Equal(got.groups, wantGroups) || !slices.Equal(got.signatures, wantSignatures) {
		t.Fatalf(
			"ClientHello groups/signatures = %v/%v, want %v/%v",
			got.groups,
			got.signatures,
			wantGroups,
			wantSignatures,
		)
	}
}

func normalizeTLSGREASEExtensions(ids []uint16) []uint16 {
	normalized := slices.Clone(ids)
	for i, id := range normalized {
		if byte(id>>8) == byte(id) && byte(id)&0x0f == 0x0a {
			normalized[i] = 0x0a0a
		}
	}
	return normalized
}

type manualClientHelloObservation struct {
	fingerprint utlsengine.Fingerprint
	extensions  []uint16
	groups      []uint16
	signatures  []uint16
}

func runManualClientHelloAPIRequest(
	t *testing.T,
	certificate tls.Certificate,
	profile TLSClientHello,
) manualClientHelloObservation {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	capture := &manualClientHelloListener{Listener: listener, hello: make(chan []byte, 1)}
	// #nosec G112 -- Loopback-only fixture closed by test cleanup, not a deployed HTTP server.
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS12 || r.TLS.ServerName != profile.ServerName ||
			r.TLS.NegotiatedProtocol != "http/1.1" ||
			r.TLS.CipherSuite != profile.CipherSuites[0] {
			t.Errorf(
				"negotiated TLS state = %+v; want TLS 1.2, SNI %q, ALPN http/1.1, cipher %#x",
				r.TLS,
				profile.ServerName,
				profile.CipherSuites[0],
			)
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(tls.NewListener(capture, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			NextProtos:   []string{"http/1.1"},
		}))
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = capture.Close()
		<-serveDone
	})

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	result, err := NewClient().Do(ctx, Request{
		URL:         "https://" + listener.Addr().String() + "/",
		HTTPVersion: "1.1",
		Insecure:    true,
		TLSProfile:  &TLSProfile{ClientHello: &profile},
	})
	if err != nil {
		t.Fatalf(
			"Client.Do() with manual ClientHello (extension order size %d, IDs %v): %v",
			len(profile.ExtensionOrder),
			profile.ExtensionOrder,
			err,
		)
	}
	defer result.Close()
	if got, want := result.Response.StatusCode, http.StatusNoContent; got != want {
		t.Fatalf("response status = %d, want %d", got, want)
	}
	select {
	case hello := <-capture.hello:
		observation, parseErr := parseManualClientHelloExtensions(hello)
		if parseErr != nil {
			t.Fatalf("parse captured ClientHello: %v", parseErr)
		}
		// The listener strips the handshake header; restore its bounded length
		// before parsing the actual captured bytes, never a generated profile.
		if len(hello) > 65535 {
			t.Fatal("fixture ClientHello exceeds one TLS record")
		}
		message := append([]byte{1, 0, byte((len(hello) >> 8) & 255), byte(len(hello) & 255)}, hello...)
		observation.fingerprint, parseErr = utlsengine.FingerprintClientHello(message)
		if parseErr != nil {
			t.Fatalf("fingerprint captured ClientHello: %v", parseErr)
		}
		return observation
	case <-ctx.Done():
		t.Fatalf("wait for captured ClientHello: %v", ctx.Err())
		return manualClientHelloObservation{}
	}
}

func assertManualTLSWireVectors(t *testing.T, got utlsengine.Fingerprint, want TLSClientHello) {
	t.Helper()
	if !slices.Equal(got.CipherSuites, want.CipherSuites) ||
		!slices.Equal(got.SupportedVersions, want.SupportedVersions) || !slices.Equal(got.ALPN, want.ALPN) {
		t.Errorf("wire vectors ciphers=%v versions=%v ALPN=%v; want %v / %v / %v",
			got.CipherSuites, got.SupportedVersions, got.ALPN, want.CipherSuites, want.SupportedVersions, want.ALPN)
	}
}

type manualClientHelloListener struct {
	net.Listener
	hello chan []byte
}

func (l *manualClientHelloListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	var header [5]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	record := make([]byte, int(header[3])<<8|int(header[4]))
	if _, err = io.ReadFull(conn, record); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if header[0] != 22 || len(record) < 4 || record[0] != 1 {
		_ = conn.Close()
		return nil, errors.New("first TLS record does not contain a ClientHello")
	}
	messageLength := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	if messageLength > len(record)-4 {
		_ = conn.Close()
		return nil, fmt.Errorf(
			"ClientHello message is fragmented across records (%d > %d)",
			messageLength,
			len(record)-4,
		)
	}
	select {
	case l.hello <- bytes.Clone(record[4 : 4+messageLength]):
	default:
	}
	return &manualClientHelloReplayConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(header[:]), bytes.NewReader(record), conn),
	}, nil
}

type manualClientHelloReplayConn struct {
	net.Conn
	reader io.Reader
}

func (c *manualClientHelloReplayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func parseManualClientHelloExtensions(body []byte) (manualClientHelloObservation, error) {
	if len(body) < 35 {
		return manualClientHelloObservation{}, errors.New("truncated ClientHello fields")
	}
	cursor := 34
	sessionIDLength := int(body[cursor])
	cursor++
	if cursor+sessionIDLength+2 > len(body) {
		return manualClientHelloObservation{}, errors.New("truncated ClientHello session ID")
	}
	cursor += sessionIDLength
	cipherSuitesLength := int(binary.BigEndian.Uint16(body[cursor : cursor+2]))
	cursor += 2
	if cursor+cipherSuitesLength+1 > len(body) {
		return manualClientHelloObservation{}, errors.New("truncated ClientHello cipher suites")
	}
	cursor += cipherSuitesLength
	compressionLength := int(body[cursor])
	cursor++
	if cursor+compressionLength+2 > len(body) {
		return manualClientHelloObservation{}, errors.New("truncated ClientHello compression methods")
	}
	cursor += compressionLength
	extensionsLength := int(binary.BigEndian.Uint16(body[cursor : cursor+2]))
	cursor += 2
	if cursor+extensionsLength > len(body) {
		return manualClientHelloObservation{}, errors.New("truncated ClientHello extensions")
	}
	var observation manualClientHelloObservation
	extensions := body[cursor : cursor+extensionsLength]
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return manualClientHelloObservation{}, errors.New("truncated ClientHello extension header")
		}
		id := binary.BigEndian.Uint16(extensions[:2])
		length := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if length > len(extensions) {
			return manualClientHelloObservation{}, errors.New("truncated ClientHello extension body")
		}
		value := extensions[:length]
		observation.extensions = append(observation.extensions, id)
		switch id {
		case 10:
			groups, parseErr := parseUint16Vector(value)
			if parseErr != nil {
				return manualClientHelloObservation{}, fmt.Errorf("supported_groups: %w", parseErr)
			}
			observation.groups = groups
		case 13:
			signatures, parseErr := parseUint16Vector(value)
			if parseErr != nil {
				return manualClientHelloObservation{}, fmt.Errorf("signature_algorithms: %w", parseErr)
			}
			observation.signatures = signatures
		}
		extensions = extensions[length:]
	}
	return observation, nil
}

func parseUint16Vector(data []byte) ([]uint16, error) {
	if len(data) < 2 {
		return nil, errors.New("truncated vector length")
	}
	length := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if length != len(data) || length%2 != 0 {
		return nil, fmt.Errorf("invalid uint16 vector length %d for %d bytes", length, len(data))
	}
	values := make([]uint16, length/2)
	for i := range values {
		values[i] = binary.BigEndian.Uint16(data[i*2 : i*2+2])
	}
	return values, nil
}
