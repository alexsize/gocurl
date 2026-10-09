// Package utlsengine provides an isolated uTLS ClientHello builder and wire capture.
package utlsengine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// Profile selects a uTLS preset and optionally overrides its extension order and ALPN list.
// ExtensionOrder must be a permutation of the selected preset's extensions.
type Profile struct {
	Preset              string
	ExtensionOrder      []uint16
	CipherSuites        []uint16
	SupportedVersions   []uint16
	SupportedGroups     []uint16
	SignatureAlgorithms []uint16
	ALPN                []string
}

// CaptureConn records bytes successfully written through Conn.
type CaptureConn struct {
	net.Conn

	mu             sync.Mutex
	recordBuffer   []byte
	handshakeBytes []byte
	hellos         [][]byte
	capturedBytes  int
	captureDone    bool
	captureErr     error
}

const maxClientHelloCaptureBytes = 1 << 20

// Write records only the prefix accepted by the underlying connection.
func (c *CaptureConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	if n > 0 {
		c.mu.Lock()
		if !c.captureDone {
			c.capturedBytes += n
			if c.captureErr == nil {
				c.captureWritten(p[:n])
			}
		}
		c.mu.Unlock()
	}

	return n, err
}

// ClientHelloBytes returns the first complete ClientHello observed on the wire.
func (c *CaptureConn) ClientHelloBytes() ([]byte, error) {
	return c.ClientHelloBytesAt(1)
}

// ClientHelloBytesAt returns a complete, one-based ClientHello observation.
func (c *CaptureConn) ClientHelloBytesAt(index int) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if index < 1 {
		return nil, fmt.Errorf("uTLS capture: ClientHello index must be positive")
	}
	captureErr := c.captureErr
	if index <= len(c.hellos) {
		return bytes.Clone(c.hellos[index-1]), nil
	}
	if captureErr != nil {
		return nil, captureErr
	}
	return nil, errCaptureIncomplete
}

// ClientHelloCount returns how many complete ClientHello messages were observed.
func (c *CaptureConn) ClientHelloCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.hellos)
}

// CaptureError returns an error observed while parsing the on-wire capture.
func (c *CaptureConn) CaptureError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.captureErr
}

// CapturedBytes returns the number of bytes accepted by the underlying
// connection while capture was active.
func (c *CaptureConn) CapturedBytes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.capturedBytes
}

// StopCapture freezes the connection capture once the TLS handshake is done.
func (c *CaptureConn) StopCapture() {
	c.mu.Lock()
	if c.captureErr == nil && (len(c.recordBuffer) > 0 || len(c.handshakeBytes) > 0) {
		c.captureErr = errCaptureIncomplete
	}
	c.captureDone = true
	c.recordBuffer = nil
	c.handshakeBytes = nil
	c.mu.Unlock()
}

func (c *CaptureConn) captureWritten(data []byte) {
	if len(c.recordBuffer)+len(data) > maxClientHelloCaptureBytes {
		c.captureErr = fmt.Errorf("uTLS capture: pending TLS data exceeds %d bytes", maxClientHelloCaptureBytes)
		return
	}
	c.recordBuffer = append(c.recordBuffer, data...)
	for len(c.recordBuffer) >= 5 {
		recordLength := int(binary.BigEndian.Uint16(c.recordBuffer[3:5]))
		if recordLength > maxClientHelloCaptureBytes {
			c.captureErr = fmt.Errorf("uTLS capture: TLS record length %d exceeds capture limit", recordLength)
			return
		}
		frameLength := 5 + recordLength
		if len(c.recordBuffer) < frameLength {
			return
		}
		contentType := c.recordBuffer[0]
		payload := bytes.Clone(c.recordBuffer[5:frameLength])
		c.recordBuffer = append(c.recordBuffer[:0], c.recordBuffer[frameLength:]...)
		if contentType == 22 {
			c.captureHandshakePayload(payload)
			if c.captureErr != nil {
				return
			}
		}
	}
}

func (c *CaptureConn) captureHandshakePayload(payload []byte) {
	if len(c.handshakeBytes)+len(payload) > maxClientHelloCaptureBytes {
		c.captureErr = fmt.Errorf("uTLS capture: handshake data exceeds %d bytes", maxClientHelloCaptureBytes)
		return
	}
	c.handshakeBytes = append(c.handshakeBytes, payload...)
	for len(c.handshakeBytes) >= 4 {
		messageLength := 4 + (int(c.handshakeBytes[1]) << 16) +
			(int(c.handshakeBytes[2]) << 8) + int(c.handshakeBytes[3])
		if messageLength > maxClientHelloCaptureBytes {
			c.captureErr = fmt.Errorf("uTLS capture: handshake message exceeds %d bytes", maxClientHelloCaptureBytes)
			return
		}
		if len(c.handshakeBytes) < messageLength {
			return
		}
		message := bytes.Clone(c.handshakeBytes[:messageLength])
		c.handshakeBytes = append(c.handshakeBytes[:0], c.handshakeBytes[messageLength:]...)
		if message[0] == 1 {
			if _, err := parseClientHello(message); err != nil {
				c.captureErr = fmt.Errorf("uTLS capture: malformed ClientHello: %w", err)
				return
			}
			c.hellos = append(c.hellos, message)
		}
	}
}

// Handshake applies profile to conn and returns the negotiated uTLS connection and its wire capture.
func Handshake(
	ctx context.Context,
	conn net.Conn,
	config *utls.Config,
	profile Profile,
) (tlsConn *utls.UConn, capture *CaptureConn, err error) {
	if conn == nil {
		return nil, nil, errors.New("uTLS: connection is nil")
	}
	if config == nil {
		return nil, nil, errors.New("uTLS: TLS config is nil")
	}
	if ctx == nil {
		return nil, nil, errors.New("uTLS: handshake context is nil")
	}

	id, err := presetID(profile.Preset)
	if err != nil {
		return nil, nil, err
	}

	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return nil, nil, fmt.Errorf("uTLS: load preset %q: %w", profile.Preset, err)
	}
	if err = applyProfile(&spec, config.ServerName, profile); err != nil {
		return nil, nil, err
	}

	capture = &CaptureConn{Conn: conn}
	defer capture.StopCapture()
	tlsConn = utls.UClient(capture, config.Clone(), utls.HelloCustom)
	if err = tlsConn.ApplyPreset(&spec); err != nil {
		return nil, capture, fmt.Errorf("uTLS: apply profile %q: %w", profile.Preset, err)
	}
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		return nil, capture, err
	}

	return tlsConn, capture, nil
}

var errCaptureIncomplete = errors.New("uTLS capture: ClientHello was not completely observed")

func presetID(name string) (id utls.ClientHelloID, err error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "chrome", "chrome-120":
		return utls.HelloChrome_120, nil
	case "firefox", "firefox-120":
		return utls.HelloFirefox_120, nil
	case "safari", "safari-16":
		return utls.HelloSafari_16_0, nil
	case "android", "android-11":
		return utls.HelloAndroid_11_OkHttp, nil
	default:
		return id, fmt.Errorf("uTLS: unsupported preset %q", name)
	}
}

// ValidateProfile checks preset selection and supported ClientHello overrides
// without opening a network connection.
func ValidateProfile(profile Profile, serverName string) error {
	id, err := presetID(profile.Preset)
	if err != nil {
		return err
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return fmt.Errorf("uTLS: load preset %q: %w", profile.Preset, err)
	}
	return applyProfile(&spec, serverName, profile)
}

func applyProfile(spec *utls.ClientHelloSpec, serverName string, profile Profile) (err error) {
	if len(profile.CipherSuites) > 0 {
		spec.CipherSuites = append([]uint16(nil), profile.CipherSuites...)
	}
	if err = overrideProfileExtension(spec.Extensions, 43, profile.SupportedVersions); err != nil {
		return err
	}
	if err = overrideProfileExtension(spec.Extensions, 10, profile.SupportedGroups); err != nil {
		return err
	}
	if err = overrideProfileExtension(spec.Extensions, 13, profile.SignatureAlgorithms); err != nil {
		return err
	}
	extensions := make(map[uint16][]utls.TLSExtension, len(spec.Extensions))
	for _, extension := range spec.Extensions {
		if sni, ok := extension.(*utls.SNIExtension); ok {
			sni.ServerName = serverName
		}
		id, idErr := extensionID(extension)
		if idErr != nil {
			return idErr
		}
		extensions[id] = append(extensions[id], extension)
	}

	if err = applyProfileALPN(extensions, profile.ALPN); err != nil {
		return err
	}
	return applyProfileExtensionOrder(spec, extensions, profile)
}

func overrideProfileExtension(extensions []utls.TLSExtension, extensionType uint16, values []uint16) error {
	if len(values) == 0 {
		return nil
	}
	found := 0
	for _, extension := range extensions {
		switch typed := extension.(type) {
		case *utls.SupportedVersionsExtension:
			if extensionType == 43 {
				typed.Versions = append([]uint16(nil), values...)
				found++
			}
		case *utls.SupportedCurvesExtension:
			if extensionType == 10 {
				typed.Curves = make([]utls.CurveID, len(values))
				for i, value := range values {
					typed.Curves[i] = utls.CurveID(value)
				}
				found++
			}
		case *utls.SignatureAlgorithmsExtension:
			if extensionType == 13 {
				typed.SupportedSignatureAlgorithms = make([]utls.SignatureScheme, len(values))
				for i, value := range values {
					typed.SupportedSignatureAlgorithms[i] = utls.SignatureScheme(value)
				}
				found++
			}
		}
	}
	if found != 1 {
		return fmt.Errorf("uTLS: profile requires exactly one extension 0x%04x, preset has %d", extensionType, found)
	}
	return nil
}

func extensionID(extension utls.TLSExtension) (id uint16, err error) {
	switch extension.(type) {
	case *utls.SNIExtension:
		return 0, nil
	case *utls.UtlsGREASEExtension:
		return 0x0a0a, nil
	case *utls.StatusRequestExtension:
		return 5, nil
	case *utls.SupportedCurvesExtension:
		return 10, nil
	case *utls.SupportedPointsExtension:
		return 11, nil
	case *utls.SignatureAlgorithmsExtension:
		return 13, nil
	case *utls.ALPNExtension:
		return 16, nil
	case *utls.SCTExtension:
		return 18, nil
	case *utls.UtlsPaddingExtension:
		return 21, nil
	case *utls.ExtendedMasterSecretExtension:
		return 23, nil
	case *utls.UtlsCompressCertExtension:
		return 27, nil
	case *utls.SupportedVersionsExtension:
		return 43, nil
	case *utls.PSKKeyExchangeModesExtension:
		return 45, nil
	case *utls.KeyShareExtension:
		return 51, nil
	}

	encoded := make([]byte, extension.Len())
	if _, err = extension.Read(encoded); err != nil && !errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("uTLS: encode extension type: %w", err)
	}
	if len(encoded) < 2 {
		return 0, fmt.Errorf("uTLS: extension %T has no encoded type", extension)
	}

	return normalizeGREASE(binary.BigEndian.Uint16(encoded[:2])), nil
}

func normalizeGREASE(id uint16) uint16 {
	if isGREASE(id) {
		return 0x0a0a
	}

	return id
}

func extractClientHello(records []byte) (hello []byte, err error) {
	var handshake bytes.Buffer
	for len(records) >= 5 {
		if records[0] != 22 {
			return nil, fmt.Errorf("uTLS capture: expected handshake record, got content type %d", records[0])
		}
		recordLength := int(binary.BigEndian.Uint16(records[3:5]))
		if len(records) < 5+recordLength {
			return nil, errCaptureIncomplete
		}
		_, _ = handshake.Write(records[5 : 5+recordLength])
		records = records[5+recordLength:]
		data := handshake.Bytes()
		if len(data) < 4 {
			continue
		}
		if data[0] != 1 {
			return nil, fmt.Errorf("uTLS capture: first handshake message type is %d, not ClientHello", data[0])
		}
		helloLength := 4 + (int(data[1]) << 16) + (int(data[2]) << 8) + int(data[3])
		if len(data) >= helloLength {
			return bytes.Clone(data[:helloLength]), nil
		}
	}

	return nil, errCaptureIncomplete
}
