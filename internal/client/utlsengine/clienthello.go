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
	Preset         string
	ExtensionOrder []uint16
	ALPN           []string
}

// CaptureConn records bytes successfully written through Conn.
type CaptureConn struct {
	net.Conn

	mu         sync.Mutex
	sent       bytes.Buffer
	complete   bool
	captureErr error
}

const maxClientHelloCaptureBytes = 1 << 20

// Write records only the prefix accepted by the underlying connection.
func (c *CaptureConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	if n > 0 {
		c.mu.Lock()
		if !c.complete && c.captureErr == nil {
			if c.sent.Len()+n > maxClientHelloCaptureBytes {
				c.captureErr = fmt.Errorf("uTLS capture: ClientHello exceeds %d bytes", maxClientHelloCaptureBytes)
			} else {
				_, _ = c.sent.Write(p[:n])
				_, captureErr := extractClientHello(c.sent.Bytes())
				if captureErr == nil {
					c.complete = true
				} else if !errors.Is(captureErr, errCaptureIncomplete) {
					c.captureErr = captureErr
				}
			}
		}
		c.mu.Unlock()
	}

	return n, err
}

// ClientHelloBytes returns the first complete ClientHello handshake message observed on the wire.
func (c *CaptureConn) ClientHelloBytes() ([]byte, error) {
	c.mu.Lock()
	data := bytes.Clone(c.sent.Bytes())
	captureErr := c.captureErr
	c.mu.Unlock()
	if captureErr != nil {
		return nil, captureErr
	}

	return extractClientHello(data)
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

func applyProfile(spec *utls.ClientHelloSpec, serverName string, profile Profile) (err error) {
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

	if len(profile.ALPN) > 0 {
		for _, protocol := range profile.ALPN {
			if len(protocol) == 0 || len(protocol) > 255 {
				return fmt.Errorf("uTLS: ALPN protocol length must be between 1 and 255 bytes; got %d", len(protocol))
			}
		}
		var alpn *utls.ALPNExtension
		for _, extension := range extensions[16] {
			if candidate, ok := extension.(*utls.ALPNExtension); ok {
				alpn = candidate
				break
			}
		}
		if alpn == nil {
			return errors.New("uTLS: selected preset has no ALPN extension")
		}
		alpn.AlpnProtocols = append([]string(nil), profile.ALPN...)
	}

	if len(profile.ExtensionOrder) == 0 {
		return nil
	}
	availableExtensionCount := len(spec.Extensions)
	for _, extension := range spec.Extensions {
		if padding, ok := extension.(*utls.UtlsPaddingExtension); ok && !padding.WillPad {
			availableExtensionCount--
		}
	}
	if len(profile.ExtensionOrder) != availableExtensionCount {
		return fmt.Errorf("uTLS: extension order has %d entries; preset has %d active extensions", len(profile.ExtensionOrder), availableExtensionCount)
	}

	ordered := make([]utls.TLSExtension, 0, len(profile.ExtensionOrder))
	used := make(map[uint16]int, len(profile.ExtensionOrder))
	for _, requestedID := range profile.ExtensionOrder {
		id := normalizeGREASE(requestedID)
		variants := extensions[id]
		index := used[id]
		if index >= len(variants) {
			return fmt.Errorf("uTLS: extension ID 0x%04x is not supported by preset %q", requestedID, profile.Preset)
		}
		used[id] = index + 1
		ordered = append(ordered, variants[index])
	}
	for id, variants := range extensions {
		if used[id] == len(variants) {
			continue
		}
		for _, extension := range variants[used[id]:] {
			padding, ok := extension.(*utls.UtlsPaddingExtension)
			if !ok || padding.WillPad {
				return fmt.Errorf("uTLS: extension order omits extension ID 0x%04x", id)
			}
		}
	}
	spec.Extensions = ordered

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
	if byte(id>>8) == byte(id) && byte(id)&0x0f == 0x0a {
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
