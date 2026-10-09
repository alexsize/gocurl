package gocurl

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

const quicV2Version uint32 = 0x6b3343cf

var quicV2InitialSalt = []byte{
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
	0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
}

func TestClientDoQUICTransportParameterOrderOnWire(t *testing.T) {
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := seed.TLS.Certificates[0]
	seed.Close()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	capture := &quicInitialCaptureConn{PacketConn: packetConn, packets: make(chan []byte, 4)}
	listener, err := quic.Listen(capture, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"h3"},
	}, &quic.Config{Versions: []quic.Version{quic.Version2}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept(ctx)
		if acceptErr == nil {
			<-ctx.Done()
			_ = conn.CloseWithError(0, "test complete")
		}
	}()
	clientDone := make(chan error, 1)
	go func() {
		result, doErr := NewClient().Do(ctx, Request{
			URL:                         "https://" + listener.Addr().String() + "/",
			HTTPVersion:                 "3",
			Insecure:                    true,
			QUICTransport:               QUICTransport{Version: "2"},
			QUICTransportParameterOrder: []uint64{4, 1, 5},
		})
		if result != nil {
			_ = result.Close()
		}
		clientDone <- doErr
	}()

	clientHello := collectQUICV2ClientHello(ctx, t, capture.packets, clientDone)
	ids, parseErr := clientHelloQUICTransportParameterIDs(clientHello)
	if parseErr != nil {
		t.Fatalf("parse captured ClientHello: %v", parseErr)
	}
	if len(ids) < 4 || ids[1] != 4 || ids[2] != 1 || ids[3] != 5 {
		t.Fatalf("wire QUIC transport parameter order = %v, want requested IDs [4 1 5] immediately after GREASE", ids)
	}

	cancel()
	select {
	case <-clientDone:
	case <-time.After(time.Second):
		t.Fatal("Client.Do did not stop after context cancellation")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("QUIC listener did not stop after context cancellation")
	}
}

type quicInitialCaptureConn struct {
	net.PacketConn
	packets chan []byte
}

func (c *quicInitialCaptureConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(buffer)
	if err == nil {
		packet := append([]byte(nil), buffer[:n]...)
		select {
		case c.packets <- packet:
		default:
		}
	}
	return n, addr, err
}

func quicV2ClientCryptoChunk(packet []byte) (uint64, []byte, error) {
	dcid, pnOffset, payloadLength, err := parseQUICV2InitialHeader(packet)
	if err != nil {
		return 0, nil, err
	}
	initialSecret := hkdfExtract(quicV2InitialSalt, dcid)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", 32)
	headerKey := hkdfExpandLabel(clientSecret, "quicv2 hp", 16)
	block, err := aes.NewCipher(headerKey)
	if err != nil {
		return 0, nil, err
	}
	var mask [aes.BlockSize]byte
	block.Encrypt(mask[:], packet[pnOffset+4:pnOffset+4+aes.BlockSize])
	firstByte := packet[0] ^ (mask[0] & 0x0f)
	pnLength := int(firstByte&0x03) + 1
	if pnOffset+pnLength > len(packet) {
		return 0, nil, errors.New("truncated protected packet number")
	}
	if payloadLength < uint64(pnLength) {
		return 0, nil, errors.New("Initial payload is shorter than its packet number")
	}
	associatedData := append([]byte(nil), packet[:pnOffset+pnLength]...)
	associatedData[0] = firstByte
	var packetNumber uint64
	for i, maskByte := range mask[1:5] {
		if i >= pnLength {
			break
		}
		associatedData[pnOffset+i] ^= maskByte
		packetNumber = packetNumber<<8 | uint64(associatedData[pnOffset+i])
	}
	iv := hkdfExpandLabel(clientSecret, "quicv2 iv", 12)
	var nonce [12]byte
	copy(nonce[:], iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte((packetNumber >> (8 * i)) & 0xff)
	}
	aeadKey := hkdfExpandLabel(clientSecret, "quicv2 key", 16)
	aeadBlock, err := aes.NewCipher(aeadKey)
	if err != nil {
		return 0, nil, err
	}
	aead, err := cipher.NewGCM(aeadBlock)
	if err != nil {
		return 0, nil, err
	}
	packetEnd := pnOffset + int(payloadLength) // #nosec G115 -- Checked against len(packet)-pnOffset before decryption.
	if packetEnd > len(packet) {
		return 0, nil, errors.New("Initial payload exceeds captured datagram")
	}
	plaintext, err := aead.Open(nil, nonce[:], packet[pnOffset+pnLength:packetEnd], associatedData)
	if err != nil {
		return 0, nil, fmt.Errorf("decrypt Initial payload: %w", err)
	}
	return quicInitialCryptoChunk(plaintext)
}

func quicInitialCryptoChunk(payload []byte) (uint64, []byte, error) {
	var cryptoOffset uint64
	var crypto []byte
	for len(payload) > 0 {
		frameType, n, err := readQUICVarint(payload)
		if err != nil {
			return 0, nil, err
		}
		payload = payload[n:]
		switch frameType {
		case 0: // PADDING
		case 1: // PING
		case 6: // CRYPTO
			offset, n, readErr := readQUICVarint(payload)
			if readErr != nil {
				return 0, nil, readErr
			}
			payload = payload[n:]
			length, n, readErr := readQUICVarint(payload)
			if readErr != nil {
				return 0, nil, readErr
			}
			payload = payload[n:]
			if length > uint64(len(payload)) || len(crypto) != 0 {
				return 0, nil, errors.New("unexpected multiple or truncated ClientHello CRYPTO frames")
			}
			cryptoOffset = offset
			chunkLength := int(length) // #nosec G115 -- length is checked against len(payload) immediately above.
			crypto = append(crypto, payload[:chunkLength]...)
			payload = payload[chunkLength:]
		case 2, 3: // ACK / ACK_ECN
			payload, err = skipQUICInitialACK(payload, frameType)
			if err != nil {
				return 0, nil, err
			}
		default:
			return 0, nil, fmt.Errorf("unsupported QUIC Initial frame type %#x", frameType)
		}
	}
	if len(crypto) == 0 {
		return 0, nil, errors.New("Initial packet contains no ClientHello CRYPTO data")
	}
	return cryptoOffset, crypto, nil
}

func clientHelloQUICTransportParameterIDs(message []byte) ([]uint64, error) {
	if len(message) < 4 || message[0] != 1 {
		return nil, errors.New("CRYPTO data does not begin with ClientHello")
	}
	messageLength := int(message[1])<<16 | int(message[2])<<8 | int(message[3])
	if messageLength > len(message)-4 {
		return nil, fmt.Errorf(
			"truncated ClientHello handshake message: declared %d bytes, captured %d",
			messageLength,
			len(message)-4,
		)
	}
	message = message[4 : 4+messageLength]
	if len(message) < 35 {
		return nil, errors.New("truncated ClientHello fixed fields")
	}
	cursor := 34
	sessionIDLength := int(message[cursor])
	cursor++
	if cursor+sessionIDLength+2 > len(message) {
		return nil, errors.New("truncated ClientHello session ID")
	}
	cursor += sessionIDLength
	cipherLength := int(binary.BigEndian.Uint16(message[cursor : cursor+2]))
	cursor += 2
	if cursor+cipherLength+1 > len(message) {
		return nil, errors.New("truncated ClientHello cipher suites")
	}
	cursor += cipherLength
	compressionLength := int(message[cursor])
	cursor++
	if cursor+compressionLength+2 > len(message) {
		return nil, errors.New("truncated ClientHello compression methods")
	}
	cursor += compressionLength
	extensionsLength := int(binary.BigEndian.Uint16(message[cursor : cursor+2]))
	cursor += 2
	if cursor+extensionsLength > len(message) {
		return nil, errors.New("truncated ClientHello extensions")
	}
	extensions := message[cursor : cursor+extensionsLength]
	for len(extensions) >= 4 {
		id := binary.BigEndian.Uint16(extensions[:2])
		length := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if length > len(extensions) {
			return nil, errors.New("truncated ClientHello extension")
		}
		if id == 0x39 {
			return parseQUICTransportParameterIDs(extensions[:length])
		}
		extensions = extensions[length:]
	}
	return nil, errors.New("ClientHello has no QUIC transport parameters extension")
}

func parseQUICTransportParameterIDs(data []byte) ([]uint64, error) {
	var ids []uint64
	for len(data) > 0 {
		id, idLength, err := readQUICVarint(data)
		if err != nil {
			return nil, err
		}
		length, valueLength, err := readQUICVarint(data[idLength:])
		if err != nil {
			return nil, err
		}
		data = data[idLength+valueLength:]
		if length > uint64(len(data)) {
			return nil, errors.New("QUIC transport parameter exceeds extension")
		}
		ids = append(ids, id)
		data = data[int(length):] // #nosec G115 -- length is checked against len(data) immediately above.
	}
	return ids, nil
}

func readQUICVarint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, errors.New("truncated QUIC varint")
	}
	length := 1 << (data[0] >> 6)
	if len(data) < length {
		return 0, 0, errors.New("truncated QUIC varint")
	}
	value := uint64(data[0] & 0x3f)
	for _, b := range data[1:length] {
		value = value<<8 | uint64(b)
	}
	return value, length, nil
}

func hkdfExtract(salt, input []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write(input)
	return mac.Sum(nil)
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	// This fixture needs only a single SHA-256 block (the QUIC keys, IV, and
	// client secret). Reject unsupported requests instead of truncating fields.
	if length < 1 || length > sha256.Size {
		panic("test HKDF length must fit one SHA-256 block")
	}
	fullLabel := "tls13 " + label
	if len(fullLabel) > 255 {
		panic("test HKDF label exceeds its one-byte length field")
	}
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len(fullLabel)&0xff))
	info = append(info, fullLabel...)
	info = append(info, 0) // Empty HKDF context.
	info = append(info, 1) // First HKDF-Expand block.
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(info)
	return mac.Sum(nil)[:length]
}

func parseQUICV2InitialHeader(packet []byte) (dcid []byte, pnOffset int, payloadLength uint64, err error) {
	if len(packet) < 7 || packet[0]&0x80 == 0 || binary.BigEndian.Uint32(packet[1:5]) != quicV2Version {
		return nil, 0, 0, errors.New("packet is not a QUIC v2 long-header packet")
	}
	if packet[0]&0x30 != 0x10 {
		return nil, 0, 0, fmt.Errorf("long-header packet type = %#x, want Initial", packet[0]&0x30)
	}
	cursor := 5
	dcidLength := int(packet[cursor])
	cursor++
	if dcidLength == 0 || cursor+dcidLength+1 > len(packet) {
		return nil, 0, 0, errors.New("invalid Initial destination connection ID")
	}
	dcid = packet[cursor : cursor+dcidLength]
	cursor += dcidLength
	scidLength := int(packet[cursor])
	cursor++
	if cursor+scidLength > len(packet) {
		return nil, 0, 0, errors.New("invalid Initial source connection ID")
	}
	cursor += scidLength
	tokenLength, consumed, err := readQUICVarint(packet[cursor:])
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read Initial token length: %w", err)
	}
	cursor += consumed
	if tokenLength > uint64(len(packet)-cursor) { // #nosec G115 -- Successful varint read leaves cursor within packet.
		return nil, 0, 0, errors.New("Initial token exceeds packet")
	}
	cursor += int(tokenLength) // #nosec G115 -- Checked above against the remaining slice length (an int).
	payloadLength, consumed, err = readQUICVarint(packet[cursor:])
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read Initial payload length: %w", err)
	}
	cursor += consumed
	pnOffset = cursor
	// #nosec G115 -- Successful varint read leaves pnOffset within packet.
	remainingPayload := uint64(len(packet) - pnOffset)
	if pnOffset+4+aes.BlockSize > len(packet) || payloadLength > remainingPayload {
		return nil, 0, 0, errors.New("truncated Initial packet")
	}
	return dcid, pnOffset, payloadLength, nil
}

func skipQUICInitialACK(payload []byte, frameType uint64) ([]byte, error) {
	var ackRanges uint64
	for i := 0; i < 4; i++ {
		value, consumed, readErr := readQUICVarint(payload)
		if readErr != nil {
			return nil, readErr
		}
		payload = payload[consumed:]
		if i == 2 {
			ackRanges = value
		}
	}
	if ackRanges > uint64(len(payload)) {
		return nil, errors.New("excessive ACK range count")
	}
	for i := uint64(0); i < ackRanges*2; i++ {
		_, consumed, readErr := readQUICVarint(payload)
		if readErr != nil {
			return nil, readErr
		}
		payload = payload[consumed:]
	}
	if frameType == 3 {
		for i := 0; i < 3; i++ {
			_, consumed, readErr := readQUICVarint(payload)
			if readErr != nil {
				return nil, readErr
			}
			payload = payload[consumed:]
		}
	}
	return payload, nil
}

func collectQUICV2ClientHello(
	ctx context.Context,
	t *testing.T,
	packets <-chan []byte,
	clientDone <-chan error,
) []byte {
	t.Helper()
	var clientHello []byte
	clientHelloLength := -1
	for clientHelloLength < 0 || len(clientHello) < clientHelloLength {
		select {
		case packet := <-packets:
			offset, chunk, parseErr := quicV2ClientCryptoChunk(packet)
			if parseErr != nil {
				t.Fatalf("parse captured QUIC v2 Initial: %v", parseErr)
			}
			if offset != uint64(len(clientHello)) {
				t.Fatalf("ClientHello CRYPTO offset = %d, accumulated length = %d", offset, len(clientHello))
			}
			clientHello = append(clientHello, chunk...)
			if clientHelloLength < 0 && len(clientHello) >= 4 {
				clientHelloLength = 4 + int(clientHello[1])<<16 + int(clientHello[2])<<8 + int(clientHello[3])
			}
		case err := <-clientDone:
			t.Fatalf("public Client.Do ended before the QUIC Initial capture: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	return clientHello
}
