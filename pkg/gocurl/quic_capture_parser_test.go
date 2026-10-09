package gocurl

import (
	"encoding/binary"
	"strings"
	"testing"
)

func malformedQUICInitialForTest() []byte {
	packet := binary.BigEndian.AppendUint32([]byte{0xd0}, quicV2Version)
	// One-byte DCID, empty SCID/token, zero advertised payload, but enough
	// captured bytes for the header-protection sample to be present.
	packet = append(packet, 1, 1, 0, 0, 0)
	return append(packet, make([]byte, 24)...)
}

func TestQUICCaptureRejectsPayloadShorterThanPacketNumber(t *testing.T) {
	_, _, err := quicV2ClientCryptoChunk(malformedQUICInitialForTest())
	if err == nil || !strings.Contains(err.Error(), "packet number") {
		t.Fatalf("error = %v, want invalid payload/packet-number length", err)
	}
}

func FuzzQUICInitialCaptureParser(f *testing.F) {
	f.Add(malformedQUICInitialForTest())
	f.Add([]byte(nil))
	f.Add([]byte{0xd0})
	f.Fuzz(func(_ *testing.T, packet []byte) {
		_, _, _ = quicV2ClientCryptoChunk(packet)
	})
}

func TestHKDFExpandLabelFixtureBounds(t *testing.T) {
	for _, length := range []int{1, 12, 16, 32} {
		if got := hkdfExpandLabel(make([]byte, 32), "quicv2 key", length); len(got) != length {
			t.Fatalf("HKDF output length = %d, want %d", len(got), length)
		}
	}
	for _, tc := range []struct {
		name   string
		length int
		label  string
	}{
		{"negative length", -1, "key"},
		{"empty length", 0, "key"},
		{"more than one HKDF block", 33, "key"},
		{"label length overflow", 16, strings.Repeat("x", 250)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("unsupported fixture did not fail explicitly")
				}
			}()
			_ = hkdfExpandLabel(make([]byte, 32), tc.label, tc.length)
		})
	}
}
