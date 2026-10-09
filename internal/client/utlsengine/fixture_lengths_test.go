package utlsengine

import (
	"encoding/binary"
	"strconv"
	"testing"
)

// Fail loudly rather than constructing a silently truncated wire fixture.
func uint16LenForTest(length int) uint16 {
	if length < 0 || length > 0xffff {
		panic("test vector exceeds its 16-bit length field")
	}
	return uint16(length)
}

func tlsRecordForTest(payload []byte) []byte {
	header := binary.BigEndian.AppendUint16([]byte{22, 3, 1}, uint16LenForTest(len(payload)))
	return append(header, payload...)
}

func TestFixtureLengthBounds(t *testing.T) {
	for _, length := range []int{0, 0xffff} {
		if got := uint16LenForTest(length); int(got) != length {
			t.Fatalf("encoded length = %d, want %d", got, length)
		}
	}
	for _, length := range []int{-1, 0x10000} {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("out-of-range fixture length did not panic")
				}
			}()
			_ = uint16LenForTest(length)
		})
	}
}
