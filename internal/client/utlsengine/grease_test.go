package utlsengine

import "testing"

func TestGREASEDetectionAndNormalizationExhaustive(t *testing.T) {
	reserved := map[uint16]bool{
		0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
		0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
		0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
		0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
	}
	for value := uint16(0); ; value++ {
		if got := isGREASE(value); got != reserved[value] {
			t.Fatalf("isGREASE(%04x) = %t, want %t", value, got, reserved[value])
		}
		want := value
		if reserved[value] {
			want = 0x0a0a
		}
		if got := normalizeGREASE(value); got != want {
			t.Fatalf("normalizeGREASE(%04x) = %04x, want %04x", value, got, want)
		}
		if value == 0xffff {
			break
		}
	}
}
