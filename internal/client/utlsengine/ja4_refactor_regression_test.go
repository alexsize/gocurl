package utlsengine

import (
	"reflect"
	"testing"
)

func TestJA4PreservesFilteringVersionAndSignatureOrder(t *testing.T) {
	hello := parsedClientHello{
		legacyVersion: 0x0303,
		ciphers:       []uint16{0x1302, 0x1a1a, 0x1301},
		extensions: []parsedExtension{
			{id: 43, data: []byte{6, 0x0a, 0x0a, 3, 3, 3, 4}},
			{id: 0x2a2a},
			{id: 0},
			{id: 16, data: []byte{0, 3, 2, 'h', '2'}},
			{id: 13, data: []byte{0, 6, 8, 4, 0x3a, 0x3a, 4, 3}},
		},
	}
	want := "t13d0204h2_" + truncatedSHA256("1301,1302") + "_" + truncatedSHA256("000d,002b_0804,0403")
	got, err := hello.ja4()
	if err != nil || got != want {
		t.Fatalf("JA4 = %q, %v; want %q", got, err, want)
	}
	if !reflect.DeepEqual(hello.ciphers, []uint16{0x1302, 0x1a1a, 0x1301}) {
		t.Fatal("JA4 sorted the original cipher slice")
	}
}

func TestJA4PreservesDuplicateExtensionPolicies(t *testing.T) {
	hello := parsedClientHello{
		legacyVersion: 0x0303, ciphers: []uint16{0x1301},
		extensions: []parsedExtension{
			{id: 43, data: []byte{2, 3, 4}},
			{id: 43, data: []byte{2, 3, 3}},
			{id: 16, data: []byte{0, 3, 2, 'h', '2'}},
			{id: 16, data: []byte{0, 0}},
			{id: 13, data: []byte{0, 2, 8, 4}},
			{id: 13, data: []byte{0, 2, 4, 3}},
		},
	}
	want := "t12i0106h2_" + truncatedSHA256("1301") + "_" + truncatedSHA256("000d,000d,002b,002b_0804,0403")
	got, err := hello.ja4()
	if err != nil || got != want {
		t.Fatalf("JA4 duplicate policy = %q, %v; want %q", got, err, want)
	}
}

func TestJA4PreservesGREASEOnlyVersionAndEmptyHash(t *testing.T) {
	for _, tc := range []struct {
		extensions []parsedExtension
		want       string
	}{
		{nil, "t12i000000_e3b0c44298fc_000000000000"},
		{[]parsedExtension{{id: 43, data: []byte{2, 0x0a, 0x0a}}}, "t00i000100_e3b0c44298fc_" + truncatedSHA256("002b")},
	} {
		hello := parsedClientHello{legacyVersion: 0x0303, ciphers: []uint16{0x1a1a}, extensions: tc.extensions}
		got, err := hello.ja4()
		if err != nil || got != tc.want {
			t.Fatalf("JA4 empty/GREASE policy = %q, %v; want %q", got, err, tc.want)
		}
	}
}

func TestJA4PreservesExtensionErrorOrder(t *testing.T) {
	for _, tc := range []struct {
		id   uint16
		want string
	}{
		{16, "ClientHello: ALPN extension: length prefix needs 2 bytes, got 0"},
		{13, "ClientHello: signature algorithms: length prefix needs 2 bytes, got 0"},
		{43, "ClientHello: supported versions: length prefix needs 1 bytes, got 0"},
	} {
		hello := parsedClientHello{extensions: []parsedExtension{{id: tc.id}, {id: 16}}}
		got, err := hello.ja4()
		if err == nil || err.Error() != tc.want || got != "" {
			t.Fatalf("JA4 extension %d = %q, %v; want %q", tc.id, got, err, tc.want)
		}
	}
}
