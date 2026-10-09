package utlsengine

import (
	"encoding/binary"
	"encoding/json"
	"reflect"
	"testing"
)

func TestNormalizedExtensionFieldsGoldenCases(t *testing.T) {
	tests := []struct {
		name string
		ext  parsedExtension
		want map[string]any
	}{
		{
			name: "SNI excludes hostname",
			ext:  parsedExtension{id: 0, data: []byte{0, 6, 0, 0, 3, 'a', 'b', 'c'}},
			want: map[string]any{"present": true},
		},
		{
			name: "SNI excludes future name types",
			ext:  parsedExtension{id: 0, data: []byte{0, 4, 1, 0, 1, 'a'}},
			want: map[string]any{"present": true},
		},
		{
			name: "supported groups normalize GREASE",
			ext:  parsedExtension{id: 10, data: []byte{0, 4, 0x0a, 0x0a, 0, 23}},
			want: map[string]any{"values": []any{"GREASE", 23}},
		},
		{
			name: "supported versions normalize GREASE",
			ext:  parsedExtension{id: 43, data: []byte{4, 0x0a, 0x0a, 3, 4}},
			want: map[string]any{"values": []any{"GREASE", 772}},
		},
		{
			name: "point formats remain integers",
			ext:  parsedExtension{id: 11, data: []byte{2, 0, 1}},
			want: map[string]any{"values": []int{0, 1}},
		},
		{
			name: "key shares retain group and key length",
			ext:  parsedExtension{id: 51, data: []byte{0, 10, 0x0a, 0x0a, 0, 2, 1, 2, 0, 23, 0, 0}},
			want: map[string]any{"shares": []any{
				map[string]any{"group": "GREASE", "key_length": 2},
				map[string]any{"group": 23, "key_length": 0},
			}},
		},
		{
			name: "GREASE extension exposes only length",
			ext:  parsedExtension{id: 0x2a2a, data: []byte{1, 2, 3}},
			want: map[string]any{"opaque_length": 3},
		},
		{
			name: "renegotiation info exposes length",
			ext:  parsedExtension{id: 0xff01, data: []byte{1, 2}},
			want: map[string]any{"length": 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizedExtensionFields(tt.ext)
			if err != nil {
				t.Fatal(err)
			}
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			wantJSON, err := json.Marshal(tt.want)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotJSON) != string(wantJSON) {
				t.Fatalf("normalized fields = %s, want %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestNormalizedExtensionFieldsRejectMalformedSNI(t *testing.T) {
	for _, data := range [][]byte{
		{},
		{0, 5, 0, 0, 1, 'a'}, // outer vector length does not match
		{0, 3, 0, 0, 0},      // empty host name
	} {
		if _, err := normalizedExtensionFields(parsedExtension{id: 0, data: data}); err == nil {
			t.Errorf("accepted malformed SNI payload %x", data)
		}
	}
}

func TestNormalizedClientHelloIncludesOrderedExtensionFields(t *testing.T) {
	hello := parsedClientHello{
		legacyVersion:      0x0303,
		ciphers:            []uint16{0x0a0a, 0x1301},
		compressionMethods: []int{0},
		extensions: []parsedExtension{
			{id: 43, data: []byte{2, 3, 4}},
			{id: 10, data: []byte{0, 2, 0, 23}},
		},
	}
	got, err := normalizedClientHelloSHA256(hello)
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("normalized hash must not be empty")
	}
	reordered := hello
	reordered.extensions = []parsedExtension{hello.extensions[1], hello.extensions[0]}
	other, err := normalizedClientHelloSHA256(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if got == other {
		t.Fatal("normalization must preserve extension order")
	}

	greaseChanged := hello
	greaseChanged.ciphers = []uint16{0x1a1a, 0x1301}
	greaseHash, err := normalizedClientHelloSHA256(greaseChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalizedIDs(hello.ciphers), normalizedIDs(greaseChanged.ciphers)) {
		t.Fatal("GREASE cipher values should normalize identically")
	}
	if greaseHash != got {
		t.Fatal("changing a GREASE cipher value changed normalized hash")
	}
}

func TestNormalizedPSKIdentityDropsAgeAndBinder(t *testing.T) {
	identity := []byte("ticket")
	data := binary.BigEndian.AppendUint16(nil, uint16LenForTest(len(identity)+6))
	data = binary.BigEndian.AppendUint16(data, uint16LenForTest(len(identity)))
	data = append(data, identity...)
	data = append(data, 0, 0, 0, 1) // obfuscated_ticket_age
	data = append(data, 0, 33, 32)  // binder vector and binder length
	data = append(data, make([]byte, 32)...)

	got, err := normalizedExtensionFields(parsedExtension{id: 41, data: data})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"identities": []any{map[string]any{"length": len(identity)}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized PSK fields = %#v, want %#v", got, want)
	}
}
