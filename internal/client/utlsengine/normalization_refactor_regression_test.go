package utlsengine

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestNormalizationDispatcherPreservesAllFieldFamilies(t *testing.T) {
	psk := append([]byte{0, 7, 0, 1, 't', 0, 0, 0, 1, 0, 33, 32}, make([]byte, 32)...)
	for _, tc := range []struct {
		ids  []uint16
		data []byte
		want string
	}{
		{[]uint16{0}, []byte{0, 4, 1, 0, 1, 'a'}, `{"present":true}`},
		{[]uint16{10, 13, 34, 50}, []byte{0, 4, 0x0a, 0x0a, 0, 23}, `{"values":["GREASE",23]}`},
		{[]uint16{43}, []byte{4, 0x0a, 0x0a, 3, 4}, `{"values":["GREASE",772]}`},
		{[]uint16{27, 11, 45}, []byte{2, 0, 1}, `{"values":[0,1]}`},
		{[]uint16{16, 17513, 17613}, []byte{0, 3, 2, 'h', '2'}, `{"protocols_hex":["6832"]}`},
		{[]uint16{41}, psk, `{"identities":[{"length":1}]}`},
		{[]uint16{42}, []byte{1}, `{"present":true}`},
		{[]uint16{51}, []byte{0, 6, 0, 29, 0, 2, 1, 2}, `{"shares":[{"group":29,"key_length":2}]}`},
		{[]uint16{28}, []byte{0x40, 0}, `{"limit":16384}`},
		{[]uint16{21}, []byte{0, 0}, `{"padding_length":2}`},
		{[]uint16{35}, []byte{1, 2}, `{"ticket_length":2}`},
		{[]uint16{65037}, []byte{1}, `{"inner_available":false}`},
		{[]uint16{5, 18, 23}, []byte{0xab, 0xcd}, `{"data_hex":"abcd"}`},
		{[]uint16{65281}, []byte{1, 2}, `{"length":2}`},
		{[]uint16{0x2a2a, 1234}, []byte{1, 2, 3}, `{"opaque_length":3}`},
	} {
		for _, id := range tc.ids {
			fields, err := normalizedExtensionFields(parsedExtension{id: id, data: tc.data})
			if err != nil {
				t.Fatalf("extension %d: %v", id, err)
			}
			got, err := json.Marshal(fields)
			if err != nil || string(got) != tc.want {
				t.Fatalf("extension %d = %s, %v; want %s", id, got, err, tc.want)
			}
		}
	}
}

func TestNormalizationByteVectorPreservesConcreteTypes(t *testing.T) {
	for _, tc := range []struct {
		id   uint16
		want any
	}{
		{27, []any{0, 1}}, {11, []int{0, 1}}, {45, []int{0, 1}},
	} {
		fields, err := normalizedExtensionFields(parsedExtension{id: tc.id, data: []byte{2, 0, 1}})
		if err != nil || !reflect.DeepEqual(fields["values"], tc.want) {
			t.Fatalf("extension %d = %#v, %v; want %#v", tc.id, fields, err, tc.want)
		}
	}
}

func TestNormalizationDispatcherPreservesMalformedFailures(t *testing.T) {
	for _, tc := range []struct {
		ids  []uint16
		data []byte
		want string
	}{
		{[]uint16{0}, []byte{0, 3, 0, 0, 0}, "malformed extension payload"},
		{[]uint16{10, 13, 34, 50}, []byte{0, 1, 0}, "vector contains an odd number of bytes"},
		{[]uint16{43}, []byte{2, 3}, "vector length 2 exceeds remaining data 1"},
		{[]uint16{27, 11, 45}, []byte{0, 1}, "malformed extension payload"},
		{[]uint16{16, 17513, 17613}, []byte{0, 1, 0}, "ALPN protocol is empty"},
		{[]uint16{41, 51}, []byte{0, 1, 0}, "malformed extension payload"},
		{[]uint16{28}, []byte{0}, "malformed extension payload"},
		{[]uint16{21}, []byte{0, 1}, "malformed extension payload"},
	} {
		for _, id := range tc.ids {
			fields, err := normalizedExtensionFields(parsedExtension{id: id, data: tc.data})
			if err == nil || err.Error() != tc.want || fields != nil {
				t.Fatalf("extension %d = %#v, %v; want nil, %q", id, fields, err, tc.want)
			}
		}
	}
}

func FuzzNormalizedExtensionFields(f *testing.F) {
	for _, id := range []uint16{0, 10, 11, 13, 16, 21, 27, 28, 34, 41, 42, 43, 45, 50, 51, 17513, 17613, 65037, 65281, 0x0a0a} {
		f.Add(id, []byte{0, 0})
	}
	f.Fuzz(func(t *testing.T, id uint16, data []byte) {
		if len(data) > 65535 {
			return
		}
		fields, err := normalizedExtensionFields(parsedExtension{id: id, data: data})
		if err != nil {
			if fields != nil {
				t.Fatal("malformed extension returned partial normalized fields")
			}
			return
		}
		if fields == nil {
			t.Fatal("successful normalization returned nil fields")
		}
		if _, err = json.Marshal(fields); err != nil {
			t.Fatal(err)
		}
	})
}
