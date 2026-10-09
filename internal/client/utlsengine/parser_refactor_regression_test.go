package utlsengine

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ameshkov/gocurl/internal/testutil"
)

func parserRegressionMessage(extensionBytes []byte) []byte {
	message := buildClientHelloForTest(0x0303, []uint16{0x1301}, nil)
	// The existing builder appends a two-byte empty extension vector.
	message = append(message[:len(message)-2], extensionBytes...)
	length := len(message) - 4
	message[1] = testutil.Uint8((length >> 16) & 0xff)
	message[2] = testutil.Uint8((length >> 8) & 0xff)
	message[3] = testutil.Uint8(length & 0xff)
	return message
}

func TestClientHelloParserPreservesExtensionFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"truncated vector", []byte{0}, "extensions: length prefix needs 2 bytes, got 1"},
		{"trailing data", []byte{0, 0, 99}, "1 unexpected trailing bytes"},
		{"truncated header", []byte{0, 1, 0}, "truncated extension header"},
		{"truncated payload", []byte{0, 4, 0, 16, 0, 1}, "extension 0x0010 length 1 exceeds remaining data"},
		{"point formats trailing", []byte{0, 7, 0, 11, 0, 3, 1, 0, 1}, "extension 0x000b: trailing bytes after point formats"},
		{"groups odd length", []byte{0, 7, 0, 10, 0, 3, 0, 1, 0}, "extension 0x000a: vector contains an odd number of bytes"},
		{"signatures trailing", []byte{0, 7, 0, 13, 0, 3, 0, 0, 1}, "extension 0x000d: 1 trailing bytes after vector"},
		{"versions truncated", []byte{0, 6, 0, 43, 0, 2, 2, 3}, "extension 0x002b: vector length 2 exceeds remaining data 1"},
		{"ALPN empty protocol", []byte{0, 7, 0, 16, 0, 3, 0, 1, 0}, "extension 0x0010: ALPN protocol is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hello, err := parseClientHello(parserRegressionMessage(tc.data))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseClientHello() = %v, want %q", err, tc.want)
			}
			if hello.legacyVersion != 0x0303 || !reflect.DeepEqual(hello.ciphers, []uint16{0x1301}) ||
				!reflect.DeepEqual(hello.compressionMethods, []int{0}) || len(hello.extensions) != 0 {
				t.Fatalf("partial ClientHello fields changed: %+v", hello)
			}
		})
	}
}

func TestClientHelloParserRetainsOnlyCompleteExtensionsOnFailure(t *testing.T) {
	message := buildClientHelloForTest(0x0303, []uint16{0x1301}, []testExtension{
		{id: 43, data: []byte{2, 3, 4}},
		{id: 16, data: []byte{0, 2, 2, 'h'}},
		{id: 10, data: []byte{0, 2, 0, 29}},
	})
	hello, err := parseClientHello(message)
	if err == nil || !strings.Contains(err.Error(), "extension 0x0010") {
		t.Fatalf("parseClientHello() = %v", err)
	}
	if !reflect.DeepEqual(hello.supportedVersions, []uint16{0x0304}) || len(hello.extensions) != 1 ||
		hello.extensions[0].id != 43 || len(hello.supportedGroups) != 0 {
		t.Fatalf("partial extension state = %+v", hello)
	}
}

func TestClientHelloParserPreservesLegacyAndDuplicateExtensions(t *testing.T) {
	for _, suffix := range [][]byte{nil, {0, 0}} {
		hello, err := parseClientHello(parserRegressionMessage(suffix))
		if err != nil || len(hello.extensions) != 0 {
			t.Fatalf("legacy extension suffix %x: %+v, %v", suffix, hello, err)
		}
	}
	hello, err := parseClientHello(buildClientHelloForTest(0x0303, []uint16{0x1301}, []testExtension{
		{id: 43, data: []byte{2, 3, 3}}, {id: 43, data: []byte{2, 3, 4}},
	}))
	if err != nil || len(hello.extensions) != 2 || !reflect.DeepEqual(hello.supportedVersions, []uint16{0x0304}) {
		t.Fatalf("duplicate extensions changed: %+v, %v", hello, err)
	}
}
