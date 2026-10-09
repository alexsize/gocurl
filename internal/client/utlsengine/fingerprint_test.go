package utlsengine

import (
	"encoding/binary"
	"reflect"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestFingerprintClientHelloMatchesJA3ReferenceVector(t *testing.T) {
	message := buildClientHelloForTest(0x0301,
		[]uint16{47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4},
		[]testExtension{
			{id: 0},
			{id: 10, data: []byte{0, 6, 0, 23, 0, 24, 0, 25}},
			{id: 11, data: []byte{1, 0}},
		},
	)

	got, err := FingerprintClientHello(message)
	if err != nil {
		t.Fatalf("FingerprintClientHello() error = %v", err)
	}
	wantString := "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
	if got.JA3String != wantString {
		t.Fatalf("JA3 string = %q, want %q", got.JA3String, wantString)
	}
	if got.JA3 != "ada70206e40642a3e4461f35503241d5" {
		t.Fatalf("JA3 = %q, want reference hash ada70206e40642a3e4461f35503241d5", got.JA3)
	}
}

func TestFingerprintClientHelloMatchesJA3ProxyTLSNormGolden(t *testing.T) {
	message := buildClientHelloForTest(0x0303, []uint16{4865}, nil)
	fingerprint, err := FingerprintClientHello(message)
	if err != nil {
		t.Fatalf("FingerprintClientHello() error = %v", err)
	}
	if fingerprint.NormalizationVersion != "TLS-NORM-1" ||
		fingerprint.NormalizedSHA256 != "43a11d0e4c85f03ceaf8207a3e4af2c1b14fa82196fd0f0800fab09c2079f454" {
		t.Fatalf("TLS-NORM golden = %s %s", fingerprint.NormalizationVersion, fingerprint.NormalizedSHA256)
	}

	message[6] = 0xff // ClientRandom is intentionally excluded from TLS-NORM-1.
	dynamic, err := FingerprintClientHello(message)
	if err != nil {
		t.Fatalf("FingerprintClientHello(dynamic random) error = %v", err)
	}
	if dynamic.NormalizedSHA256 != fingerprint.NormalizedSHA256 {
		t.Fatalf("random changed TLS-NORM: base=%s dynamic=%s", fingerprint.NormalizedSHA256, dynamic.NormalizedSHA256)
	}
}

func TestTLSNormExcludesSNIHostname(t *testing.T) {
	base := buildClientHelloForTest(
		0x0303,
		[]uint16{4865},
		[]testExtension{{id: 0, data: sniExtensionForTest("one.test")}},
	)
	otherName := buildClientHelloForTest(
		0x0303,
		[]uint16{4865},
		[]testExtension{{id: 0, data: sniExtensionForTest("two.test")}},
	)
	baseFingerprint, err := FingerprintClientHello(base)
	if err != nil {
		t.Fatal(err)
	}
	otherFingerprint, err := FingerprintClientHello(otherName)
	if err != nil {
		t.Fatal(err)
	}
	if baseFingerprint.NormalizedSHA256 == "" || baseFingerprint.NormalizedSHA256 != otherFingerprint.NormalizedSHA256 {
		t.Fatalf(
			"TLS-NORM leaked/retained SNI: %q != %q",
			baseFingerprint.NormalizedSHA256,
			otherFingerprint.NormalizedSHA256,
		)
	}
}

func sniExtensionForTest(host string) []byte {
	name := []byte(host)
	nameEntry := binary.BigEndian.AppendUint16([]byte{0}, uint16LenForTest(len(name)))
	nameEntry = append(nameEntry, name...)
	data := binary.BigEndian.AppendUint16(nil, uint16LenForTest(len(nameEntry)))
	return append(data, nameEntry...)
}

func TestFingerprintClientHelloMatchesJA4ReferenceVector(t *testing.T) {
	ciphers := []uint16{
		0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
		0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
	}
	signatures := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	sigData := uint16VectorForTest(signatures)
	signatureExtension := append(binary.BigEndian.AppendUint16(nil, uint16LenForTest(len(sigData))), sigData...)

	message := buildClientHelloForTest(0x0303, ciphers, []testExtension{
		{id: 0x001b},
		{id: 0x0000},
		{id: 0x0033},
		{id: 0x0010, data: []byte{0, 3, 2, 'h', '2'}},
		{id: 0x4469},
		{id: 0x0017},
		{id: 0x002d},
		{id: 0x000d, data: signatureExtension},
		{id: 0x0005},
		{id: 0x0023},
		{id: 0x0012},
		{id: 0x002b, data: []byte{2, 3, 4}},
		{id: 0xff01},
		{id: 0x000b, data: []byte{1, 0}},
		{id: 0x000a, data: []byte{0, 2, 0, 0x1d}},
		{id: 0x0015},
	})

	got, err := FingerprintClientHello(message)
	if err != nil {
		t.Fatalf("FingerprintClientHello() error = %v", err)
	}
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if got.JA4 != want {
		t.Fatalf("JA4 = %q, want reference fingerprint %q", got.JA4, want)
	}
}

func TestFingerprintClientHelloIgnoresGREASE(t *testing.T) {
	base := buildClientHelloForTest(0x0303, []uint16{0x1301}, []testExtension{
		{id: 0x000d, data: []byte{0, 2, 4, 3}},
		{id: 0x002b, data: []byte{4, 0x0a, 0x0a, 3, 4}},
	})
	withGREASE := buildClientHelloForTest(0x0303, []uint16{0x1a1a, 0x1301}, []testExtension{
		{id: 0x2a2a},
		{id: 0x000d, data: []byte{0, 4, 0x3a, 0x3a, 4, 3}},
		{id: 0x002b, data: []byte{6, 0x3a, 0x3a, 0x0a, 0x0a, 3, 4}},
	})

	baseFingerprint, err := FingerprintClientHello(base)
	if err != nil {
		t.Fatalf("FingerprintClientHello(base) error = %v", err)
	}
	greaseFingerprint, err := FingerprintClientHello(withGREASE)
	if err != nil {
		t.Fatalf("FingerprintClientHello(withGREASE) error = %v", err)
	}
	if greaseFingerprint.JA3 != baseFingerprint.JA3 || greaseFingerprint.JA4 != baseFingerprint.JA4 {
		t.Fatalf("GREASE changed fingerprints: base=%+v with-GREASE=%+v", baseFingerprint, greaseFingerprint)
	}
}

func TestFingerprintClientHelloReturnsObservedWireFields(t *testing.T) {
	message := buildClientHelloForTest(0x0303, []uint16{0x1301, 0xc02f}, []testExtension{
		{id: 0x2a2a},
		{id: 16, data: []byte{0, 5, 2, 'h', '2', 1, 'x'}},
		{id: 43, data: []byte{2, 3, 4}},
	})
	fingerprint, err := FingerprintClientHello(message)
	if err != nil {
		t.Fatalf("FingerprintClientHello() error = %v", err)
	}
	wantExtensions := []uint16{0x0a0a, 16, 43}
	if !reflect.DeepEqual(fingerprint.ExtensionOrder, wantExtensions) {
		t.Fatalf("observed extension order = %v, want %v", fingerprint.ExtensionOrder, wantExtensions)
	}
	if !reflect.DeepEqual(fingerprint.ALPN, []string{"h2", "x"}) {
		t.Fatalf("observed ALPN = %v, want [h2 x]", fingerprint.ALPN)
	}
	if !reflect.DeepEqual(fingerprint.CipherSuites, []uint16{0x1301, 0xc02f}) {
		t.Fatalf("observed cipher suites = %v, want [0x1301 0xc02f]", fingerprint.CipherSuites)
	}
}

func TestFingerprintClientHelloExtractsProfileTLSFields(t *testing.T) {
	hello := buildClientHelloForTest(0x0303, []uint16{0x1301}, []testExtension{
		{id: 10, data: []byte{0, 4, 0, 29, 0, 23}},
		{id: 13, data: []byte{0, 4, 4, 3, 8, 4}},
		{id: 43, data: []byte{4, 3, 4, 3, 3}},
	})
	fingerprint, err := FingerprintClientHello(hello)
	if err != nil {
		t.Fatalf("FingerprintClientHello() error = %v", err)
	}
	if !reflect.DeepEqual(fingerprint.SupportedVersions, []uint16{0x0304, 0x0303}) ||
		!reflect.DeepEqual(fingerprint.SupportedGroups, []uint16{0x001d, 0x0017}) ||
		!reflect.DeepEqual(fingerprint.SignatureAlgorithms, []uint16{0x0403, 0x0804}) {
		t.Fatalf("extracted TLS fields = %+v", fingerprint)
	}
}

func TestJA4ALPNUsesHexForNonAlphanumericEnds(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "two letters", input: "h2", want: "h2"},
		{name: "http version", input: "http/1.1", want: "h1"},
		{name: "punctuation at end", input: "a ", want: "60"},
		{name: "binary bytes", input: string([]byte{0xab, 0xcd}), want: "ad"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ja4ALPN(tt.input); got != tt.want {
				t.Fatalf("ja4ALPN(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFingerprintClientHelloRejectsMalformedData(t *testing.T) {
	valid := buildClientHelloForTest(0x0303, []uint16{0x1301}, []testExtension{
		{id: 0x002b, data: []byte{2, 3, 4}},
	})
	malformed := [][]byte{
		valid[:3],
		append(append([]byte(nil), valid...), 0),
		buildClientHelloForTest(0x0303, []uint16{0x1301}, []testExtension{
			{id: 0x002b, data: []byte{3, 3, 4}},
		}),
		buildClientHelloForTest(0x0303, []uint16{0x1301}, []testExtension{
			{id: 0x0010, data: []byte{0, 2, 2, 'h'}},
		}),
	}
	for i, message := range malformed {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			if _, err := FingerprintClientHello(message); err == nil {
				t.Fatal("FingerprintClientHello() accepted malformed ClientHello")
			}
		})
	}
}

func TestApplyProfileRejectsInvalidALPN(t *testing.T) {
	id, err := presetID("chrome")
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"", string(make([]byte, 256))} {
		spec, specErr := utls.UTLSIdToSpec(id)
		if specErr != nil {
			t.Fatal(specErr)
		}
		err = applyProfile(&spec, "example.test", Profile{Preset: "chrome", ALPN: []string{protocol}})
		if err == nil {
			t.Fatalf("applyProfile() accepted ALPN value with %d bytes", len(protocol))
		}
	}
}

func FuzzFingerprintClientHello(f *testing.F) {
	valid := buildClientHelloForTest(0x0303, []uint16{0x1301}, []testExtension{
		{id: 0x002b, data: []byte{2, 3, 4}},
	})
	f.Add(valid)
	f.Add([]byte(nil))
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(_ *testing.T, message []byte) {
		_, _ = FingerprintClientHello(message)
	})
}

type testExtension struct {
	id   uint16
	data []byte
}

func buildClientHelloForTest(version uint16, ciphers []uint16, extensions []testExtension) (message []byte) {
	var body []byte
	body = binary.BigEndian.AppendUint16(body, version)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	cipherData := uint16VectorForTest(ciphers)
	body = binary.BigEndian.AppendUint16(body, uint16LenForTest(len(cipherData)))
	body = append(body, cipherData...)
	body = append(body, 1, 0)
	var extensionData []byte
	for _, extension := range extensions {
		extensionData = binary.BigEndian.AppendUint16(extensionData, extension.id)
		extensionData = binary.BigEndian.AppendUint16(extensionData, uint16LenForTest(len(extension.data)))
		extensionData = append(extensionData, extension.data...)
	}
	body = binary.BigEndian.AppendUint16(body, uint16LenForTest(len(extensionData)))
	body = append(body, extensionData...)
	if len(body) > 0xffffff {
		panic("test ClientHello exceeds its 24-bit length field")
	}
	message = append(message, 1, byte((len(body)>>16)&0xff), byte((len(body)>>8)&0xff), byte(len(body)&0xff))
	message = append(message, body...)

	return message
}

func uint16VectorForTest(values []uint16) (data []byte) {
	for _, value := range values {
		data = binary.BigEndian.AppendUint16(data, value)
	}

	return data
}
