package utlsengine

import (
	"crypto/md5" // #nosec G501 -- JA3 specifies MD5 as a stable fingerprint encoding, not for security.
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Fingerprint contains JA3 and JA4 values calculated from an observed ClientHello.
type Fingerprint struct {
	JA3String            string   `json:"ja3_string"`
	JA3                  string   `json:"ja3_hash"`
	JA4                  string   `json:"ja4"`
	NormalizedSHA256     string   `json:"normalized_sha256"`
	NormalizationVersion string   `json:"normalization_version"`
	NormalizationError   string   `json:"normalization_error,omitempty"`
	CipherSuites         []uint16 `json:"cipher_suites"`
	ExtensionOrder       []uint16 `json:"extension_order"`
	ALPN                 []string `json:"alpn"`
	SupportedVersions    []uint16 `json:"supported_versions,omitempty"`
	SupportedGroups      []uint16 `json:"supported_groups,omitempty"`
	SignatureAlgorithms  []uint16 `json:"signature_algorithms,omitempty"`
	normalizedDocument   []byte
}

// FingerprintClientHello parses a captured ClientHello handshake message and computes JA3 and JA4.
func FingerprintClientHello(hello []byte) (fingerprint Fingerprint, err error) {
	parsed, err := parseClientHello(hello)
	if err != nil {
		return fingerprint, err
	}

	ja3String := parsed.ja3String()
	ja3Hash := md5.Sum([]byte(ja3String)) // #nosec G401 -- JA3 defines MD5 as a fingerprint encoding, not for security.
	ja4, err := parsed.ja4()
	if err != nil {
		return fingerprint, err
	}
	normalizedDocument, normalizationErr := normalizedClientHelloDocument(parsed)
	normalizedHash := ""
	if normalizationErr == nil {
		normalizedHash = normalizedDocumentSHA256(normalizedDocument)
	}
	normalizationError := ""
	if normalizationErr != nil {
		normalizationError = normalizationErr.Error()
	}

	return Fingerprint{
		JA3String:            ja3String,
		JA3:                  hex.EncodeToString(ja3Hash[:]),
		JA4:                  ja4,
		NormalizedSHA256:     normalizedHash,
		NormalizationVersion: TLSNormalizationVersion,
		NormalizationError:   normalizationError,
		normalizedDocument:   normalizedDocument,
		CipherSuites:         append([]uint16(nil), parsed.ciphers...),
		ExtensionOrder:       parsed.extensionOrder(),
		ALPN:                 parsed.alpn(),
		SupportedVersions:    append([]uint16(nil), parsed.supportedVersions...),
		SupportedGroups:      append([]uint16(nil), parsed.supportedGroups...),
		SignatureAlgorithms:  append([]uint16(nil), parsed.signatureAlgorithms...),
	}, nil
}

func (h parsedClientHello) extensionOrder() (order []uint16) {
	for _, extension := range h.extensions {
		id := extension.id
		if isGREASE(id) {
			id = 0x0a0a
		}
		order = append(order, id)
	}

	return order
}

func (h parsedClientHello) alpn() (protocols []string) {
	for _, extension := range h.extensions {
		if extension.id != 16 {
			continue
		}
		protocols, _ = parseALPN(extension.data)
		return protocols
	}

	return nil
}

// Fingerprint returns JA3 and JA4 calculated from the ClientHello observed by this connection.
func (c *CaptureConn) Fingerprint() (fingerprint Fingerprint, err error) {
	return c.FingerprintAt(1)
}

// FingerprintAt calculates the fingerprint of one-based ClientHello index.
func (c *CaptureConn) FingerprintAt(index int) (fingerprint Fingerprint, err error) {
	hello, err := c.ClientHelloBytesAt(index)
	if err != nil {
		return fingerprint, err
	}

	return FingerprintClientHello(hello)
}

type parsedClientHello struct {
	legacyVersion       uint16
	sessionIDLength     int
	ciphers             []uint16
	compressionMethods  []int
	extensions          []parsedExtension
	supportedVersions   []uint16
	supportedGroups     []uint16
	signatureAlgorithms []uint16
}

type parsedExtension struct {
	id   uint16
	data []byte
}

func parseClientHello(message []byte) (hello parsedClientHello, err error) {
	if len(message) < 4 || message[0] != 1 {
		return hello, fmt.Errorf("ClientHello: invalid handshake header")
	}
	messageLength := int(message[1])<<16 | int(message[2])<<8 | int(message[3])
	if messageLength != len(message)-4 {
		return hello, fmt.Errorf("ClientHello: handshake length is %d, captured %d", messageLength, len(message)-4)
	}
	data := message[4:]
	if len(data) < 2+32 {
		return hello, fmt.Errorf("ClientHello: truncated version or random")
	}
	hello.legacyVersion = binary.BigEndian.Uint16(data[:2])
	data = data[2+32:]
	sessionID, rest, err := readVector(data, 1)
	if err != nil {
		return hello, fmt.Errorf("ClientHello: session ID: %w", err)
	}
	hello.sessionIDLength = len(sessionID)
	data = rest
	cipherBytes, rest, err := readVector(data, 2)
	if err != nil {
		return hello, fmt.Errorf("ClientHello: cipher suites: %w", err)
	}
	if len(cipherBytes)%2 != 0 {
		return hello, fmt.Errorf("ClientHello: cipher suites have odd byte length %d", len(cipherBytes))
	}
	for len(cipherBytes) > 0 {
		hello.ciphers = append(hello.ciphers, binary.BigEndian.Uint16(cipherBytes[:2]))
		cipherBytes = cipherBytes[2:]
	}
	data = rest
	compressionMethods, rest, err := readVector(data, 1)
	if err != nil {
		return hello, fmt.Errorf("ClientHello: compression methods: %w", err)
	}
	if len(compressionMethods) == 0 {
		return hello, fmt.Errorf("ClientHello: compression methods are empty")
	}
	for _, method := range compressionMethods {
		hello.compressionMethods = append(hello.compressionMethods, int(method))
	}
	data = rest
	if len(data) == 0 {
		return hello, nil
	}
	err = parseClientHelloExtensions(&hello, data)
	return hello, err
}

func readVector(data []byte, prefixBytes int) (vector, rest []byte, err error) {
	if len(data) < prefixBytes {
		return nil, nil, fmt.Errorf("length prefix needs %d bytes, got %d", prefixBytes, len(data))
	}
	var length int
	switch prefixBytes {
	case 1:
		length = int(data[0])
	case 2:
		length = int(binary.BigEndian.Uint16(data[:2]))
	default:
		return nil, nil, fmt.Errorf("unsupported length prefix size %d", prefixBytes)
	}
	if length > len(data)-prefixBytes {
		return nil, nil, fmt.Errorf("vector length %d exceeds remaining data %d", length, len(data)-prefixBytes)
	}

	return data[prefixBytes : prefixBytes+length], data[prefixBytes+length:], nil
}

func (h parsedClientHello) ja3String() string {
	ciphers := make([]string, 0, len(h.ciphers))
	for _, cipher := range h.ciphers {
		if !isGREASE(cipher) {
			ciphers = append(ciphers, fmt.Sprint(cipher))
		}
	}
	extensionIDs := make([]string, 0, len(h.extensions))
	var groups, pointFormats []string
	for _, extension := range h.extensions {
		if isGREASE(extension.id) {
			continue
		}
		extensionIDs = append(extensionIDs, fmt.Sprint(extension.id))
		switch extension.id {
		case 10:
			values, err := parseUint16Vector(extension.data, 2)
			if err == nil {
				groups = append(groups, decimalValues(values, true)...)
			}
		case 11:
			values, _, err := readVector(extension.data, 1)
			if err == nil {
				for _, value := range values {
					pointFormats = append(pointFormats, fmt.Sprint(value))
				}
			}
		}
	}

	return strings.Join([]string{
		fmt.Sprint(h.legacyVersion),
		strings.Join(ciphers, "-"),
		strings.Join(extensionIDs, "-"),
		strings.Join(groups, "-"),
		strings.Join(pointFormats, "-"),
	}, ",")
}

func (h parsedClientHello) ja4() (fingerprint string, err error) {
	ciphers := make([]uint16, 0, len(h.ciphers))
	for _, cipher := range h.ciphers {
		if !isGREASE(cipher) {
			ciphers = append(ciphers, cipher)
		}
	}
	fields, err := collectJA4ExtensionFields(h)
	if err != nil {
		return "", err
	}

	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	sort.Slice(fields.extensions, func(i, j int) bool { return fields.extensions[i] < fields.extensions[j] })
	ja4b := truncatedSHA256(formatHexValues(ciphers))
	ja4c := "000000000000"
	if len(fields.extensions) > 0 {
		input := formatHexValues(fields.extensions)
		if len(fields.signatureAlgorithms) > 0 {
			input += "_" + formatHexValues(fields.signatureAlgorithms)
		}
		ja4c = truncatedSHA256(input)
	}
	nameFlag := "i"
	if fields.sni {
		nameFlag = "d"
	}

	return fmt.Sprintf(
		"t%s%s%02d%02d%s_%s_%s",
		ja4Version(fields.version),
		nameFlag,
		min(
			len(ciphers),
			99,
		),
		min(len(h.extensions)-countGREASEExtensions(h.extensions), 99),
		fields.alpn,
		ja4b,
		ja4c,
	), nil
}

func parseUint16Vector(data []byte, prefixBytes int) (values []uint16, err error) {
	vector, rest, err := readVector(data, prefixBytes)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%d trailing bytes after vector", len(rest))
	}
	if len(vector)%2 != 0 {
		return nil, fmt.Errorf("vector contains an odd number of bytes")
	}
	for len(vector) > 0 {
		values = append(values, binary.BigEndian.Uint16(vector[:2]))
		vector = vector[2:]
	}

	return values, nil
}

func parseALPN(data []byte) (protocols []string, err error) {
	list, rest, err := readVector(data, 2)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%d trailing bytes after ALPN list", len(rest))
	}
	for len(list) > 0 {
		protocol, remaining, readErr := readVector(list, 1)
		if readErr != nil {
			return nil, readErr
		}
		if len(protocol) == 0 {
			return nil, fmt.Errorf("ALPN protocol is empty")
		}
		protocols = append(protocols, string(protocol))
		list = remaining
	}

	return protocols, nil
}

func ja4ALPN(protocol string) (value string) {
	first, last := protocol[0], protocol[len(protocol)-1]
	if !asciiAlphaNumeric(first) || !asciiAlphaNumeric(last) {
		encoded := hex.EncodeToString([]byte(protocol))
		return encoded[:1] + encoded[len(encoded)-1:]
	}

	return string([]byte{first, last})
}

func asciiAlphaNumeric(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func ja4Version(version uint16) string {
	switch version {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

func decimalValues(values []uint16, skipGREASE bool) (result []string) {
	for _, value := range values {
		if skipGREASE && isGREASE(value) {
			continue
		}
		result = append(result, fmt.Sprint(value))
	}

	return result
}

func formatHexValues(values []uint16) (result string) {
	formatted := make([]string, len(values))
	for i, value := range values {
		formatted[i] = fmt.Sprintf("%04x", value)
	}

	return strings.Join(formatted, ",")
}

func truncatedSHA256(value string) (hash string) {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])[:12]
}

func isGREASE(value uint16) bool {
	return value>>8 == value&0xff && value&0x0f == 0x0a
}

func countGREASEExtensions(extensions []parsedExtension) (count int) {
	for _, extension := range extensions {
		if isGREASE(extension.id) {
			count++
		}
	}

	return count
}
