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
	JA3String string
	JA3       string
	JA4       string
}

// FingerprintClientHello parses a captured ClientHello handshake message and computes JA3 and JA4.
func FingerprintClientHello(hello []byte) (fingerprint Fingerprint, err error) {
	parsed, err := parseClientHello(hello)
	if err != nil {
		return fingerprint, err
	}

	ja3String := parsed.ja3String()
	ja3Hash := md5.Sum([]byte(ja3String))
	ja4, err := parsed.ja4()
	if err != nil {
		return fingerprint, err
	}

	return Fingerprint{
		JA3String: ja3String,
		JA3:       hex.EncodeToString(ja3Hash[:]),
		JA4:       ja4,
	}, nil
}

// Fingerprint returns JA3 and JA4 calculated from the ClientHello observed by this connection.
func (c *CaptureConn) Fingerprint() (fingerprint Fingerprint, err error) {
	hello, err := c.ClientHelloBytes()
	if err != nil {
		return fingerprint, err
	}

	return FingerprintClientHello(hello)
}

type parsedClientHello struct {
	legacyVersion uint16
	ciphers       []uint16
	extensions    []parsedExtension
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
	if _, data, err = readVector(data, 1); err != nil {
		return hello, fmt.Errorf("ClientHello: session ID: %w", err)
	}
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
	data = rest
	if len(data) == 0 {
		return hello, nil
	}
	extensionBytes, rest, err := readVector(data, 2)
	if err != nil {
		return hello, fmt.Errorf("ClientHello: extensions: %w", err)
	}
	if len(rest) != 0 {
		return hello, fmt.Errorf("ClientHello: %d unexpected trailing bytes", len(rest))
	}
	for len(extensionBytes) > 0 {
		if len(extensionBytes) < 4 {
			return hello, fmt.Errorf("ClientHello: truncated extension header")
		}
		id := binary.BigEndian.Uint16(extensionBytes[:2])
		extensionLength := int(binary.BigEndian.Uint16(extensionBytes[2:4]))
		extensionBytes = extensionBytes[4:]
		if extensionLength > len(extensionBytes) {
			return hello, fmt.Errorf("ClientHello: extension 0x%04x length %d exceeds remaining data", id, extensionLength)
		}
		extension := parsedExtension{
			id:   id,
			data: extensionBytes[:extensionLength],
		}
		switch id {
		case 10, 13:
			if _, parseErr := parseUint16Vector(extension.data, 2); parseErr != nil {
				return hello, fmt.Errorf("ClientHello: extension 0x%04x: %w", id, parseErr)
			}
		case 11:
			if _, rest, parseErr := readVector(extension.data, 1); parseErr != nil || len(rest) != 0 {
				if parseErr == nil {
					parseErr = fmt.Errorf("trailing bytes after point formats")
				}
				return hello, fmt.Errorf("ClientHello: extension 0x%04x: %w", id, parseErr)
			}
		case 16:
			if _, parseErr := parseALPN(extension.data); parseErr != nil {
				return hello, fmt.Errorf("ClientHello: extension 0x%04x: %w", id, parseErr)
			}
		case 43:
			if _, parseErr := parseUint16Vector(extension.data, 1); parseErr != nil {
				return hello, fmt.Errorf("ClientHello: extension 0x%04x: %w", id, parseErr)
			}
		}
		hello.extensions = append(hello.extensions, extension)
		extensionBytes = extensionBytes[extensionLength:]
	}

	return hello, nil
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
	extensions := make([]uint16, 0, len(h.extensions))
	version := h.legacyVersion
	sni := false
	alpn := "00"
	var signatureAlgorithms []uint16
	for _, extension := range h.extensions {
		if isGREASE(extension.id) {
			continue
		}
		switch extension.id {
		case 0:
			sni = true
		case 16:
			protocols, parseErr := parseALPN(extension.data)
			if parseErr != nil {
				return "", fmt.Errorf("ClientHello: ALPN extension: %w", parseErr)
			}
			if len(protocols) > 0 {
				alpn = ja4ALPN(protocols[0])
			}
		case 13:
			var values []uint16
			values, err = parseUint16Vector(extension.data, 2)
			if err != nil {
				return "", fmt.Errorf("ClientHello: signature algorithms: %w", err)
			}
			for _, value := range values {
				if !isGREASE(value) {
					signatureAlgorithms = append(signatureAlgorithms, value)
				}
			}
		case 43:
			versions, parseErr := parseUint16Vector(extension.data, 1)
			if parseErr != nil {
				return "", fmt.Errorf("ClientHello: supported versions: %w", parseErr)
			}
			version = 0
			for _, candidate := range versions {
				if !isGREASE(candidate) && candidate > version {
					version = candidate
				}
			}
		}
		if extension.id != 0 && extension.id != 16 {
			extensions = append(extensions, extension.id)
		}
	}

	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })
	ja4b := truncatedSHA256(formatHexValues(ciphers))
	ja4c := "000000000000"
	if len(extensions) > 0 {
		input := formatHexValues(extensions)
		if len(signatureAlgorithms) > 0 {
			input += "_" + formatHexValues(signatureAlgorithms)
		}
		ja4c = truncatedSHA256(input)
	}
	nameFlag := "i"
	if sni {
		nameFlag = "d"
	}

	return fmt.Sprintf("t%s%s%02d%02d%s_%s_%s", ja4Version(version), nameFlag,
		min(len(ciphers), 99), min(len(h.extensions)-countGREASEExtensions(h.extensions), 99), alpn, ja4b, ja4c), nil
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
	return byte(value>>8) == byte(value) && byte(value)&0x0f == 0x0a
}

func countGREASEExtensions(extensions []parsedExtension) (count int) {
	for _, extension := range extensions {
		if isGREASE(extension.id) {
			count++
		}
	}

	return count
}
