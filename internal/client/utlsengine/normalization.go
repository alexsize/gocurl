package utlsengine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// TLSNormalizationVersion identifies the JA3Proxy-compatible canonical form.
const TLSNormalizationVersion = "TLS-NORM-1"

func normalizedClientHelloSHA256(hello parsedClientHello) (string, error) {
	normalized, err := normalizedClientHelloDocument(hello)
	if err != nil {
		return "", err
	}
	return normalizedDocumentSHA256(normalized), nil
}

func normalizedClientHelloDocument(hello parsedClientHello) ([]byte, error) {
	ciphers := normalizedIDs(hello.ciphers)
	compression := append([]int(nil), hello.compressionMethods...)
	extensions := make([]any, 0, len(hello.extensions))
	for _, extension := range hello.extensions {
		fields, err := normalizedExtensionFields(extension)
		if err != nil {
			return nil, fmt.Errorf("TLS-NORM-1 extension 0x%04x: %w", extension.id, err)
		}
		extensions = append(extensions, map[string]any{
			"id": normalizedID(extension.id), "fields": fields,
		})
	}
	normalized, err := json.Marshal(map[string]any{
		"legacy_version": hello.legacyVersion, "session_id_length": hello.sessionIDLength,
		"ciphers": ciphers, "compression_methods": compression, "extensions": extensions,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS-NORM-1 encode: %w", err)
	}
	return normalized, nil
}

func normalizedDocumentSHA256(normalized []byte) string {
	canonical := append([]byte(TLSNormalizationVersion+"\n"), normalized...)
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:])
}

func normalizedExtensionFields(extension parsedExtension) (map[string]any, error) {
	data := extension.data
	if isGREASE(extension.id) {
		return map[string]any{"opaque_length": len(data)}, nil
	}
	fields := map[string]any{}
	switch extension.id {
	case 0:
		return normalizedSNIFields(data)
	case 10, 13, 34, 50:
		return normalizedUint16Fields(data, 2)
	case 43:
		return normalizedUint16Fields(data, 1)
	case 27:
		return normalizedByteFields(data, true)
	case 11, 45:
		return normalizedByteFields(data, false)
	case 16, 17513, 17613:
		return normalizedProtocolFields(data)
	case 41:
		return normalizedListFields(data, "identities", normalizedPSKIdentities)
	case 42:
		fields["present"] = true
	case 51:
		return normalizedListFields(data, "shares", normalizedKeyShares)
	case 28:
		if len(data) != 2 {
			return nil, malformedNormalizedExtension()
		}
		fields["limit"] = int(data[0])<<8 | int(data[1])
	case 21:
		return normalizedPaddingFields(data)
	case 35:
		fields["ticket_length"] = len(data)
	case 65037:
		fields["inner_available"] = false
	case 5, 18, 23:
		fields["data_hex"] = hex.EncodeToString(data)
	case 65281:
		fields["length"] = len(data)
	default:
		fields["opaque_length"] = len(data)
	}
	return fields, nil
}

func normalizedIDs(values []uint16) []any {
	result := make([]any, len(values))
	for i, value := range values {
		if isGREASE(value) {
			result[i] = "GREASE"
		} else {
			result[i] = int(value)
		}
	}
	return result
}

func normalizedKeyShares(data []byte) ([]any, error) {
	list, rest, err := readVector(data, 2)
	if err != nil || len(rest) != 0 {
		return nil, malformedNormalizedExtension()
	}
	shares := make([]any, 0)
	for len(list) > 0 {
		if len(list) < 2 {
			return nil, malformedNormalizedExtension()
		}
		group := uint16(list[0])<<8 | uint16(list[1])
		key, remaining, readErr := readVector(list[2:], 2)
		if readErr != nil {
			return nil, malformedNormalizedExtension()
		}
		shares = append(shares, map[string]any{
			"group": normalizedID(group), "key_length": len(key),
		})
		list = remaining
	}
	return shares, nil
}

func normalizedPSKIdentities(data []byte) ([]any, error) {
	list, rest, err := readVector(data, 2)
	if err != nil {
		return nil, malformedNormalizedExtension()
	}
	identities := make([]any, 0)
	for len(list) > 0 {
		identity, remaining, readErr := readVector(list, 2)
		if readErr != nil || len(identity) == 0 || len(remaining) < 4 {
			return nil, malformedNormalizedExtension()
		}
		identities = append(identities, map[string]any{"length": len(identity)})
		list = remaining[4:]
	}
	if len(identities) == 0 {
		return nil, malformedNormalizedExtension()
	}
	binders, trailing, err := readVector(rest, 2)
	if err != nil || len(trailing) != 0 {
		return nil, malformedNormalizedExtension()
	}
	binderCount := 0
	for len(binders) > 0 {
		binder, remaining, readErr := readVector(binders, 1)
		if readErr != nil || len(binder) < 32 {
			return nil, malformedNormalizedExtension()
		}
		binderCount++
		binders = remaining
	}
	if binderCount != len(identities) {
		return nil, malformedNormalizedExtension()
	}
	return identities, nil
}

func normalizedID(value uint16) any {
	if isGREASE(value) {
		return "GREASE"
	}
	return int(value)
}

func malformedNormalizedExtension() error {
	return fmt.Errorf("malformed extension payload")
}
