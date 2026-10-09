package utlsengine

import "encoding/hex"

func normalizedSNIFields(data []byte) (map[string]any, error) {
	list, rest, err := readVector(data, 2)
	if err != nil || len(rest) != 0 {
		return nil, malformedNormalizedExtension()
	}
	for len(list) > 0 {
		if len(list) < 3 {
			return nil, malformedNormalizedExtension()
		}
		// TLS-NORM-1 deliberately drops SNI name types and values; retain
		// JA3Proxy's behavior of accepting future name types.
		name, remaining, readErr := readVector(list[1:], 2)
		if readErr != nil || len(name) == 0 {
			return nil, malformedNormalizedExtension()
		}
		list = remaining
	}
	return map[string]any{"present": true}, nil
}

func normalizedUint16Fields(data []byte, prefixBytes int) (map[string]any, error) {
	values, err := parseUint16Vector(data, prefixBytes)
	if err != nil {
		return nil, err
	}
	return map[string]any{"values": normalizedIDs(values)}, nil
}

func normalizedByteFields(data []byte, heterogeneous bool) (map[string]any, error) {
	vector, rest, err := readVector(data, 1)
	if err != nil || len(rest) != 0 {
		return nil, malformedNormalizedExtension()
	}
	if heterogeneous {
		values := make([]any, len(vector))
		for i, value := range vector {
			values[i] = int(value)
		}
		return map[string]any{"values": values}, nil
	}
	values := make([]int, len(vector))
	for i, value := range vector {
		values[i] = int(value)
	}
	return map[string]any{"values": values}, nil
}

func normalizedProtocolFields(data []byte) (map[string]any, error) {
	protocols, err := parseALPN(data)
	if err != nil {
		return nil, err
	}
	encoded := make([]string, len(protocols))
	for i, protocol := range protocols {
		encoded[i] = hex.EncodeToString([]byte(protocol))
	}
	return map[string]any{"protocols_hex": encoded}, nil
}

func normalizedListFields(
	data []byte,
	name string,
	parse func([]byte) ([]any, error),
) (map[string]any, error) {
	values, err := parse(data)
	if err != nil {
		return nil, err
	}
	return map[string]any{name: values}, nil
}

func normalizedPaddingFields(data []byte) (map[string]any, error) {
	for _, value := range data {
		if value != 0 {
			return nil, malformedNormalizedExtension()
		}
	}
	return map[string]any{"padding_length": len(data)}, nil
}
