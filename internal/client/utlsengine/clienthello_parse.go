package utlsengine

import (
	"encoding/binary"
	"fmt"
)

func parseClientHelloExtensions(hello *parsedClientHello, data []byte) error {
	extensionBytes, rest, err := readVector(data, 2)
	if err != nil {
		return fmt.Errorf("ClientHello: extensions: %w", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("ClientHello: %d unexpected trailing bytes", len(rest))
	}
	for len(extensionBytes) > 0 {
		if len(extensionBytes) < 4 {
			return fmt.Errorf("ClientHello: truncated extension header")
		}
		id := binary.BigEndian.Uint16(extensionBytes[:2])
		extensionLength := int(binary.BigEndian.Uint16(extensionBytes[2:4]))
		extensionBytes = extensionBytes[4:]
		if extensionLength > len(extensionBytes) {
			return fmt.Errorf(
				"ClientHello: extension 0x%04x length %d exceeds remaining data",
				id,
				extensionLength,
			)
		}
		extension := parsedExtension{
			id:   id,
			data: extensionBytes[:extensionLength],
		}
		if err = parseClientHelloExtensionFields(hello, extension); err != nil {
			return err
		}
		hello.extensions = append(hello.extensions, extension)
		extensionBytes = extensionBytes[extensionLength:]
	}

	return nil
}

func parseClientHelloExtensionFields(hello *parsedClientHello, extension parsedExtension) error {
	id := extension.id
	switch id {
	case 10, 13:
		values, parseErr := parseUint16Vector(extension.data, 2)
		if parseErr != nil {
			return fmt.Errorf("ClientHello: extension 0x%04x: %w", id, parseErr)
		}
		if id == 10 {
			hello.supportedGroups = values
		} else {
			hello.signatureAlgorithms = values
		}
	case 11:
		if _, rest, parseErr := readVector(extension.data, 1); parseErr != nil || len(rest) != 0 {
			if parseErr == nil {
				parseErr = fmt.Errorf("trailing bytes after point formats")
			}
			return fmt.Errorf("ClientHello: extension 0x%04x: %w", id, parseErr)
		}
	case 16:
		if _, parseErr := parseALPN(extension.data); parseErr != nil {
			return fmt.Errorf("ClientHello: extension 0x%04x: %w", id, parseErr)
		}
	case 43:
		values, parseErr := parseUint16Vector(extension.data, 1)
		if parseErr != nil {
			return fmt.Errorf("ClientHello: extension 0x%04x: %w", id, parseErr)
		}
		hello.supportedVersions = values
	}
	return nil
}
