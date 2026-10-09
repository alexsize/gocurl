package utlsengine

import "fmt"

type ja4ExtensionFields struct {
	extensions          []uint16
	version             uint16
	sni                 bool
	alpn                string
	signatureAlgorithms []uint16
}

func collectJA4ExtensionFields(h parsedClientHello) (fields ja4ExtensionFields, err error) {
	fields = ja4ExtensionFields{extensions: make([]uint16, 0, len(h.extensions)), version: h.legacyVersion, alpn: "00"}
	for _, extension := range h.extensions {
		if isGREASE(extension.id) {
			continue
		}
		switch extension.id {
		case 0:
			fields.sni = true
		case 16:
			protocols, parseErr := parseALPN(extension.data)
			if parseErr != nil {
				return fields, fmt.Errorf("ClientHello: ALPN extension: %w", parseErr)
			}
			if len(protocols) > 0 {
				fields.alpn = ja4ALPN(protocols[0])
			}
		case 13:
			var values []uint16
			values, err = parseUint16Vector(extension.data, 2)
			if err != nil {
				return fields, fmt.Errorf("ClientHello: signature algorithms: %w", err)
			}
			for _, value := range values {
				if !isGREASE(value) {
					fields.signatureAlgorithms = append(fields.signatureAlgorithms, value)
				}
			}
		case 43:
			versions, parseErr := parseUint16Vector(extension.data, 1)
			if parseErr != nil {
				return fields, fmt.Errorf("ClientHello: supported versions: %w", parseErr)
			}
			fields.version = 0
			for _, candidate := range versions {
				if !isGREASE(candidate) && candidate > fields.version {
					fields.version = candidate
				}
			}
		}
		if extension.id != 0 && extension.id != 16 {
			fields.extensions = append(fields.extensions, extension.id)
		}
	}

	return fields, nil
}
