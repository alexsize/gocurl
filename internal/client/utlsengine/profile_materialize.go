package utlsengine

import (
	"fmt"

	utls "github.com/refraction-networking/utls"
)

func (p ClientProfile) materializeTLSFields(
	spec *utls.ClientHelloSpec,
	result *Profile,
	unsupported []string,
) []string {
	// Do not materialize cipher suites the exporter marks as non-replayable.
	if len(p.Fields.CipherSuites) > 0 && !contains(unsupported, "fields.cipher_suites") {
		if len(spec.CipherSuites) == 0 {
			unsupported = appendUnique(unsupported, "fields.cipher_suites")
		} else {
			result.CipherSuites = append([]uint16(nil), p.Fields.CipherSuites...)
		}
	}
	for _, field := range []struct {
		path        string
		extension   uint16
		values      []uint16
		materialize func([]uint16)
	}{
		{path: "fields.supported_versions", extension: 43, values: p.Fields.SupportedVersions, materialize: func(v []uint16) { result.SupportedVersions = append([]uint16(nil), v...) }},
		{path: "fields.supported_groups", extension: 10, values: p.Fields.SupportedGroups, materialize: func(v []uint16) { result.SupportedGroups = append([]uint16(nil), v...) }},
		{path: "fields.signature_algorithms", extension: 13, values: p.Fields.SignatureAlgorithms, materialize: func(v []uint16) { result.SignatureAlgorithms = append([]uint16(nil), v...) }},
	} {
		if len(field.values) == 0 {
			continue
		}
		if contains(unsupported, field.path) {
			continue
		}
		if countProfileExtensions(spec.Extensions, field.extension) != 1 {
			unsupported = appendUnique(unsupported, field.path)
			continue
		}
		field.materialize(field.values)
	}
	return unsupported
}

func (p ClientProfile) materializeProtocolFields(result *Profile, unsupported []string) []string {
	if len(p.Fields.ALPN) != 0 && !contains(p.Replayability.Unsupported, "fields.alpn") {
		result.ALPN = append([]string(nil), p.Fields.ALPN...)
	}
	if len(p.Fields.CustomALPN) != 0 && !contains(p.Replayability.Unsupported, "fields.custom_alpn") {
		result.ALPN = append([]string(nil), p.Fields.CustomALPN...)
	}
	if p.Fields.ALPSPolicy != "" || len(p.Fields.ALPS) != 0 || len(p.Fields.CustomALPS) != 0 {
		for _, field := range []string{"fields.alps", "fields.alps_policy", "fields.custom_alps"} {
			unsupported = appendUnique(unsupported, field)
		}
	}
	if p.Fields.ALPNPolicy == "DOWNSTREAM" || p.Fields.ALPNPolicy == "INTERSECTION" {
		unsupported = appendUnique(unsupported, "fields.alpn_policy")
	}
	if p.Fields.PaddingLength != nil {
		unsupported = appendUnique(unsupported, "fields.padding_length")
	}
	return unsupported
}

func (p ClientProfile) validateMaterializedMUST(result Profile, unsupported []string) error {
	for _, path := range p.Policy.MustMatch {
		if !supportedMustField(path) {
			return &UnsupportedProfileError{Field: path}
		}
		if path == "fields.extension_order" && len(p.Fields.ExtensionOrder) == 0 {
			return fmt.Errorf("client profile MUST field %q has no value", path)
		}
		if path == "fields.alpn" && len(result.ALPN) == 0 {
			return fmt.Errorf("client profile MUST field %q has no materializable value", path)
		}
		switch path {
		case "fields.cipher_suites",
			"fields.supported_versions",
			"fields.supported_groups",
			"fields.signature_algorithms":
			if len(profileFieldValues(p.Fields, path)) == 0 {
				return fmt.Errorf("client profile MUST field %q has no value", path)
			}
		}
		if contains(unsupported, path) {
			return &UnsupportedProfileError{Field: path}
		}
	}
	return nil
}
