package utlsengine

import (
	"errors"
	"fmt"

	utls "github.com/refraction-networking/utls"
)

func applyProfileALPN(extensions map[uint16][]utls.TLSExtension, protocols []string) error {
	if len(protocols) > 0 {
		for _, protocol := range protocols {
			if len(protocol) == 0 || len(protocol) > 255 {
				return fmt.Errorf("uTLS: ALPN protocol length must be between 1 and 255 bytes; got %d", len(protocol))
			}
		}
		var alpn *utls.ALPNExtension
		for _, extension := range extensions[16] {
			if candidate, ok := extension.(*utls.ALPNExtension); ok {
				alpn = candidate
				break
			}
		}
		if alpn == nil {
			return errors.New("uTLS: selected preset has no ALPN extension")
		}
		alpn.AlpnProtocols = append([]string(nil), protocols...)
	}
	return nil
}

func applyProfileExtensionOrder(
	spec *utls.ClientHelloSpec,
	extensions map[uint16][]utls.TLSExtension,
	profile Profile,
) error {
	if len(profile.ExtensionOrder) == 0 {
		return nil
	}
	availableExtensionCount := len(spec.Extensions)
	for _, extension := range spec.Extensions {
		if padding, ok := extension.(*utls.UtlsPaddingExtension); ok && !padding.WillPad {
			availableExtensionCount--
		}
	}
	if len(profile.ExtensionOrder) != availableExtensionCount {
		return fmt.Errorf(
			"uTLS: extension order has %d entries; preset has %d active extensions",
			len(profile.ExtensionOrder),
			availableExtensionCount,
		)
	}

	ordered := make([]utls.TLSExtension, 0, len(profile.ExtensionOrder))
	used := make(map[uint16]int, len(profile.ExtensionOrder))
	for _, requestedID := range profile.ExtensionOrder {
		id := normalizeGREASE(requestedID)
		variants := extensions[id]
		index := used[id]
		if index >= len(variants) {
			return fmt.Errorf("uTLS: extension ID 0x%04x is not supported by preset %q", requestedID, profile.Preset)
		}
		used[id] = index + 1
		ordered = append(ordered, variants[index])
	}
	for id, variants := range extensions {
		if used[id] == len(variants) {
			continue
		}
		for _, extension := range variants[used[id]:] {
			padding, ok := extension.(*utls.UtlsPaddingExtension)
			if !ok || padding.WillPad {
				return fmt.Errorf("uTLS: extension order omits extension ID 0x%04x", id)
			}
		}
	}
	spec.Extensions = ordered

	return nil
}
