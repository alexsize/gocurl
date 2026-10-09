package utlsengine

import (
	"reflect"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestApplyProfilePreservesErrorPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile Profile
		want    string
	}{
		{"versions before groups", Profile{SupportedVersions: []uint16{0x0304}, SupportedGroups: []uint16{29}}, "extension 0x002b"},
		{"groups before signatures", Profile{SupportedGroups: []uint16{29}, SignatureAlgorithms: []uint16{1027}}, "extension 0x000a"},
		{"signatures before ALPN", Profile{SignatureAlgorithms: []uint16{1027}, ALPN: []string{""}}, "extension 0x000d"},
		{"empty ALPN before order", Profile{ALPN: []string{""}, ExtensionOrder: []uint16{0, 16}}, "ALPN protocol length"},
		{"long ALPN before missing extension", Profile{ALPN: []string{strings.Repeat("x", 256)}}, "ALPN protocol length"},
		{"missing ALPN before order", Profile{ALPN: []string{"h2"}, ExtensionOrder: []uint16{0, 16}}, "no ALPN extension"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sni := &utls.SNIExtension{}
			spec := utls.ClientHelloSpec{Extensions: []utls.TLSExtension{sni}}
			err := applyProfile(&spec, "example.test", tc.profile)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("applyProfile() = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestApplyProfileKeepsGREASEMultiplicityAndOptionalPadding(t *testing.T) {
	sni := &utls.SNIExtension{}
	alpn := &utls.ALPNExtension{AlpnProtocols: []string{"h2"}}
	padding := &utls.UtlsPaddingExtension{WillPad: false}
	grease1 := &utls.UtlsGREASEExtension{}
	grease2 := &utls.UtlsGREASEExtension{}
	spec := utls.ClientHelloSpec{Extensions: []utls.TLSExtension{sni, alpn, padding, grease1, grease2}}
	profile := Profile{ExtensionOrder: []uint16{0x1a1a, 16, 0, 0x2a2a}, ALPN: []string{"http/1.1"}}
	if err := applyProfile(&spec, "example.test", profile); err != nil {
		t.Fatal(err)
	}
	want := []utls.TLSExtension{grease1, alpn, sni, grease2}
	if !reflect.DeepEqual(spec.Extensions, want) || sni.ServerName != "example.test" {
		t.Fatalf("extensions = %#v, SNI = %q", spec.Extensions, sni.ServerName)
	}
	profile.ALPN[0] = "changed"
	if !reflect.DeepEqual(alpn.AlpnProtocols, []string{"http/1.1"}) {
		t.Fatal("ALPN extension aliases the profile")
	}
}

func TestApplyProfileRejectsActivePaddingOmission(t *testing.T) {
	spec := utls.ClientHelloSpec{Extensions: []utls.TLSExtension{
		&utls.SNIExtension{}, &utls.UtlsPaddingExtension{WillPad: true},
	}}
	err := applyProfile(&spec, "example.test", Profile{ExtensionOrder: []uint16{0}})
	if err == nil || !strings.Contains(err.Error(), "preset has 2 active extensions") {
		t.Fatalf("applyProfile() = %v", err)
	}
}

func TestApplyProfileRejectsExtraGREASEOccurrence(t *testing.T) {
	spec := utls.ClientHelloSpec{Extensions: []utls.TLSExtension{
		&utls.SNIExtension{}, &utls.ALPNExtension{},
		&utls.UtlsGREASEExtension{}, &utls.UtlsGREASEExtension{},
	}}
	err := applyProfile(&spec, "example.test", Profile{ExtensionOrder: []uint16{0, 0x0a0a, 0x1a1a, 0x2a2a}})
	if err == nil || !strings.Contains(err.Error(), "extension ID 0x2a2a is not supported") {
		t.Fatalf("applyProfile() = %v", err)
	}
}

func TestApplyProfileCopiesTLSOverrides(t *testing.T) {
	versions := &utls.SupportedVersionsExtension{}
	groups := &utls.SupportedCurvesExtension{}
	signatures := &utls.SignatureAlgorithmsExtension{}
	spec := utls.ClientHelloSpec{Extensions: []utls.TLSExtension{versions, groups, signatures}}
	profile := Profile{
		CipherSuites: []uint16{0x1301}, SupportedVersions: []uint16{0x0304},
		SupportedGroups: []uint16{29}, SignatureAlgorithms: []uint16{1027},
	}
	if err := applyProfile(&spec, "", profile); err != nil {
		t.Fatal(err)
	}
	profile.CipherSuites[0] = 0
	profile.SupportedVersions[0] = 0
	profile.SupportedGroups[0] = 0
	profile.SignatureAlgorithms[0] = 0
	if !reflect.DeepEqual(spec.CipherSuites, []uint16{0x1301}) ||
		!reflect.DeepEqual(versions.Versions, []uint16{0x0304}) ||
		!reflect.DeepEqual(groups.Curves, []utls.CurveID{29}) ||
		!reflect.DeepEqual(signatures.SupportedSignatureAlgorithms, []utls.SignatureScheme{1027}) {
		t.Fatal("TLS extensions alias the profile or lose overrides")
	}
}
