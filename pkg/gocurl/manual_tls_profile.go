package gocurl

import (
	"fmt"
	"slices"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/ameshkov/gocurl/internal/config"
)

func applyAPIManualTLSProfile(cfg *config.Config, request Request) error {
	if request.TLSProfile == nil || request.TLSProfile.ClientHello == nil {
		return nil
	}
	{
		manual := request.TLSProfile.ClientHello
		if cfg.RequestURL.Scheme != "https" {
			return fmt.Errorf("gocurl API: manual TLS ClientHello profiles require an https URL")
		}
		if cfg.ForceHTTP3 {
			return fmt.Errorf("gocurl API: manual TCP TLS ClientHello profiles cannot be used with HTTP/3")
		}
		switch {
		case cfg.ForceHTTP11:
			if len(manual.ALPN) > 0 && (len(manual.ALPN) != 1 || manual.ALPN[0] != "http/1.1") {
				return fmt.Errorf("gocurl API: manual TLS profile ALPN is incompatible with HTTP/1.1")
			}
		case cfg.ForceHTTP2:
			if len(manual.ALPN) > 0 && (len(manual.ALPN) != 1 || manual.ALPN[0] != "h2") {
				return fmt.Errorf("gocurl API: manual TLS profile ALPN is incompatible with HTTP/2")
			}
		default:
			if len(manual.ALPN) == 0 || slices.Contains(manual.ALPN, "h2") {
				return fmt.Errorf(
					"gocurl API: manual TLS profile with an empty or h2 ALPN requires HTTPVersion 1.1 or 2",
				)
			}
			if len(manual.ALPN) != 1 || manual.ALPN[0] != "http/1.1" {
				return fmt.Errorf(
					"gocurl API: manual TLS profile ALPN is incompatible with automatic HTTP negotiation",
				)
			}
		}
		profile := utlsengine.Profile{
			Preset:              manual.Preset,
			CipherSuites:        append([]uint16(nil), manual.CipherSuites...),
			SupportedVersions:   append([]uint16(nil), manual.SupportedVersions...),
			SupportedGroups:     append([]uint16(nil), manual.SupportedGroups...),
			SignatureAlgorithms: append([]uint16(nil), manual.SignatureAlgorithms...),
			ExtensionOrder:      append([]uint16(nil), manual.ExtensionOrder...),
			ALPN:                append([]string(nil), manual.ALPN...),
		}
		serverName := request.TLSServerName
		if serverName == "" {
			serverName = manual.ServerName
		}
		if serverName == "" {
			serverName = cfg.RequestURL.Hostname()
		}
		if err := utlsengine.ValidateProfile(profile, serverName); err != nil {
			return fmt.Errorf("gocurl API: invalid manual ClientHello profile: %w", err)
		}
		cfg.TLSProfile = &profile
	}
	return nil
}
