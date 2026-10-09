package gocurl

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
)

func requestArgs(request Request) ([]string, error) {
	if request.URL == "" {
		return nil, fmt.Errorf("gocurl API: URL is required")
	}
	if request.PostQuantum {
		requestURL, err := url.Parse(request.URL)
		if err != nil {
			return nil, fmt.Errorf("gocurl API: parse URL for post-quantum TLS: %w", err)
		}
		if !strings.EqualFold(requestURL.Scheme, "https") {
			return nil, fmt.Errorf("gocurl API: post-quantum TLS requires an https URL")
		}
	}
	args := make([]string, 0, 12+len(request.Headers)*2)
	// Keep builders ordered: the first invalid option must retain its original error.
	for _, appendArgs := range []func([]string, Request) ([]string, error){
		appendManualTLSArgs,
		appendTLSVersionArgs,
		appendRequestMetadataArgs,
		appendHTTP2Args,
		appendHTTP3Args,
		appendQUICArgs,
		appendRoutingArgs,
		appendDNSArgs,
		appendConnectionPolicyArgs,
		appendOHTTPArgs,
		appendTLSWireArgs,
		appendHTTPVersionArgs,
		appendProfileHeaderArgs,
	} {
		var err error
		args, err = appendArgs(args, request)
		if err != nil {
			return nil, err
		}
	}
	return append(args, request.URL), nil
}

func appendManualTLSArgs(args []string, request Request) ([]string, error) {
	if p := request.TLSProfile; p != nil && p.ClientHello != nil {
		if p.ProfilePath != "" {
			return nil, fmt.Errorf(
				"gocurl API: TLSProfile.ProfilePath and TLSProfile.ClientHello are mutually exclusive",
			)
		}
		if p.Check || p.Strict {
			return nil, fmt.Errorf(
				"gocurl API: manual TLSProfile.ClientHello cannot use Check or Strict without imported expectations",
			)
		}
		if request.TLSMinVersion != "" || request.TLSMaxVersion != "" || len(request.TLSCipherSuites) != 0 ||
			request.PostQuantum {
			return nil, fmt.Errorf(
				"gocurl API: TLSProfile.ClientHello cannot be combined with TLS version, cipher-suite, or post-quantum overrides",
			)
		}
		if request.TLSServerName != "" && p.ClientHello.ServerName != "" &&
			request.TLSServerName != p.ClientHello.ServerName {
			return nil, fmt.Errorf("gocurl API: TLSServerName conflicts with TLSProfile.ClientHello.ServerName")
		}
		if p.ClientHello.ServerName != "" && request.TLSServerName == "" {
			args = append(args, "--tls-servername="+p.ClientHello.ServerName)
		}
	}
	return args, nil
}

func appendTLSVersionArgs(args []string, request Request) ([]string, error) {
	if request.TLSServerName != "" {
		args = append(args, "--tls-servername="+request.TLSServerName)
	}
	switch request.TLSMinVersion {
	case "":
	case "1.2":
		args = append(args, "--tlsv1.2")
	case "1.3":
		args = append(args, "--tlsv1.3")
	default:
		return nil, fmt.Errorf("gocurl API: unsupported TLSMinVersion %q; use 1.2 or 1.3", request.TLSMinVersion)
	}
	if request.TLSMaxVersion != "" {
		if request.TLSMaxVersion != "1.2" && request.TLSMaxVersion != "1.3" {
			return nil, fmt.Errorf("gocurl API: unsupported TLSMaxVersion %q; use 1.2 or 1.3", request.TLSMaxVersion)
		}
		args = append(args, "--tls-max="+request.TLSMaxVersion)
	}
	if request.TLSMinVersion == "1.3" && request.TLSMaxVersion == "1.2" {
		return nil, fmt.Errorf("gocurl API: TLSMinVersion 1.3 cannot exceed TLSMaxVersion 1.2")
	}
	if len(request.TLSCipherSuites) != 0 {
		for _, name := range request.TLSCipherSuites {
			if strings.TrimSpace(name) != name || name == "" || strings.ContainsAny(name, " \t\r\n") {
				return nil, fmt.Errorf(
					"gocurl API: TLSCipherSuites entries must be non-empty cipher names without whitespace",
				)
			}
		}
		args = append(args, "--ciphers="+strings.Join(request.TLSCipherSuites, " "))
	}
	if request.PostQuantum {
		args = append(args, "--experiment=pq")
	}
	return args, nil
}

func appendRequestMetadataArgs(args []string, request Request) ([]string, error) {
	if request.Method != "" {
		args = append(args, "--request", request.Method)
	}
	if request.RequestTarget != "" {
		args = append(args, "--request-target="+request.RequestTarget)
	}
	if request.NoDefaultHeaders {
		args = append(args, "--no-default-headers")
	}
	for _, name := range request.JSONRedactHeaders {
		args = append(args, "--json-redact-header="+name)
	}
	return args, nil
}

func appendHTTP2Args(args []string, request Request) ([]string, error) {
	if v := request.HTTP2Settings.HeaderTableSize; v != 0 {
		args = append(args, fmt.Sprintf("--h2-header-table-size=%d", v))
	}
	if v := request.HTTP2Settings.MaxFrameSize; v != 0 {
		args = append(args, fmt.Sprintf("--h2-max-frame-size=%d", v))
	}
	if v := request.HTTP2Settings.MaxHeaderListSize; v != 0 {
		args = append(args, fmt.Sprintf("--h2-max-header-list-size=%d", v))
	}
	if len(request.HTTP2PseudoOrder) != 0 {
		args = append(args, "--h2-pseudo-order="+strings.Join(request.HTTP2PseudoOrder, ","))
	}
	if len(request.HTTP2SettingsOrder) != 0 {
		args = append(args, "--h2-settings-order="+strings.Join(request.HTTP2SettingsOrder, ","))
	}
	if request.HTTP2DataFrameSize != 0 {
		args = append(args, fmt.Sprintf("--h2-data-frame-size=%d", request.HTTP2DataFrameSize))
	}
	if request.HTTP2HeaderFrameSize != 0 {
		args = append(args, fmt.Sprintf("--h2-header-frame-size=%d", request.HTTP2HeaderFrameSize))
	}
	if request.HTTP2FramePadding != 0 {
		args = append(args, fmt.Sprintf("--h2-frame-padding=%d", request.HTTP2FramePadding))
	}
	if len(request.HTTP2HeaderOrder) != 0 {
		args = append(args, "--h2-header-order="+strings.Join(request.HTTP2HeaderOrder, ","))
	}
	if p := request.HTTP2Priority; p != nil {
		args = append(args, fmt.Sprintf("--h2-priority=%d:%d:%t", p.Dependency, p.Weight, p.Exclusive))
	}
	return args, nil
}

func appendHTTP3Args(args []string, request Request) ([]string, error) {
	if len(request.HTTP3AdditionalSettings) != 0 {
		ids := make([]uint64, 0, len(request.HTTP3AdditionalSettings))
		for id := range request.HTTP3AdditionalSettings {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			args = append(args, fmt.Sprintf("--h3-setting=%d=%d", id, request.HTTP3AdditionalSettings[id]))
		}
	}
	if request.HTTP3Datagrams {
		args = append(args, "--h3-datagrams")
	}
	return args, nil
}

func appendQUICArgs(args []string, request Request) ([]string, error) {
	if p := request.QUICTransport; p != (QUICTransport{}) {
		args = appendQUICReceiveArgs(args, p)
		var err error
		args, err = appendQUICLimitsArgs(args, p)
		if err != nil {
			return nil, err
		}
		args, err = appendQUICWireArgs(args, p)
		if err != nil {
			return nil, err
		}
	}
	if len(request.QUICTransportParameterOrder) != 0 {
		ids := make([]string, len(request.QUICTransportParameterOrder))
		for i, id := range request.QUICTransportParameterOrder {
			ids[i] = fmt.Sprintf("0x%x", id)
		}
		args = append(args, "--quic-transport-parameter-order="+strings.Join(ids, ","))
	}
	return args, nil
}

func appendQUICReceiveArgs(args []string, p QUICTransport) []string {
	if p.InitialStreamReceiveWindow != 0 {
		args = append(args, fmt.Sprintf("--quic-initial-stream-window=%d", p.InitialStreamReceiveWindow))
	}
	if p.InitialMaxStreamDataBidiLocal != nil {
		args = append(
			args,
			fmt.Sprintf("--quic-initial-max-stream-data-bidi-local=%d", *p.InitialMaxStreamDataBidiLocal),
		)
	}
	if p.InitialMaxStreamDataBidiRemote != nil {
		args = append(
			args,
			fmt.Sprintf("--quic-initial-max-stream-data-bidi-remote=%d", *p.InitialMaxStreamDataBidiRemote),
		)
	}
	if p.InitialMaxStreamDataUni != nil {
		args = append(args, fmt.Sprintf("--quic-initial-max-stream-data-uni=%d", *p.InitialMaxStreamDataUni))
	}
	if p.InitialConnectionReceiveWindow != 0 {
		args = append(args, fmt.Sprintf("--quic-initial-connection-window=%d", p.InitialConnectionReceiveWindow))
	}
	return args
}

func appendQUICLimitsArgs(args []string, p QUICTransport) ([]string, error) {
	if p.MaxIdleTimeout != 0 {
		if p.MaxIdleTimeout%time.Millisecond != 0 {
			return nil, fmt.Errorf("gocurl API: QUIC MaxIdleTimeout must be a whole number of milliseconds")
		}
		args = append(args, fmt.Sprintf("--quic-max-idle-timeout-ms=%d", p.MaxIdleTimeout/time.Millisecond))
	}
	if p.MaxIncomingStreams != 0 {
		args = append(args, fmt.Sprintf("--quic-max-incoming-streams=%d", p.MaxIncomingStreams))
	}
	if p.MaxIncomingUniStreams != 0 {
		args = append(args, fmt.Sprintf("--quic-max-incoming-uni-streams=%d", p.MaxIncomingUniStreams))
	}
	if p.Version != "" {
		args = append(args, "--quic-version="+p.Version)
	}
	if p.InitialPacketSize != 0 {
		args = append(args, fmt.Sprintf("--quic-initial-packet-size=%d", p.InitialPacketSize))
	}
	if p.ConnectionIDLength != 0 {
		args = append(args, fmt.Sprintf("--quic-connection-id-length=%d", p.ConnectionIDLength))
	}
	if p.ActiveConnectionIDLimit != 0 {
		args = append(args, fmt.Sprintf("--quic-active-connection-id-limit=%d", p.ActiveConnectionIDLimit))
	}
	return args, nil
}

func appendQUICWireArgs(args []string, p QUICTransport) ([]string, error) {
	if p.AckDelayExponent != nil {
		args = append(args, fmt.Sprintf("--quic-ack-delay-exponent=%d", *p.AckDelayExponent))
	}
	if p.MaxAckDelay != nil {
		if *p.MaxAckDelay < 0 || *p.MaxAckDelay%time.Millisecond != 0 {
			return nil, fmt.Errorf(
				"gocurl API: QUIC MaxAckDelay must be a non-negative whole number of milliseconds",
			)
		}
		args = append(args, fmt.Sprintf("--quic-max-ack-delay-ms=%d", *p.MaxAckDelay/time.Millisecond))
	}
	if p.MaxUDPPayloadSize != 0 {
		args = append(args, fmt.Sprintf("--quic-max-udp-payload-size=%d", p.MaxUDPPayloadSize))
	}
	if p.EnableResetStreamAt {
		args = append(args, "--quic-reset-stream-at")
	}
	if p.DisableActiveMigration {
		args = append(args, "--quic-disable-active-migration")
	}
	return args, nil
}

func appendRoutingArgs(args []string, request Request) ([]string, error) {
	if request.ProxyURL != "" {
		args = append(args, "--proxy", request.ProxyURL)
	}
	if request.ProxyInsecure {
		args = append(args, "--proxy-insecure")
	}
	if request.ConnectTimeout < 0 || request.ConnectTimeout%time.Second != 0 {
		return nil, fmt.Errorf("gocurl API: ConnectTimeout must be zero or a non-negative whole number of seconds")
	}
	if request.ConnectTimeout > 0 {
		args = append(args, "--connect-timeout", fmt.Sprintf("%d", request.ConnectTimeout/time.Second))
	}
	for _, mapping := range request.ConnectTo {
		args = append(args, "--connect-to", mapping)
	}
	if len(request.Resolve) != 0 {
		hosts := make([]string, 0, len(request.Resolve))
		for host := range request.Resolve {
			hosts = append(hosts, host)
		}
		slices.Sort(hosts)
		for _, host := range hosts {
			addresses := request.Resolve[host]
			if host == "" || len(addresses) == 0 {
				return nil, fmt.Errorf("gocurl API: Resolve requires a host and at least one IP address")
			}
			for _, address := range addresses {
				if net.ParseIP(address) == nil {
					return nil, fmt.Errorf("gocurl API: invalid Resolve IP address %q for host %q", address, host)
				}
			}
			args = append(args, "--resolve="+host+":0:"+strings.Join(addresses, ","))
		}
	}
	return args, nil
}

func appendDNSArgs(args []string, request Request) ([]string, error) {
	switch request.IPVersion {
	case "":
	case "4":
		args = append(args, "--ipv4")
	case "6":
		args = append(args, "--ipv6")
	default:
		return nil, fmt.Errorf("gocurl API: unsupported IPVersion %q; use 4 or 6", request.IPVersion)
	}
	if len(request.DNSServers) != 0 {
		for _, server := range request.DNSServers {
			if server == "" || strings.TrimSpace(server) != server || strings.Contains(server, ",") {
				return nil, fmt.Errorf(
					"gocurl API: DNSServers entries must be non-empty DNS addresses without commas or surrounding whitespace",
				)
			}
		}
		args = append(args, "--dns-servers="+strings.Join(request.DNSServers, ","))
	}
	return args, nil
}

func appendConnectionPolicyArgs(args []string, request Request) ([]string, error) {
	if request.ProxyHTTP2Connect {
		args = append(args, "--proxy-http2-connect")
	}
	if request.Insecure {
		args = append(args, "--insecure")
	}
	if request.ECH {
		args = append(args, "--ech")
	}
	if request.ECHGrease {
		args = append(args, "--echgrease")
	}
	if request.ECHConfig != "" {
		args = append(args, "--echconfig="+request.ECHConfig)
	}
	return args, nil
}

func appendOHTTPArgs(args []string, request Request) ([]string, error) {
	if request.OHTTPGatewayURL != "" || request.OHTTPKeysURL != "" {
		if request.OHTTPGatewayURL == "" || request.OHTTPKeysURL == "" {
			return nil, fmt.Errorf("gocurl API: OHTTPGatewayURL and OHTTPKeysURL must be specified together")
		}
		args = append(args,
			"--ohttp-gateway-url="+request.OHTTPGatewayURL,
			"--ohttp-keys-url="+request.OHTTPKeysURL,
		)
	}
	return args, nil
}

func appendTLSWireArgs(args []string, request Request) ([]string, error) {
	if request.TLSRandom != nil {
		if len(request.TLSRandom) != 32 {
			return nil, fmt.Errorf(
				"gocurl API: TLSRandom must contain exactly 32 bytes (got %d)",
				len(request.TLSRandom),
			)
		}
		args = append(args, "--tls-random="+base64.StdEncoding.EncodeToString(request.TLSRandom))
	}
	if split := request.TLSSplitHello; split != nil {
		if split.FirstChunkSize <= 0 {
			return nil, fmt.Errorf("gocurl API: TLSSplitHello.FirstChunkSize must be positive")
		}
		if split.Delay < 0 || split.Delay%time.Millisecond != 0 {
			return nil, fmt.Errorf(
				"gocurl API: TLSSplitHello.Delay must be a non-negative whole number of milliseconds",
			)
		}
		args = append(args, fmt.Sprintf("--tls-split-hello=%d:%d", split.FirstChunkSize, split.Delay/time.Millisecond))
	}
	return args, nil
}

func appendHTTPVersionArgs(args []string, request Request) ([]string, error) {
	if request.PostQuantum && request.HTTPVersion == "3" {
		return nil, fmt.Errorf("gocurl API: post-quantum TLS is unavailable with HTTP/3")
	}
	switch request.HTTPVersion {
	case "":
	case "1.1":
		args = append(args, "--http1.1")
	case "2":
		args = append(args, "--http2")
	case "3":
		args = append(args, "--http3")
	default:
		return nil, fmt.Errorf("gocurl API: unsupported HTTPVersion %q; use 1.1, 2, or 3", request.HTTPVersion)
	}
	return args, nil
}

func appendProfileHeaderArgs(args []string, request Request) ([]string, error) {
	if request.TLSProfile != nil {
		p := request.TLSProfile
		if p.ProfilePath != "" {
			args = append(args, "--tls-profile", p.ProfilePath)
		}
		if p.Strict {
			args = append(args, "--tls-profile-strict")
		} else if p.Check {
			args = append(args, "--tls-profile-check")
		}
		if p.ProxyProfilePath != "" {
			args = append(args, "--proxy-tls-profile", p.ProxyProfilePath)
		}
		if p.ProxyStrict {
			args = append(args, "--proxy-tls-profile-strict")
		} else if p.ProxyCheck {
			args = append(args, "--proxy-tls-profile-check")
		}
	}
	for _, header := range request.Headers {
		args = append(args, "--header", header.Name+":"+header.Value)
	}
	return args, nil
}
