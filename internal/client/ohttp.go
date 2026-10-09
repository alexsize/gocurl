package client

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/chris-wood/ohttp-go"
)

// obliviousHTTPTransport is transport that uses Oblivious HTTP to encrypt
// requests before sending them to a gateway.
type obliviousHTTPTransport struct {
	base         Transport
	gatewayURL   *url.URL
	publicConfig ohttp.PublicConfig
	cfg          *config.Config
	out          *output.Output
}

// type check
var _ Transport = (*obliviousHTTPTransport)(nil)

// Conn returns the last established connection using this transport.
func (t *obliviousHTTPTransport) Conn() (conn net.Conn) {
	return t.base.Conn()
}

// RoundTrip implements the http.RoundTripper interface for
// *obliviousHTTPTransport. It encrypts the request using OHTTP and sends it to
// the gateway.
func (t *obliviousHTTPTransport) RoundTrip(r *http.Request) (resp *http.Response, err error) {
	r = r.Clone(withTLSLegContext(r.Context(), "gateway"))
	r = withTLSProfileCheckContext(r, t.cfg.TLSProfileCheck || t.cfg.OutputJSON, t.cfg.TLSProfileDocument)

	// Create an OHTTP client with the public configuration.
	client := ohttp.NewDefaultClient(t.publicConfig)

	// BinaryRequest encodes its path field from URL.Path, which excludes the
	// query component. Put the escaped request-target (path plus query) in a
	// cloned URL path so the Binary HTTP decoder reconstructs the complete URL.
	binaryHTTPReq := *r
	requestURL := *r.URL
	requestURL.Path = r.URL.RequestURI()
	requestURL.RawPath = ""
	requestURL.RawQuery = ""
	requestURL.ForceQuery = false
	binaryHTTPReq.URL = &requestURL
	binaryReq := (*ohttp.BinaryRequest)(&binaryHTTPReq)
	requestBytes, err := binaryReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize request: %w", err)
	}

	t.out.Debug("Encrypting request with OHTTP, original size: %d bytes", len(requestBytes))

	// Encrypt the request using OHTTP.
	encapsulatedReq, encapContext, err := client.EncapsulateRequest(requestBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encapsulate request: %w", err)
	}

	// Marshal the encapsulated request to bytes.
	encapsulatedReqBytes := encapsulatedReq.Marshal()
	t.out.Debug("Encrypted request size: %d bytes", len(encapsulatedReqBytes))

	// Create a new HTTP POST request to the gateway with the encrypted payload.
	gatewayReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodPost,
		t.gatewayURL.String(),
		bytes.NewReader(encapsulatedReqBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gateway request: %w", err)
	}

	// Set the content type for OHTTP requests.
	gatewayReq.Header.Set("Content-Type", "message/ohttp-req")

	t.out.Debug("Sending encrypted request to gateway: %s", t.gatewayURL.String())

	// Send the encrypted request to the gateway.
	gatewayResp, err := t.base.RoundTrip(gatewayReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to gateway: %w", err)
	}
	defer func() {
		_ = gatewayResp.Body.Close()
	}()

	// Verify the gateway response status.
	if gatewayResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned non-OK status: %s", gatewayResp.Status)
	}

	// Verify the gateway response content type.
	contentType := gatewayResp.Header.Get("Content-Type")
	if contentType != "message/ohttp-res" {
		t.out.Debug("Warning: unexpected Content-Type from gateway: %s (expected message/ohttp-res)", contentType)
	}

	// Read the encrypted response from the gateway.
	encapsulatedRespBytes, err := io.ReadAll(gatewayResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read gateway response: %w", err)
	}

	t.out.Debug("Received encrypted response from gateway, size: %d bytes", len(encapsulatedRespBytes))

	// Unmarshal the encapsulated response.
	encapsulatedResp, err := ohttp.UnmarshalEncapsulatedResponse(encapsulatedRespBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal encapsulated response: %w", err)
	}

	// Decrypt the response using OHTTP.
	decryptedResp, err := encapContext.DecapsulateResponse(encapsulatedResp)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate response: %w", err)
	}

	t.out.Debug("Decrypted response size: %d bytes", len(decryptedResp))

	// Parse the decrypted response as an HTTP response using BinaryResponse
	// format.
	resp, err = ohttp.UnmarshalBinaryResponse(decryptedResp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decrypted response: %w", err)
	}
	// Binary HTTP field names are lowercase on the wire. Normalize them to
	// net/http's canonical map keys so Header.Get and Header.Values work.
	canonicalHeaders := make(http.Header, len(resp.Header))
	for name, values := range resp.Header {
		canonicalName := textproto.CanonicalMIMEHeaderKey(name)
		canonicalHeaders[canonicalName] = append(canonicalHeaders[canonicalName], values...)
	}
	resp.Header = canonicalHeaders

	// bhttp may not set the status and proto fields, so we do it here.
	if resp.Proto == "" {
		resp.Proto = "OHTTP/1.0"
	}

	if resp.Status == "" {
		resp.Status = fmt.Sprintf("%d", resp.StatusCode)
	}
	resp.Request = r
	resp.TLS = gatewayResp.TLS

	return resp, nil
}

func newRoundTripper(
	hostname string,
	cfg *config.Config,
	out *output.Output,
) (rt http.RoundTripper, d *clientDialer, err error) {
	d, err = newDialer(hostname, cfg, out)
	if err != nil {
		return nil, nil, err
	}

	// Create transport for communicating with the hostname.
	rt, err = createHTTPTransport(d, cfg)
	if err != nil {
		return nil, nil, err
	}

	return rt, d, nil
}

// newObliviousHTTPTransport creates a new obliviousHTTPTransport.
func newObliviousHTTPTransport(
	cfg *config.Config,
	out *output.Output,
) (rt Transport, err error) {
	// Create base transport for requesting the KeyConfig.
	keyTransport, keyDialer, err := newRoundTripper(cfg.OHTTPKeysURL.Hostname(), cfg, out)
	if err != nil {
		return nil, fmt.Errorf("failed to create key transport: %w", err)
	}
	shareKeyTransport := sameOHTTPOrigin(cfg.OHTTPKeysURL, cfg.OHTTPGatewayURL)
	if shareKeyTransport {
		if httpTransport, ok := keyTransport.(*http.Transport); ok {
			httpTransport.DisableKeepAlives = false
		}
	}
	keepKeyTransport := false
	defer func() {
		if keepKeyTransport {
			return
		}
		if conn := keyDialer.currentConn(); conn != nil {
			_ = conn.Close()
		}
		if closer, ok := keyTransport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}()

	// Download the KeyConfig from the keys URL.
	out.Debug("Downloading OHTTP KeyConfig from: %s", cfg.OHTTPKeysURL.String())

	keyReq, err := http.NewRequest(http.MethodGet, cfg.OHTTPKeysURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OHTTP KeyConfig request: %w", err)
	}

	keyResp, err := keyTransport.RoundTrip(keyReq)
	if err != nil {
		return nil, fmt.Errorf("failed to download OHTTP KeyConfig: %w", err)
	}
	defer func() {
		_ = keyResp.Body.Close()
	}()

	if keyResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download OHTTP KeyConfig, status: %s", keyResp.Status)
	}

	keyConfigBytes, err := io.ReadAll(keyResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OHTTP KeyConfig: %w", err)
	}

	out.Debug("Downloaded OHTTP KeyConfig, size: %d bytes", len(keyConfigBytes))

	// Deserialize and validate the KeyConfig (PublicConfig).
	publicConfig, err := ohttp.UnmarshalPublicConfig(keyConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize OHTTP KeyConfig: %w", err)
	}

	out.Debug("OHTTP KeyConfig deserialized successfully, KeyID: %d", publicConfig.ID)

	// Reuse the keys connection when both endpoints have the same origin. This
	// matters for HTTP/2, where the key fetch and gateway request can share one
	// TLS connection without changing routing to a different origin.
	baseTransport := keyTransport
	d := keyDialer
	if shareKeyTransport {
		keepKeyTransport = true
	} else {
		baseTransport, d, err = newRoundTripper(cfg.OHTTPGatewayURL.Hostname(), cfg, out)
		if err != nil {
			return nil, fmt.Errorf("failed to create gateway transport: %w", err)
		}
	}

	return &obliviousHTTPTransport{
		base:         &transport{d: d, base: baseTransport},
		gatewayURL:   cfg.OHTTPGatewayURL,
		publicConfig: publicConfig,
		cfg:          cfg,
		out:          out,
	}, nil
}

func sameOHTTPOrigin(a, b *url.URL) bool {
	if a == nil || b == nil || !strings.EqualFold(a.Scheme, b.Scheme) ||
		!strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return ohttpPort(a) == ohttpPort(b)
}

func ohttpPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}
