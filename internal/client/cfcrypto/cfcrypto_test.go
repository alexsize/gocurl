// Cloudflare integration tests are opt-in; the default suite uses local fixtures.
package cfcrypto_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ameshkov/gocurl/internal/testutil"

	"github.com/AdguardTeam/dnsproxy/upstream"
	ctls "github.com/ameshkov/cfcrypto/tls"
	"github.com/ameshkov/gocurl/internal/client/cfcrypto"
	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/ameshkov/gocurl/internal/resolve"
	"github.com/cloudflare/circl/hpke"
	"github.com/stretchr/testify/require"
)

func TestECHHandshakeAcceptedByLocalServer(t *testing.T) {
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	publicKey, privateKey, err := kemScheme.GenerateKeyPair()
	require.NoError(t, err)
	publicKeyBytes, err := publicKey.MarshalBinary()
	require.NoError(t, err)
	privateKeyBytes, err := privateKey.MarshalBinary()
	require.NoError(t, err)

	var contents bytes.Buffer
	contents.WriteByte(1) // config_id
	require.NoError(t, binary.Write(&contents, binary.BigEndian, uint16(hpke.KEM_X25519_HKDF_SHA256)))
	require.NoError(t, binary.Write(&contents, binary.BigEndian, testutil.Uint16(len(publicKeyBytes))))
	contents.Write(publicKeyBytes)
	require.NoError(t, binary.Write(&contents, binary.BigEndian, uint16(4))) // cipher_suites length
	require.NoError(t, binary.Write(&contents, binary.BigEndian, uint16(1))) // HKDF-SHA256
	require.NoError(t, binary.Write(&contents, binary.BigEndian, uint16(1))) // AES-128-GCM
	contents.WriteByte(0)                                                    // maximum_name_length
	contents.WriteByte(byte(len("public.test")))
	contents.WriteString("public.test")
	require.NoError(t, binary.Write(&contents, binary.BigEndian, uint16(0))) // extensions length

	var rawConfig bytes.Buffer
	require.NoError(t, binary.Write(&rawConfig, binary.BigEndian, uint16(0xfe0d))) // ECH version
	require.NoError(t, binary.Write(&rawConfig, binary.BigEndian, testutil.Uint16(contents.Len())))
	rawConfig.Write(contents.Bytes())
	var serializedConfig bytes.Buffer
	require.NoError(t, binary.Write(&serializedConfig, binary.BigEndian, testutil.Uint16(rawConfig.Len())))
	serializedConfig.Write(rawConfig.Bytes())

	var serializedKey bytes.Buffer
	require.NoError(t, binary.Write(&serializedKey, binary.BigEndian, testutil.Uint16(len(privateKeyBytes))))
	serializedKey.Write(privateKeyBytes)
	require.NoError(t, binary.Write(&serializedKey, binary.BigEndian, testutil.Uint16(rawConfig.Len())))
	serializedKey.Write(rawConfig.Bytes())
	keys, err := ctls.EXP_UnmarshalECHKeys(serializedKey.Bytes())
	require.NoError(t, err)
	require.Len(t, keys, 1)
	provider, err := ctls.EXP_NewECHKeySet(keys)
	require.NoError(t, err)
	echConfigs, err := ctls.UnmarshalECHConfigs(serializedConfig.Bytes())
	require.NoError(t, err)
	require.Len(t, echConfigs, 1)

	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	t.Cleanup(func() { _ = serverConn.Close() })
	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, clientConn.SetDeadline(deadline))
	require.NoError(t, serverConn.SetDeadline(deadline))

	type handshakeResult struct {
		state ctls.ConnectionState
		err   error
	}
	serverResult := make(chan handshakeResult, 1)
	go func() {
		server := ctls.Server(serverConn, &ctls.Config{
			Certificates: []ctls.Certificate{
				{Certificate: certificate.Certificate, PrivateKey: certificate.PrivateKey, Leaf: certificate.Leaf},
			},
			MinVersion:        ctls.VersionTLS13,
			ECHEnabled:        true,
			ServerECHProvider: provider,
		})
		err := server.Handshake()
		serverResult <- handshakeResult{state: server.ConnectionState(), err: err}
	}()

	client := ctls.Client(clientConn, &ctls.Config{
		ServerName:         "private.test",
		InsecureSkipVerify: true,
		MinVersion:         ctls.VersionTLS13,
		ECHEnabled:         true,
		ClientECHConfigs:   echConfigs,
	})
	require.NoError(t, client.Handshake())
	serverHandshake := <-serverResult
	require.NoError(t, serverHandshake.err)
	require.True(t, client.ConnectionState().ECHAccepted, "client must confirm ECH acceptance")
	require.True(t, serverHandshake.state.ECHAccepted, "server must confirm ECH acceptance")
}

func TestHandshake_encryptedClientHello(t *testing.T) {
	requireNetworkIntegration(t)

	const relayDomain = "cloudflare-ech.com"
	const privateDomain = "cloudflare.com"
	const path = "cdn-cgi/trace"

	out, err := output.NewOutput("", false, false)
	require.NoError(t, err)

	cfg := &config.Config{ECH: true}

	r, err := resolve.NewResolver(cfg, out)
	require.NoError(t, err)

	echConfigs, err := r.LookupECHConfigs(relayDomain)
	require.NoError(t, err)
	require.NotEmpty(t, echConfigs)

	// Make sure that the resolved ECH configs will be used.
	cfg.ECHConfigs = echConfigs

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:443", relayDomain))
	require.NoError(t, err)

	tlsConf := &tls.Config{
		ServerName: privateDomain,
		NextProtos: []string{"http/1.1"},
	}

	tlsConn, err := cfcrypto.Handshake(conn, tlsConf, r, cfg, out)
	require.NoError(t, err)

	u := fmt.Sprintf("https://%s/%s", privateDomain, path)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	require.NoError(t, err)

	transport := &http.Transport{
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return tlsConn, nil
		},
	}
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NotEmpty(t, body)

	bodyStr := string(body)
	require.Contains(t, bodyStr, "sni=encrypted")
}

func TestHandshake_postQuantum(t *testing.T) {
	requireNetworkIntegration(t)

	const domainName = "cloudflare.com"
	const path = "cdn-cgi/trace"

	out, err := output.NewOutput("", false, false)
	require.NoError(t, err)

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:443", domainName))
	require.NoError(t, err)

	tlsConf := &tls.Config{
		ServerName: domainName,
		NextProtos: []string{"http/1.1"},
	}

	cfg := &config.Config{
		Experiments: map[config.Experiment]string{
			config.ExpPostQuantum: "",
		},
	}

	tlsConn, err := cfcrypto.Handshake(conn, tlsConf, nil, cfg, out)
	require.NoError(t, err)

	u := fmt.Sprintf("https://%s/%s", domainName, path)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	require.NoError(t, err)

	transport := &http.Transport{
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return tlsConn, nil
		},
	}

	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NotEmpty(t, body)

	bodyStr := string(body)
	require.Contains(t, bodyStr, "kex=X25519MLKEM768")
}

func TestHandshake_encryptedClientHelloLocal(t *testing.T) {
	const encodedECHConfig = "AEX+DQBBowAgACA+MDtQ9ShQuke+cqO01oHPiKeg1UDwoyeh5EL+9wfWQwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="
	echConfigBytes, err := base64.StdEncoding.DecodeString(encodedECHConfig)
	require.NoError(t, err)
	echConfigs, err := ctls.UnmarshalECHConfigs(echConfigBytes)
	require.NoError(t, err)
	require.NotEmpty(t, echConfigs)

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	t.Cleanup(func() { _ = serverConn.Close() })
	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, clientConn.SetDeadline(deadline))
	require.NoError(t, serverConn.SetDeadline(deadline))

	type captureResult struct {
		fingerprint utlsengine.Fingerprint
		err         error
	}
	serverResult := make(chan captureResult, 1)
	go func() {
		var handshake []byte
		for {
			recordHeader := make([]byte, 5)
			if _, readErr := io.ReadFull(serverConn, recordHeader); readErr != nil {
				serverResult <- captureResult{err: readErr}
				return
			}
			if recordHeader[0] != 22 {
				serverResult <- captureResult{err: fmt.Errorf("first client TLS record type is %d, want handshake", recordHeader[0])}
				return
			}
			record := make([]byte, int(recordHeader[3])<<8|int(recordHeader[4]))
			if _, readErr := io.ReadFull(serverConn, record); readErr != nil {
				serverResult <- captureResult{err: readErr}
				return
			}
			handshake = append(handshake, record...)
			if len(handshake) >= 4 {
				messageLength := 4 + (int(handshake[1]) << 16) + (int(handshake[2]) << 8) + int(handshake[3])
				if len(handshake) >= messageLength {
					fingerprint, parseErr := utlsengine.FingerprintClientHello(handshake[:messageLength])
					_, writeErr := serverConn.Write([]byte{21, 3, 3, 0, 2, 2, 40})
					if parseErr != nil {
						serverResult <- captureResult{err: parseErr}
					} else if writeErr != nil {
						serverResult <- captureResult{err: writeErr}
					} else {
						serverResult <- captureResult{fingerprint: fingerprint}
					}
					return
				}
			}
		}
	}()

	out, err := output.NewOutput("", false, false)
	require.NoError(t, err)
	dnsListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = dnsListener.Close() })
	dnsUpstream, err := upstream.AddressToUpstream(dnsListener.LocalAddr().String(), nil)
	require.NoError(t, err)
	cfg := &config.Config{ECH: true, ECHConfigs: echConfigs, DNSServers: []upstream.Upstream{dnsUpstream}}
	r, err := resolve.NewResolver(cfg, out)
	require.NoError(t, err)
	_, handshakeErr := cfcrypto.Handshake(clientConn, &tls.Config{
		ServerName: "private.example",
		NextProtos: []string{"http/1.1"},
	}, r, cfg, out)
	require.Error(t, handshakeErr, "the local peer intentionally rejects after receiving ClientHello")

	result := <-serverResult
	require.NoError(t, result.err)
	require.Contains(t, result.fingerprint.ExtensionOrder, uint16(0xfe0d), "ClientHello must carry the ECH extension")
}

func TestHandshake_postQuantumClientHelloLocal(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	t.Cleanup(func() { _ = serverConn.Close() })
	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, clientConn.SetDeadline(deadline))
	require.NoError(t, serverConn.SetDeadline(deadline))

	type captureResult struct {
		fingerprint utlsengine.Fingerprint
		err         error
	}
	serverResult := make(chan captureResult, 1)
	go func() {
		var handshake []byte
		for {
			recordHeader := make([]byte, 5)
			if _, readErr := io.ReadFull(serverConn, recordHeader); readErr != nil {
				serverResult <- captureResult{err: readErr}
				return
			}
			if recordHeader[0] != 22 {
				serverResult <- captureResult{err: fmt.Errorf("first client TLS record type is %d, want handshake", recordHeader[0])}
				return
			}
			record := make([]byte, int(recordHeader[3])<<8|int(recordHeader[4]))
			if _, readErr := io.ReadFull(serverConn, record); readErr != nil {
				serverResult <- captureResult{err: readErr}
				return
			}
			handshake = append(handshake, record...)
			if len(handshake) < 4 {
				continue
			}
			messageLength := 4 + (int(handshake[1]) << 16) + (int(handshake[2]) << 8) + int(handshake[3])
			if len(handshake) < messageLength {
				continue
			}
			fingerprint, parseErr := utlsengine.FingerprintClientHello(handshake[:messageLength])
			_, writeErr := serverConn.Write([]byte{21, 3, 3, 0, 2, 2, 40})
			if parseErr != nil {
				serverResult <- captureResult{err: parseErr}
			} else if writeErr != nil {
				serverResult <- captureResult{err: writeErr}
			} else {
				serverResult <- captureResult{fingerprint: fingerprint}
			}
			return
		}
	}()

	out, err := output.NewOutput("", false, false)
	require.NoError(t, err)
	cfg := &config.Config{
		Experiments: map[config.Experiment]string{config.ExpPostQuantum: ""},
	}
	_, handshakeErr := cfcrypto.Handshake(clientConn, &tls.Config{
		ServerName:         "pq.example",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}, nil, cfg, out)
	require.Error(t, handshakeErr, "the local peer intentionally rejects after receiving ClientHello")

	result := <-serverResult
	require.NoError(t, result.err)
	require.Contains(t, result.fingerprint.SupportedGroups, uint16(ctls.X25519MLKEM768),
		"ClientHello must offer the hybrid X25519MLKEM768 group when PQ is enabled")
}

func requireNetworkIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("GOCURL_NETWORK_INTEGRATION") != "1" {
		t.Skip("set GOCURL_NETWORK_INTEGRATION=1 to run tests against Cloudflare")
	}
}
