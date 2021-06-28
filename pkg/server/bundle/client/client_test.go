package client

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

var (
	trustDomain = spiffeid.RequireTrustDomainFromString("domain.test")
	serverID    = spiffeid.RequireFromString("spiffe://domain.test/spiffe-bundle-endpoint-server")
)

func TestClient(t *testing.T) {
	testCases := []struct {
		name             string
		expectedID       spiffeid.ID
		serverID         spiffeid.ID
		status           int
		body             string
		deprecatedConfig bool
		newClientErr     string
		fetchBundleErr   string
	}{
		{
			name:   "success",
			status: http.StatusOK,
			// We don't need a really elaborate body here. this test just
			// makes sure we unmarshal the body. The unmarshal tests will
			// provide the coverage for unmarshaling code.
			body:       `{"spiffe_refresh_hint": 10}`,
			serverID:   serverID,
			expectedID: serverID,
		},
		{
			name:             "success - deprecated config",
			status:           http.StatusOK,
			body:             `{"spiffe_refresh_hint": 10}`,
			serverID:         serverID,
			expectedID:       serverID,
			deprecatedConfig: true,
		},
		{
			name:             "wrong default SPIFFE ID - deprecated config",
			status:           http.StatusOK,
			body:             `{"spiffe_refresh_hint": 10}`,
			deprecatedConfig: true,
			serverID:         serverID,
			fetchBundleErr:   fmt.Sprintf(`unexpected ID %q`, spiffeid.RequireFromString("spiffe://domain.test/spiffe-bundle-endpoint-server")),
		},
		{
			name:         "no SPIFFE ID",
			status:       http.StatusOK,
			body:         `{"spiffe_refresh_hint": 10}`,
			serverID:     serverID,
			newClientErr: `no SPIFFE ID specified for federation with "domain.test"`,
		},
		{
			name:           "SPIFFE ID override",
			serverID:       spiffeid.RequireFromString("spiffe://domain.test/my-spiffe-bundle-endpoint-server"),
			expectedID:     spiffeid.RequireFromString("spiffe://domain.test/authorized"),
			fetchBundleErr: fmt.Sprintf(`unexpected ID %q`, spiffeid.RequireFromString("spiffe://domain.test/my-spiffe-bundle-endpoint-server")),
		},
		{
			name:           "non-200 status",
			status:         http.StatusServiceUnavailable,
			body:           "tHe SYsTEm iS DowN",
			serverID:       serverID,
			expectedID:     serverID,
			fetchBundleErr: "unexpected status 503 fetching bundle: tHe SYsTEm iS DowN",
		},
		{
			name:           "invalid bundle content",
			status:         http.StatusOK,
			body:           "NOT JSON",
			serverID:       serverID,
			expectedID:     serverID,
			fetchBundleErr: "failed to decode bundle",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			serverCert, serverKey := createServerCertificate(t, testCase.serverID)

			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(testCase.status)
				_, _ = w.Write([]byte(testCase.body))
			}))
			server.TLS = &tls.Config{
				Certificates: []tls.Certificate{
					{
						Certificate: [][]byte{serverCert.Raw},
						PrivateKey:  serverKey,
					},
				},
				MinVersion: tls.VersionTLS12,
			}
			server.StartTLS()
			defer server.Close()

			client, err := NewClient(ClientConfig{
				TrustDomain: trustDomain,
				EndpointURL: server.URL,
				SPIFFEAuth: &SPIFFEAuthConfig{
					EndpointSpiffeID: testCase.expectedID,
					RootCAs:          []*x509.Certificate{serverCert},
				},
				DeprecatedConfig: testCase.deprecatedConfig,
			})
			if testCase.newClientErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), testCase.newClientErr)
				return
			}
			require.NoError(t, err)

			bundle, err := client.FetchBundle(context.Background())
			if testCase.fetchBundleErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), testCase.fetchBundleErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, bundle)
			require.Equal(t, trustDomain.IDString(), bundle.TrustDomainID())
			require.Equal(t, 10*time.Second, bundle.RefreshHint())
		})
	}
}

func createServerCertificate(t *testing.T, serverID spiffeid.ID) (*x509.Certificate, crypto.Signer) {
	return spiretest.SelfSignCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{serverID.URL()},
	})
}
