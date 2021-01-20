package client

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

var trustDomain = spiffeid.RequireTrustDomainFromString("domain.test")

func TestClient(t *testing.T) {
	testCases := []struct {
		name        string
		spiffeID    spiffeid.ID
		status      int
		body        string
		errContains string
	}{
		{
			name:   "success",
			status: http.StatusOK,
			// We don't need a really elaborate body here. this test just
			// makes sure we unmarshal the body. The unmarshal tests will
			// provide the coverage for unmarshaling code.
			body: `{"spiffe_refresh_hint": 10}`,
		},
		{
			name:        "SPIFFE ID override",
			spiffeID:    spiffeid.RequireTrustDomainFromString("otherdomain.test").ID(),
			errContains: `unexpected ID "spiffe://domain.test/spire/server"`,
		},
		{
			name:        "non-200 status",
			status:      http.StatusServiceUnavailable,
			body:        "tHe SYsTEm iS DowN",
			errContains: "unexpected status 503 fetching bundle: tHe SYsTEm iS DowN",
		},
		{
			name:        "invalid bundle content",
			status:      http.StatusOK,
			body:        "NOT JSON",
			errContains: "failed to decode bundle",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			serverCert, serverKey := createServerCertificate(t)

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
			}
			server.StartTLS()
			defer server.Close()

			client, err := NewClient(ClientConfig{
				TrustDomain:     trustDomain,
				EndpointAddress: server.Listener.Addr().String(),
				SPIFFEAuth: &SPIFFEAuthConfig{
					EndpointSpiffeID: testCase.spiffeID,
					RootCAs:          []*x509.Certificate{serverCert},
				},
			})
			require.NoError(t, err)

			bundle, err := client.FetchBundle(context.Background())
			if testCase.errContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), testCase.errContains)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, bundle)
			require.Equal(t, trustDomain.IDString(), bundle.TrustDomainID())
			require.Equal(t, 10*time.Second, bundle.RefreshHint())
		})
	}
}

func createServerCertificate(t *testing.T) (*x509.Certificate, crypto.Signer) {
	return spiretest.SelfSignCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{idutil.ServerID(trustDomain).URL()},
	})
}
