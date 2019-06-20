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

	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	testCases := []struct {
		name        string
		spiffeID    string
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
			spiffeID:    idutil.ServerID("otherdomain.test"),
			errContains: "SPIFFE ID mismatch",
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
		t.Run(testCase.name, func(t *testing.T) {
			serverCert, serverKey := createServerCertificate(t)

			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(testCase.status)
				w.Write([]byte(testCase.body))
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

			client := NewClient(ClientConfig{
				TrustDomain:      "domain.test",
				EndpointAddress:  server.Listener.Addr().String(),
				EndpointSpiffeID: testCase.spiffeID,
				RootCAs:          []*x509.Certificate{serverCert},
			})

			bundle, err := client.FetchBundle(context.Background())
			if testCase.errContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), testCase.errContains)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, bundle)
			require.Equal(t, "spiffe://domain.test", bundle.TrustDomainID())
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
		URIs:         []*url.URL{idutil.ServerURI("domain.test")},
	})
}
