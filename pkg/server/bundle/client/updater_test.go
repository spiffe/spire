package client

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/proto/spire/server/datastore"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestBundleUpdater(t *testing.T) {
	bundle1 := bundleutil.BundleFromRootCA("spiffe://domain.test", createCACertificate(t, "bundle1"))

	bundle2 := bundleutil.BundleFromRootCA("spiffe://domain.test", createCACertificate(t, "bundle2"))
	bundle2.SetRefreshHint(time.Minute)

	testCases := []struct {
		name           string
		localBundle    *bundleutil.Bundle
		endpointBundle *bundleutil.Bundle
		endpointErr    error
		expectedBundle *bundleutil.Bundle
		updateErr      string
	}{
		{
			name:           "bootstrap via datastore",
			localBundle:    bundle1,
			endpointBundle: bundle1,
			expectedBundle: bundle1,
		},
		{
			name:      "unable to load bootstrap bundle",
			updateErr: "bundle not found",
		},
		{
			name:           "bundle updates",
			localBundle:    bundle1,
			endpointBundle: bundle2,
			expectedBundle: bundle2,
		},
		{
			name:           "bundle fails to update",
			localBundle:    bundle1,
			endpointErr:    errors.New("OHNO!"),
			updateErr:      "OHNO!",
			expectedBundle: bundle1,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			log, _ := test.NewNullLogger()
			ds := fakedatastore.New()

			if testCase.localBundle != nil {
				_, err := ds.CreateBundle(context.Background(), &datastore.CreateBundleRequest{
					Bundle: testCase.localBundle.Proto(),
				})
				require.NoError(t, err)
			}

			updater := NewBundleUpdater(BundleUpdaterConfig{
				Log:         log,
				DataStore:   ds,
				TrustDomain: "domain.test",
				TrustDomainConfig: TrustDomainConfig{
					EndpointAddress:  "ENDPOINT_ADDRESS",
					EndpointSpiffeID: "ENDPOINT_SPIFFEID",
				},
				newClient: func(client ClientConfig) Client {
					return fakeClient{
						bundle: testCase.endpointBundle,
						err:    testCase.endpointErr,
					}
				},
			})

			refreshHint, err := updater.UpdateBundle(context.Background())
			if testCase.updateErr != "" {
				spiretest.RequireErrorContains(t, err, testCase.updateErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.expectedBundle.RefreshHint(), refreshHint)

			resp, err := ds.FetchBundle(context.Background(), &datastore.FetchBundleRequest{
				TrustDomainId: "spiffe://domain.test",
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			spiretest.RequireProtoEqual(t, testCase.expectedBundle.Proto(), resp.Bundle)
		})
	}
}

type fakeClient struct {
	bundle *bundleutil.Bundle
	err    error
}

func (c fakeClient) FetchBundle(context.Context) (*bundleutil.Bundle, error) {
	return c.bundle, c.err
}

func createCACertificate(t *testing.T, cn string) *x509.Certificate {
	cert, _ := spiretest.SelfSignCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		Subject:      pkix.Name{CommonName: cn},
	})
	return cert
}
