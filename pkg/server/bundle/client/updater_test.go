package client

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/bundle"
	"github.com/spiffe/spire/proto/spire/server/datastore"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestBundleUpdater(t *testing.T) {
	bundle1 := bundleutil.BundleFromRootCA("spiffe://domain.test", createCACertificate(t, "bundle1"))
	bundle2 := bundleutil.BundleFromRootCA("spiffe://domain.test", createCACertificate(t, "bundle2"))

	testCases := []struct {
		name             string
		initDiskBundle   bool
		initStoreBundle  bool
		endpointBundle   *bundleutil.Bundle
		endpointMetadata bundle.Metadata
		endpointErr      error
		expectedBundle   *bundleutil.Bundle
		newErr           string
		updateErr        string
	}{
		{
			name:           "bootstrap via bootstrap bundle",
			initDiskBundle: true,
			endpointBundle: bundle1,
			expectedBundle: bundle1,
		},
		{
			name:            "bootstrap via datastore",
			initStoreBundle: true,
			endpointBundle:  bundle1,
			expectedBundle:  bundle1,
		},
		{
			name:   "unable to load bootstrap bundle",
			newErr: "unable to load bootstrap bundle",
		},
		{
			name:            "bundle updates",
			initStoreBundle: true,
			endpointBundle:  bundle2,
			endpointMetadata: bundle.Metadata{
				RefreshHint: time.Minute,
			},
			expectedBundle: bundle2,
		},
		{
			name:            "bundle fails to update",
			initStoreBundle: true,
			endpointErr:     errors.New("OHNO!"),
			updateErr:       "OHNO!",
			expectedBundle:  bundle1,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			log, _ := test.NewNullLogger()
			ds := fakedatastore.New()
			bootstrapBundlePath := ""

			if testCase.initDiskBundle {
				dir, err := ioutil.TempDir("", "server-bundle-client-updater")
				require.NoError(t, err)
				defer os.RemoveAll(dir)
				bootstrapBundlePath = filepath.Join(dir, "bootstrap-bundle.pem")
				err = pemutil.SaveCertificates(bootstrapBundlePath, bundle1.RootCAs(), 0644)
				require.NoError(t, err)
			}

			if testCase.initStoreBundle {
				_, err := ds.CreateBundle(context.Background(), &datastore.CreateBundleRequest{
					Bundle: bundle1.Proto(),
				})
				require.NoError(t, err)
			}

			updater, err := NewBundleUpdater(context.Background(), BundleUpdaterConfig{
				Log:         log,
				DataStore:   ds,
				TrustDomain: "domain.test",
				TrustDomainConfig: TrustDomainConfig{
					EndpointAddress:  "ENDPOINT_ADDRESS",
					EndpointSpiffeID: "ENDPOINT_SPIFFEID",
					BootstrapBundle:  bootstrapBundlePath,
				},
				newClient: func(client ClientConfig) Client {
					return fakeClient{
						bundle:   testCase.endpointBundle,
						metadata: testCase.endpointMetadata,
						err:      testCase.endpointErr,
					}
				},
			})
			if testCase.newErr != "" {
				spiretest.RequireErrorContains(t, err, testCase.newErr)
				return
			}
			require.NoError(t, err)

			refreshHint, err := updater.UpdateBundle(context.Background())
			if testCase.updateErr != "" {
				spiretest.RequireErrorContains(t, err, testCase.updateErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.endpointMetadata.RefreshHint, refreshHint)
			}

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
	bundle   *bundleutil.Bundle
	metadata bundle.Metadata
	err      error
}

func (c fakeClient) FetchBundle(context.Context) (*bundleutil.Bundle, *bundle.Metadata, error) {
	return c.bundle, &c.metadata, c.err
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
