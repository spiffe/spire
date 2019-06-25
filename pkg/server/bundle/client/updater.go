package client

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/spire/server/datastore"
	"github.com/zeebo/errs"
)

type BundleUpdaterConfig struct {
	TrustDomainConfig

	TrustDomain string
	Log         logrus.FieldLogger
	DataStore   datastore.DataStore

	// newClient is a test hook for injecting client behavior
	newClient func(ClientConfig) Client
}

type BundleUpdater interface {
	// UpdateBundle fetches the local bundle from the datastore and the
	// endpoint bundle from the endpoint. If there is a change, it stores the
	// endpoint bundle.  It returns the local and endpoint bundles. On error,
	// it will still return the local and endpoint bundles if it was able to
	// retrieve them.
	UpdateBundle(ctx context.Context) (*bundleutil.Bundle, *bundleutil.Bundle, error)
}

type bundleUpdater struct {
	c BundleUpdaterConfig
}

func NewBundleUpdater(config BundleUpdaterConfig) BundleUpdater {
	if config.newClient == nil {
		config.newClient = func(config ClientConfig) Client {
			return NewClient(config)
		}
	}

	return &bundleUpdater{
		c: config,
	}
}

func (u *bundleUpdater) UpdateBundle(ctx context.Context) (*bundleutil.Bundle, *bundleutil.Bundle, error) {
	localBundle, err := fetchBundle(ctx, u.c.DataStore, u.c.TrustDomain)
	if err != nil {
		u.c.Log.WithError(err).Error("Failed to fetch local bundle")
		return nil, nil, err
	}

	client := u.newClient(localBundle.RootCAs())

	u.c.Log.Debug("Polling for federated bundle updates")
	endpointBundle, err := client.FetchBundle(ctx)
	if err != nil {
		u.c.Log.WithError(err).Error("Failed to fetch federated bundle update")
		// Per the UpdateBundle contract return the local bundle even on
		// failure to obtain the endpoint bundle.
		return localBundle, nil, err
	}

	if !endpointBundle.EqualTo(localBundle) {
		u.c.Log.Info("Storing federated bundle")
		_, err = u.c.DataStore.SetBundle(ctx, &datastore.SetBundleRequest{
			Bundle: endpointBundle.Proto(),
		})
		if err != nil {
			u.c.Log.WithError(err).Error("Failed to store federated bundle")
			// Per the UpdateBundle contract return the local and endpoint
			// bundles even on failure to store the endpoint bundle.
			return localBundle, endpointBundle, err
		}
	}

	return localBundle, endpointBundle, nil
}

func (u *bundleUpdater) newClient(rootCAs []*x509.Certificate) Client {
	return u.c.newClient(ClientConfig{
		TrustDomain:      u.c.TrustDomain,
		EndpointAddress:  u.c.EndpointAddress,
		EndpointSpiffeID: u.c.EndpointSpiffeID,
		RootCAs:          rootCAs,
	})
}

func fetchBundle(ctx context.Context, ds datastore.DataStore, trustDomain string) (*bundleutil.Bundle, error) {
	// Load the current bundle and extract the root CA certificates
	resp, err := ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: idutil.TrustDomainID(trustDomain),
	})
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if resp.Bundle == nil {
		return nil, errors.New("bundle not found")
	}
	return bundleutil.BundleFromProto(resp.Bundle)
}
