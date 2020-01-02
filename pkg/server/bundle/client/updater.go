package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/zeebo/errs"
)

type BundleUpdaterConfig struct {
	TrustDomainConfig

	TrustDomain string
	DataStore   datastore.DataStore

	// newClient is a test hook for injecting client behavior
	newClient func(ClientConfig) Client
}

type BundleUpdater interface {
	// UpdateBundle fetches the local bundle from the datastore and the
	// endpoint bundle from the endpoint. The function will return an error if
	// the local bundle cannot be fetched, the endpoint bundle cannot be
	// downloaded, or there is a problem persisting the bundle. The local
	// bundle will always be returned if it was fetched, independent of any
	// other failures performing the update. The endpoint bundle is ONLY
	// returned if it can be successfully downloaded, is different from the
	// local bundle, and is successfully stored.
	UpdateBundle(ctx context.Context) (*bundleutil.Bundle, *bundleutil.Bundle, error)
}

type bundleUpdater struct {
	c BundleUpdaterConfig
}

func NewBundleUpdater(config BundleUpdaterConfig) BundleUpdater {
	if config.newClient == nil {
		config.newClient = NewClient
	}

	return &bundleUpdater{
		c: config,
	}
}

func (u *bundleUpdater) UpdateBundle(ctx context.Context) (*bundleutil.Bundle, *bundleutil.Bundle, error) {
	localBundle, err := fetchBundle(ctx, u.c.DataStore, u.c.TrustDomain)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch local bundle: %v", err)
	}

	client := u.newClient(localBundle.RootCAs())

	endpointBundle, err := client.FetchBundle(ctx)
	if err != nil {
		return localBundle, nil, fmt.Errorf("failed to fetch endpoint bundle: %v", err)
	}

	if endpointBundle.EqualTo(localBundle) {
		return localBundle, nil, nil
	}

	_, err = u.c.DataStore.SetBundle(ctx, &datastore.SetBundleRequest{
		Bundle: endpointBundle.Proto(),
	})
	if err != nil {
		return localBundle, nil, fmt.Errorf("failed to store endpoint bundle: %v", err)
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
