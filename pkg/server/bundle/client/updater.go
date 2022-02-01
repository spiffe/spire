package client

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/zeebo/errs"
)

type BundleUpdaterConfig struct {
	TrustDomain spiffeid.TrustDomain
	DataStore   datastore.DataStore

	TrustDomainConfig TrustDomainConfig

	// newClientHook is a test hook for injecting client behavior
	newClientHook func(ClientConfig) (Client, error)
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

	// GetTrustDomainConfig returns the configuration for the updater
	GetTrustDomainConfig() TrustDomainConfig

	// SetTrustDomainConfig sets the configuration for the updater
	SetTrustDomainConfig(TrustDomainConfig) bool
}

type bundleUpdater struct {
	td            spiffeid.TrustDomain
	ds            datastore.DataStore
	newClientHook func(ClientConfig) (Client, error)

	trustDomainConfigMtx sync.Mutex
	trustDomainConfig    TrustDomainConfig
}

func NewBundleUpdater(config BundleUpdaterConfig) BundleUpdater {
	if config.newClientHook == nil {
		config.newClientHook = NewClient
	}
	return &bundleUpdater{
		td:                config.TrustDomain,
		ds:                config.DataStore,
		newClientHook:     config.newClientHook,
		trustDomainConfig: config.TrustDomainConfig,
	}
}

func (u *bundleUpdater) UpdateBundle(ctx context.Context) (*bundleutil.Bundle, *bundleutil.Bundle, error) {
	trustDomainConfig := u.GetTrustDomainConfig()

	client, err := u.newClient(ctx, trustDomainConfig)
	if err != nil {
		return nil, nil, err
	}

	localFederatedBundleOrNil, err := fetchBundleIfExists(ctx, u.ds, u.td)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch local federated bundle: %w", err)
	}

	fetchedFederatedBundle, err := client.FetchBundle(ctx)
	if err != nil {
		return localFederatedBundleOrNil, nil, fmt.Errorf("failed to fetch federated bundle from endpoint: %w", err)
	}

	if localFederatedBundleOrNil != nil && fetchedFederatedBundle.EqualTo(localFederatedBundleOrNil) {
		return localFederatedBundleOrNil, nil, nil
	}

	_, err = u.ds.SetBundle(ctx, fetchedFederatedBundle.Proto())
	if err != nil {
		return localFederatedBundleOrNil, nil, fmt.Errorf("failed to store fetched federated bundle: %w", err)
	}

	return localFederatedBundleOrNil, fetchedFederatedBundle, nil
}

func (u *bundleUpdater) GetTrustDomainConfig() TrustDomainConfig {
	u.trustDomainConfigMtx.Lock()
	trustDomainConfig := u.trustDomainConfig
	u.trustDomainConfigMtx.Unlock()
	return trustDomainConfig
}

func (u *bundleUpdater) SetTrustDomainConfig(trustDomainConfig TrustDomainConfig) bool {
	u.trustDomainConfigMtx.Lock()
	defer u.trustDomainConfigMtx.Unlock()
	if u.trustDomainConfig != trustDomainConfig {
		u.trustDomainConfig = trustDomainConfig
		return true
	}
	return false
}

func (u *bundleUpdater) newClient(ctx context.Context, trustDomainConfig TrustDomainConfig) (Client, error) {
	clientConfig := ClientConfig{
		TrustDomain: u.td,
		EndpointURL: trustDomainConfig.EndpointURL,
	}

	if spiffeAuth, ok := trustDomainConfig.EndpointProfile.(HTTPSSPIFFEProfile); ok {
		trustDomain := spiffeAuth.EndpointSPIFFEID.TrustDomain()
		localEndpointBundle, err := fetchBundleIfExists(ctx, u.ds, trustDomain)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch local copy of bundle for %q: %w", trustDomain, err)
		}

		if localEndpointBundle == nil {
			return nil, errors.New("can't perform SPIFFE Authentication: local copy of bundle not found")
		}
		clientConfig.SPIFFEAuth = &SPIFFEAuthConfig{
			EndpointSpiffeID: spiffeAuth.EndpointSPIFFEID,
			RootCAs:          localEndpointBundle.RootCAs(),
		}
	}
	return u.newClientHook(clientConfig)
}

func fetchBundleIfExists(ctx context.Context, ds datastore.DataStore, trustDomain spiffeid.TrustDomain) (*bundleutil.Bundle, error) {
	// Load the current bundle and extract the root CA certificates
	bundle, err := ds.FetchBundle(ctx, trustDomain.IDString())
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if bundle == nil {
		return nil, nil
	}
	return bundleutil.BundleFromProto(bundle)
}
