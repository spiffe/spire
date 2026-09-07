package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/server/datastore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	UpdateBundle(ctx context.Context) (*spiffebundle.Bundle, *spiffebundle.Bundle, error)

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

func (u *bundleUpdater) UpdateBundle(ctx context.Context) (*spiffebundle.Bundle, *spiffebundle.Bundle, error) {
	trustDomainConfig := u.GetTrustDomainConfig()

	client, usedBootstrap, err := u.newClient(ctx, trustDomainConfig)
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

	if localFederatedBundleOrNil != nil && fetchedFederatedBundle.Equal(localFederatedBundleOrNil) {
		return localFederatedBundleOrNil, nil, nil
	}

	bundle, err := bundleutil.SPIFFEBundleToProto(fetchedFederatedBundle)
	if err != nil {
		return nil, nil, err
	}
	// Create if the store was empty at auth time so bootstrap roots cannot overwrite a bundle that appears before persist.
	if localFederatedBundleOrNil == nil || usedBootstrap {
		_, err = u.ds.CreateBundle(ctx, bundle)
		if err != nil {
			if status.Code(err) == codes.AlreadyExists {
				return localFederatedBundleOrNil, nil, nil
			}
			return localFederatedBundleOrNil, nil, fmt.Errorf("failed to store fetched federated bundle: %w", err)
		}
	} else {
		_, err = u.ds.SetBundle(ctx, bundle)
		if err != nil {
			return localFederatedBundleOrNil, nil, fmt.Errorf("failed to store fetched federated bundle: %w", err)
		}
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

func (u *bundleUpdater) newClient(ctx context.Context, trustDomainConfig TrustDomainConfig) (Client, bool, error) {
	clientConfig := ClientConfig{
		TrustDomain: u.td,
		EndpointURL: trustDomainConfig.EndpointURL,
	}

	usedBootstrap := false
	if spiffeAuth, ok := trustDomainConfig.EndpointProfile.(HTTPSSPIFFEProfile); ok {
		endpointTD := spiffeAuth.EndpointSPIFFEID.TrustDomain()
		localEndpointBundle, err := fetchBundleIfExists(ctx, u.ds, endpointTD)
		if err != nil {
			return nil, false, fmt.Errorf("failed to fetch local copy of bundle for %q: %w", endpointTD, err)
		}

		var rootCAs []*x509.Certificate
		rootCAs, usedBootstrap, err = rootCAsForSPIFFEAuth(localEndpointBundle, trustDomainConfig, endpointTD, u.td)
		if err != nil {
			return nil, false, err
		}
		clientConfig.SPIFFEAuth = &SPIFFEAuthConfig{
			EndpointSpiffeID: spiffeAuth.EndpointSPIFFEID,
			RootCAs:          rootCAs,
		}
	}
	client, err := u.newClientHook(clientConfig)
	return client, usedBootstrap, err
}

func rootCAsForSPIFFEAuth(local *spiffebundle.Bundle, cfg TrustDomainConfig, endpointTD, federatedTD spiffeid.TrustDomain) ([]*x509.Certificate, bool, error) {
	if local != nil {
		return local.X509Authorities(), false, nil
	}
	if cfg.BootstrapBundlePath == "" || endpointTD != federatedTD {
		return nil, false, errors.New("can't perform SPIFFE Authentication: local copy of bundle not found")
	}
	certs, err := loadBootstrapX509Authorities(cfg.BootstrapBundlePath, cfg.BootstrapBundleFormat, endpointTD)
	if err != nil {
		return nil, false, fmt.Errorf("can't perform SPIFFE Authentication: %w", err)
	}
	return certs, true, nil
}

func fetchBundleIfExists(ctx context.Context, ds datastore.DataStore, trustDomain spiffeid.TrustDomain) (*spiffebundle.Bundle, error) {
	// Load the current bundle and extract the root CA certificates
	bundle, err := ds.FetchBundle(ctx, trustDomain.IDString())
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return nil, nil
	}
	return bundleutil.SPIFFEBundleFromProto(bundle)
}
