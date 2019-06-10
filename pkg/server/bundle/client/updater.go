package client

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
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
	UpdateBundle(ctx context.Context) (time.Duration, error)
}

type bundleUpdater struct {
	c      BundleUpdaterConfig
	client Client
	bundle *bundleutil.Bundle
}

func NewBundleUpdater(ctx context.Context, config BundleUpdaterConfig) (BundleUpdater, error) {
	if config.newClient == nil {
		config.newClient = func(config ClientConfig) Client {
			return NewClient(config)
		}
	}

	// Load if the existing bundle, if present, and initialize the client.
	var rootCAs []*x509.Certificate
	bundle, err := fetchBundle(ctx, config.DataStore, config.TrustDomain)
	switch {
	case err != nil:
		return nil, errs.Wrap(err)
	case bundle != nil:
		// There is an existing bundle for the trust domain.
		rootCAs = bundle.RootCAs()
	case bundle == nil:
		// No current bundle for the trust domain. Load roots from the bootstrap bundle.
		rootCAs, err = pemutil.LoadCertificates(config.BootstrapBundle)
		if err != nil {
			return nil, errs.New("unable to load bootstrap bundle: %v", err)
		}
	}

	u := &bundleUpdater{
		c:      config,
		bundle: bundle,
	}
	u.client = u.newClient(rootCAs)
	return u, nil
}

func (u *bundleUpdater) UpdateBundle(ctx context.Context) (time.Duration, error) {
	u.c.Log.Debug("Polling for federated bundle updates")
	bundle, metadata, err := u.client.FetchBundle(ctx)
	if err != nil {
		u.c.Log.WithError(err).Error("Failed to poll for federated bundle update")
		return 0, err
	}

	switch {
	case u.bundle == nil:
		u.c.Log.Info("Creating federated bundle")
		_, err = u.c.DataStore.CreateBundle(ctx, &datastore.CreateBundleRequest{
			Bundle: bundle.Proto(),
		})
	case !u.bundle.EqualTo(bundle):
		u.c.Log.Info("Updating federated bundle")
		_, err = u.c.DataStore.UpdateBundle(ctx, &datastore.UpdateBundleRequest{
			Bundle: bundle.Proto(),
		})
	default:
		return metadata.RefreshHint, nil
	}
	if err != nil {
		u.c.Log.WithError(err).Error("Failed to store federated bundle update")
		return 0, errs.Wrap(err)
	}

	u.client = u.newClient(bundle.RootCAs())
	u.bundle = bundle
	return metadata.RefreshHint, nil
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
		return nil, nil
	}
	return bundleutil.BundleFromProto(resp.Bundle)
}
