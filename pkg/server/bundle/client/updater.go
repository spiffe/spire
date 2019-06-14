package client

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

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
	UpdateBundle(ctx context.Context) (time.Duration, error)
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

func (u *bundleUpdater) UpdateBundle(ctx context.Context) (time.Duration, error) {
	localBundle, err := fetchBundle(ctx, u.c.DataStore, u.c.TrustDomain)
	if err != nil {
		u.c.Log.WithError(err).Error("Failed to fetch local bundle")
		return 0, err
	}

	client := u.newClient(localBundle.RootCAs())

	u.c.Log.Debug("Polling for federated bundle updates")
	endpointBundle, err := client.FetchBundle(ctx)
	if err != nil {
		u.c.Log.WithError(err).Error("Failed to fetch federated bundle update")
		return 0, err
	}

	if !endpointBundle.EqualTo(localBundle) {
		u.c.Log.Info("Storing federated bundle")
		_, err = u.c.DataStore.SetBundle(ctx, &datastore.SetBundleRequest{
			Bundle: endpointBundle.Proto(),
		})
		if err != nil {
			u.c.Log.WithError(err).Error("Failed to store federated bundle")
			return 0, errs.Wrap(err)
		}
	}

	return endpointBundle.RefreshHint(), nil
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
