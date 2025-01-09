package client_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/bundle/client"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	domain1 = spiffeid.RequireTrustDomainFromString("domain1.test")
	domain2 = spiffeid.RequireTrustDomainFromString("domain2.test")
	domain3 = spiffeid.RequireTrustDomainFromString("domain3.test")
)

func TestMergedTrustDomainConfigSource(t *testing.T) {
	sourceA := client.NewTrustDomainConfigSet(client.TrustDomainConfigMap{
		domain1: client.TrustDomainConfig{EndpointURL: "A"},
	})
	sourceB := client.NewTrustDomainConfigSet(client.TrustDomainConfigMap{
		domain1: client.TrustDomainConfig{EndpointURL: "B"},
	})
	sourceC := client.NewTrustDomainConfigSet(client.TrustDomainConfigMap{
		domain2: client.TrustDomainConfig{EndpointURL: "A"},
	})

	t.Run("context is passed through and error returned", func(t *testing.T) {
		expectedCtx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var actualCtx context.Context
		source := client.MergeTrustDomainConfigSources(client.TrustDomainConfigSourceFunc(
			func(ctx context.Context) (map[spiffeid.TrustDomain]client.TrustDomainConfig, error) {
				actualCtx = ctx
				return nil, errors.New("oh no")
			},
		))
		configs, err := source.GetTrustDomainConfigs(expectedCtx)
		assert.Nil(t, configs)
		assert.Equal(t, expectedCtx, actualCtx)
		assert.EqualError(t, err, "oh no")
	})

	t.Run("empty", func(t *testing.T) {
		source := client.MergeTrustDomainConfigSources()
		configs, err := source.GetTrustDomainConfigs(context.Background())
		assert.Empty(t, configs)
		assert.NoError(t, err)
	})

	t.Run("priority is in-order", func(t *testing.T) {
		source := client.MergeTrustDomainConfigSources(sourceA, sourceB, sourceC)
		configs, err := source.GetTrustDomainConfigs(context.Background())
		require.NoError(t, err)

		require.Equal(t, map[spiffeid.TrustDomain]client.TrustDomainConfig{
			domain1: {EndpointURL: "A"},
			domain2: {EndpointURL: "A"},
		}, configs)
	})
}

func TestDataStoreTrustDomainConfigSource(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		log, _ := test.NewNullLogger()
		ds := &fakeDataStore{}
		source := client.DataStoreTrustDomainConfigSource(log, ds)
		configs, err := source.GetTrustDomainConfigs(context.Background())
		assert.Empty(t, configs)
		assert.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		log, _ := test.NewNullLogger()
		ds := &fakeDataStore{err: errors.New("oh no")}
		source := client.DataStoreTrustDomainConfigSource(log, ds)
		configs, err := source.GetTrustDomainConfigs(context.Background())
		assert.Nil(t, configs)
		assert.EqualError(t, err, "oh no")
	})

	t.Run("drops unknown profiles", func(t *testing.T) {
		log, _ := test.NewNullLogger()
		ds := &fakeDataStore{frs: []*datastore.FederationRelationship{
			{
				TrustDomain:           domain1,
				BundleEndpointURL:     parseURL(t, "https://domain1.test/bundle"),
				BundleEndpointProfile: datastore.BundleEndpointWeb,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://notused"),
			},
			{
				TrustDomain:           domain2,
				BundleEndpointURL:     parseURL(t, "https://domain2.test/bundle"),
				BundleEndpointProfile: datastore.BundleEndpointType("UNKNOWN"),
			},
			{
				TrustDomain:           domain3,
				BundleEndpointURL:     parseURL(t, "https://domain3.test/bundle"),
				BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
				EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://domain3.test/bundle-server"),
			},
		}}
		source := client.DataStoreTrustDomainConfigSource(log, ds)
		configs, err := source.GetTrustDomainConfigs(context.Background())
		assert.Equal(t, map[spiffeid.TrustDomain]client.TrustDomainConfig{
			domain1: {
				EndpointURL:     "https://domain1.test/bundle",
				EndpointProfile: client.HTTPSWebProfile{},
			},
			domain3: {
				EndpointURL: "https://domain3.test/bundle",
				EndpointProfile: client.HTTPSSPIFFEProfile{
					EndpointSPIFFEID: spiffeid.RequireFromString("spiffe://domain3.test/bundle-server"),
				},
			},
		}, configs)
		assert.NoError(t, err)
	})
}

type fakeDataStore struct {
	datastore.DataStore
	frs []*datastore.FederationRelationship
	err error
}

func (ds fakeDataStore) ListFederationRelationships(context.Context, *datastore.ListFederationRelationshipsRequest) (*datastore.ListFederationRelationshipsResponse, error) {
	if ds.err != nil {
		return nil, ds.err
	}
	return &datastore.ListFederationRelationshipsResponse{FederationRelationships: ds.frs}, nil
}

func parseURL(t *testing.T, s string) *url.URL {
	u, err := url.Parse(s)
	require.NoError(t, err)
	return u
}
