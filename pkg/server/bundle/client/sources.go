package client

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/datastore"
)

type TrustDomainConfigSource interface {
	GetTrustDomainConfigs(ctx context.Context) (map[spiffeid.TrustDomain]TrustDomainConfig, error)
}

type TrustDomainConfigSourceFunc func(ctx context.Context) (map[spiffeid.TrustDomain]TrustDomainConfig, error)

func (fn TrustDomainConfigSourceFunc) GetTrustDomainConfigs(ctx context.Context) (map[spiffeid.TrustDomain]TrustDomainConfig, error) {
	return fn(ctx)
}

type TrustDomainConfigMap = map[spiffeid.TrustDomain]TrustDomainConfig

type TrustDomainConfigSet struct {
	mtx       sync.RWMutex
	configMap TrustDomainConfigMap
}

func NewTrustDomainConfigSet(configs TrustDomainConfigMap) *TrustDomainConfigSet {
	s := &TrustDomainConfigSet{}
	s.SetAll(configs)
	return s
}

func (s *TrustDomainConfigSet) Set(td spiffeid.TrustDomain, config TrustDomainConfig) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.configMap[td] = config
}

func (s *TrustDomainConfigSet) SetAll(configMap TrustDomainConfigMap) {
	configMap = duplicateTrustDomainConfigMap(configMap)

	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.configMap = configMap
}

func (s *TrustDomainConfigSet) GetTrustDomainConfigs(ctx context.Context) (map[spiffeid.TrustDomain]TrustDomainConfig, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return s.configMap, nil
}

func duplicateTrustDomainConfigMap(in TrustDomainConfigMap) TrustDomainConfigMap {
	out := make(TrustDomainConfigMap, len(in))
	for td, config := range in {
		out[td] = config
	}
	return out
}

func MergeTrustDomainConfigSources(sources ...TrustDomainConfigSource) TrustDomainConfigSource {
	return TrustDomainConfigSourceFunc(func(ctx context.Context) (map[spiffeid.TrustDomain]TrustDomainConfig, error) {
		merged := make(map[spiffeid.TrustDomain]TrustDomainConfig)
		// merge in reverse order
		for i := len(sources) - 1; i >= 0; i-- {
			configs, err := sources[i].GetTrustDomainConfigs(ctx)
			if err != nil {
				return nil, err
			}
			for td, config := range configs {
				merged[td] = config
			}
		}
		return merged, nil
	})
}

func DataStoreTrustDomainConfigSource(log logrus.FieldLogger, ds datastore.DataStore) TrustDomainConfigSource {
	return TrustDomainConfigSourceFunc(func(ctx context.Context) (map[spiffeid.TrustDomain]TrustDomainConfig, error) {
		resp, err := ds.ListFederationRelationships(ctx, &datastore.ListFederationRelationshipsRequest{})
		if err != nil {
			return nil, err
		}

		configs := make(map[spiffeid.TrustDomain]TrustDomainConfig)
		for _, fr := range resp.FederationRelationships {
			config := TrustDomainConfig{
				EndpointURL: fr.BundleEndpointURL.String(),
			}
			switch fr.BundleEndpointProfile {
			case datastore.BundleEndpointSPIFFE:
				config.EndpointProfile = HTTPSSPIFFEProfile{
					EndpointSPIFFEID: fr.EndpointSPIFFEID,
				}
			case datastore.BundleEndpointWeb:
				config.EndpointProfile = HTTPSWebProfile{}
			default:
				log.WithFields(logrus.Fields{
					telemetry.TrustDomain:           fr.TrustDomain,
					telemetry.BundleEndpointProfile: fr.BundleEndpointProfile,
				}).Warn("Ignoring federation relationship with unknown profile type")
				continue
			}
			configs[fr.TrustDomain] = config
		}
		return configs, nil
	})
}
