package cache

import (
	"crypto"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
)

// WITSVID holds onto the WIT-SVID token and private key.
type WITSVID struct {
	Token      string
	PrivateKey crypto.Signer
	IssuedAt   time.Time
	ExpiresOn  time.Time
}

func (s WITSVID) ExpiresAt() time.Time {
	return s.ExpiresOn
}

// WITIdentity holds the data for a single WIT-SVID workload identity.
type WITIdentity struct {
	Entry      *common.RegistrationEntry
	Token      string
	PrivateKey crypto.Signer
}

// WITWorkloadUpdate is used to convey WIT workload information to cache subscribers.
type WITWorkloadUpdate struct {
	Identities       []WITIdentity
	Bundle           *spiffebundle.Bundle
	FederatedBundles map[spiffeid.TrustDomain]*spiffebundle.Bundle
}

func (u *WITWorkloadUpdate) HasIdentity() bool {
	return len(u.Identities) > 0
}

// WITLRUCache wraps LRUCache with WIT-SVID-specific operations.
type WITLRUCache struct {
	*LRUCache[WITSVID, WITWorkloadUpdate]
}

type WITLRUCacheConfig struct {
	Log              logrus.FieldLogger
	TrustDomain      spiffeid.TrustDomain
	Bundle           *Bundle
	Metrics          telemetry.Metrics
	SvidCacheMaxSize int
	Clk              clock.Clock
}

func NewWITLRUCache(config WITLRUCacheConfig) *WITLRUCache {
	c := &WITLRUCache{}
	c.LRUCache = NewLRUCache(LRUCacheConfig[WITSVID, WITWorkloadUpdate]{
		Log:              config.Log,
		TrustDomain:      config.TrustDomain,
		Bundle:           config.Bundle,
		Metrics:          config.Metrics,
		SvidCacheMaxSize: config.SvidCacheMaxSize,
		Clk:              config.Clk,
		SVIDType:         "WIT",
		BuildUpdate:      buildWITWorkloadUpdate,
	})
	return c
}

func (c *WITLRUCache) UpdateWITSVIDs(svids map[string]*WITSVID) {
	c.LRUCache.UpdateSVIDs(svids)
}

func buildWITWorkloadUpdate(cache *LRUCache[WITSVID, WITWorkloadUpdate], set selectorSet) *WITWorkloadUpdate {
	records, recordsDone := cache.getRecordsForSelectors(set)
	defer recordsDone()

	identities := make([]WITIdentity, 0, len(records))
	entries := make([]*common.RegistrationEntry, 0, len(records))
	for record := range records {
		if svid, ok := cache.svids[record.entry.EntryId]; ok {
			identities = append(identities, WITIdentity{
				Entry:      record.entry,
				Token:      svid.Token,
				PrivateKey: svid.PrivateKey,
			})
			entries = append(entries, record.entry)
		}
	}

	return &WITWorkloadUpdate{
		Bundle:           cache.bundles[cache.trustDomain],
		FederatedBundles: cache.GatherFederatedBundles(entries),
		Identities:       identities,
	}
}
