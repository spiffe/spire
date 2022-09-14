package manager

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_agent "github.com/spiffe/spire/pkg/common/telemetry/agent"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/api/limits"
	"github.com/spiffe/spire/proto/spire/common"
)

type csrRequest struct {
	EntryID              string
	SpiffeID             string
	CurrentSVIDExpiresAt time.Time
}

type SVIDCache interface {
	// UpdateEntries updates entries on cache
	UpdateEntries(update *cache.UpdateEntries, checkSVID func(*common.RegistrationEntry, *common.RegistrationEntry, *cache.X509SVID) bool)

	// UpdateSVIDs updates SVIDs on provided records
	UpdateSVIDs(update *cache.UpdateSVIDs)

	// GetStaleEntries gets a list of records that need update SVIDs
	GetStaleEntries() []*cache.StaleEntry
}

func (m *manager) syncSVIDs(ctx context.Context) (err error) {
	// perform syncSVIDs only if using LRU cache
	if m.c.SVIDCacheMaxSize > 0 {
		m.cache.SyncSVIDsWithSubscribers()
		return m.updateSVIDs(ctx, m.c.Log.WithField(telemetry.CacheType, "workload"), m.cache)
	}
	return nil
}

// synchronize fetches the authorized entries from the server, updates the
// cache, and fetches missing/expiring SVIDs.
func (m *manager) synchronize(ctx context.Context) (err error) {
	cacheUpdate, storeUpdate, err := m.fetchEntries(ctx)
	if err != nil {
		return err
	}

	if err := m.updateCache(ctx, cacheUpdate, m.c.Log.WithField(telemetry.CacheType, "workload"), "", m.cache); err != nil {
		return err
	}

	if err := m.updateCache(ctx, storeUpdate, m.c.Log.WithField(telemetry.CacheType, "svid_store"), "svid_store", m.svidStoreCache); err != nil {
		return err
	}

	// Set last success sync
	m.setLastSync()
	return nil
}

func (m *manager) updateCache(ctx context.Context, update *cache.UpdateEntries, log logrus.FieldLogger, cacheType string, c SVIDCache) error {
	// update the cache and build a list of CSRs that need to be processed
	// in this interval.
	//
	// the values in `update` now belong to the cache. DO NOT MODIFY.
	var expiring int
	var outdated int
	c.UpdateEntries(update, func(existingEntry, newEntry *common.RegistrationEntry, svid *cache.X509SVID) bool {
		switch {
		case svid == nil:
			// no SVID
		case len(svid.Chain) == 0:
			// SVID has an empty chain. this is not expected to happen.
			log.WithFields(logrus.Fields{
				telemetry.RegistrationID: newEntry.EntryId,
				telemetry.SPIFFEID:       newEntry.SpiffeId,
			}).Warn("cached X509 SVID is empty")
		case rotationutil.ShouldRotateX509(m.c.Clk.Now(), svid.Chain[0]):
			expiring++
		case existingEntry != nil && existingEntry.RevisionNumber != newEntry.RevisionNumber:
			// Registration entry has been updated
			outdated++
		default:
			// SVID is good
			return false
		}

		return true
	})

	// TODO: this values are not real, we may remove
	if expiring > 0 {
		telemetry_agent.AddCacheManagerExpiredSVIDsSample(m.c.Metrics, cacheType, float32(expiring))
		log.WithField(telemetry.ExpiringSVIDs, expiring).Debug("Updating expiring SVIDs in cache")
	}
	if outdated > 0 {
		telemetry_agent.AddCacheManagerOutdatedSVIDsSample(m.c.Metrics, cacheType, float32(outdated))
		log.WithField(telemetry.OutdatedSVIDs, outdated).Debug("Updating SVIDs with outdated attributes in cache")
	}

	return m.updateSVIDs(ctx, log, c)
}

func (m *manager) updateSVIDs(ctx context.Context, log logrus.FieldLogger, c SVIDCache) error {
	m.updateSVIDMu.Lock()
	defer m.updateSVIDMu.Unlock()

	staleEntries := c.GetStaleEntries()
	if len(staleEntries) > 0 {
		var csrs []csrRequest
		log.WithFields(logrus.Fields{
			telemetry.Count: len(staleEntries),
			telemetry.Limit: limits.SignLimitPerIP,
		}).Debug("Renewing stale entries")

		for _, entry := range staleEntries {
			// we've exceeded the CSR limit, don't make any more CSRs
			if len(csrs) >= limits.SignLimitPerIP {
				break
			}

			csrs = append(csrs, csrRequest{
				EntryID:              entry.Entry.EntryId,
				SpiffeID:             entry.Entry.SpiffeId,
				CurrentSVIDExpiresAt: entry.ExpiresAt,
			})
		}

		update, err := m.fetchSVIDs(ctx, csrs)
		if err != nil {
			return err
		}
		// the values in `update` now belong to the cache. DO NOT MODIFY.
		c.UpdateSVIDs(update)
	}
	return nil
}

func (m *manager) fetchSVIDs(ctx context.Context, csrs []csrRequest) (_ *cache.UpdateSVIDs, err error) {
	// Put all the CSRs in an array to make just one call with all the CSRs.
	counter := telemetry_agent.StartManagerFetchSVIDsUpdatesCall(m.c.Metrics)
	defer counter.Done(&err)

	csrsIn := make(map[string][]byte)

	privateKeys := make(map[string]crypto.Signer, len(csrs))
	for _, csr := range csrs {
		log := m.c.Log.WithField("spiffe_id", csr.SpiffeID)
		if !csr.CurrentSVIDExpiresAt.IsZero() {
			log = log.WithField("expires_at", csr.CurrentSVIDExpiresAt.Format(time.RFC3339))
		}

		// Since entryIDs are unique, this shouldn't happen. Log just in case
		if _, ok := privateKeys[csr.EntryID]; ok {
			log.Warnf("Ignoring duplicate X509-SVID renewal for entry ID: %q", csr.EntryID)
			continue
		}

		log.Info("Renewing X509-SVID")

		spiffeID, err := spiffeid.FromString(csr.SpiffeID)
		if err != nil {
			return nil, err
		}
		privateKey, csrBytes, err := newCSR(spiffeID, m.c.WorkloadKeyType)
		if err != nil {
			return nil, err
		}
		privateKeys[csr.EntryID] = privateKey
		csrsIn[csr.EntryID] = csrBytes
	}

	svidsOut, err := m.client.NewX509SVIDs(ctx, csrsIn)
	if err != nil {
		return nil, err
	}

	byEntryID := make(map[string]*cache.X509SVID, len(svidsOut))
	for entryID, svid := range svidsOut {
		privateKey, ok := privateKeys[entryID]
		if !ok {
			continue
		}
		chain, err := x509.ParseCertificates(svid.CertChain)
		if err != nil {
			return nil, err
		}
		byEntryID[entryID] = &cache.X509SVID{
			Chain:      chain,
			PrivateKey: privateKey,
		}
	}

	return &cache.UpdateSVIDs{
		X509SVIDs: byEntryID,
	}, nil
}

// fetchEntries fetches entries that the agent is entitled to, divided in lists, one for regular entries and
// another one for storable entries
func (m *manager) fetchEntries(ctx context.Context) (_ *cache.UpdateEntries, _ *cache.UpdateEntries, err error) {
	// Put all the CSRs in an array to make just one call with all the CSRs.
	counter := telemetry_agent.StartManagerFetchEntriesUpdatesCall(m.c.Metrics)
	defer counter.Done(&err)

	update, err := m.client.FetchUpdates(ctx)
	if err != nil {
		return nil, nil, err
	}

	bundles, err := parseBundles(update.Bundles)
	if err != nil {
		return nil, nil, err
	}

	cacheEntries := make(map[string]*common.RegistrationEntry)
	storeEntries := make(map[string]*common.RegistrationEntry)

	for entryID, entry := range update.Entries {
		switch {
		case entry.StoreSvid:
			storeEntries[entryID] = entry
		default:
			cacheEntries[entryID] = entry
		}
	}

	return &cache.UpdateEntries{
			Bundles:             bundles,
			RegistrationEntries: cacheEntries,
		}, &cache.UpdateEntries{
			Bundles:             bundles,
			RegistrationEntries: storeEntries,
		}, nil
}

func newCSR(spiffeID spiffeid.ID, keyType workloadkey.KeyType) (crypto.Signer, []byte, error) {
	pk, err := keyType.GenerateSigner()
	if err != nil {
		return nil, nil, err
	}

	csr, err := util.MakeCSR(pk, spiffeID)
	if err != nil {
		return nil, nil, err
	}
	return pk, csr, nil
}

func parseBundles(bundles map[string]*common.Bundle) (map[spiffeid.TrustDomain]*cache.Bundle, error) {
	out := make(map[spiffeid.TrustDomain]*cache.Bundle, len(bundles))
	for _, bundle := range bundles {
		bundle, err := bundleutil.BundleFromProto(bundle)
		if err != nil {
			return nil, err
		}
		td, err := spiffeid.TrustDomainFromString(bundle.TrustDomainID())
		if err != nil {
			return nil, err
		}
		out[td] = bundle
	}
	return out, nil
}
