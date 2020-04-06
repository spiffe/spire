package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_agent "github.com/spiffe/spire/pkg/common/telemetry/agent"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"
)

type csrRequest struct {
	EntryID              string
	SpiffeID             string
	CurrentSVIDExpiresAt time.Time
}

// synchronize hits the node api, checks for entries we haven't fetched yet, and fetches them.
func (m *manager) synchronize(ctx context.Context) (err error) {
	update, err := m.fetchEntries(ctx)
	if err != nil {
		return err
	}

	// update the cache and build a list of CSRs that need to be processed
	// in this interval.
	//
	// the values in `update` now belong to the cache. DO NOT MODIFY.
	var csrs []csrRequest
	var expiring int
	var outdated int
	m.cache.UpdateEntries(update, func(existingEntry, newEntry *common.RegistrationEntry, svid *cache.X509SVID) bool {
		switch {
		case svid == nil:
			// no SVID
		case len(svid.Chain) == 0:
			// SVID has an empty chain. this is not expected to happen.
			m.c.Log.WithFields(logrus.Fields{
				telemetry.RegistrationID: newEntry.EntryId,
				telemetry.SPIFFEID:       newEntry.SpiffeId,
			}).Warn("cached X509 SVID is empty")
		case rotationutil.ShouldRotateX509(m.c.Clk.Now(), svid.Chain[0]):
			expiring++
		case existingEntry != nil && !stringsEqual(existingEntry.DnsNames, newEntry.DnsNames):
			// DNS Names have changed
			outdated++
		case existingEntry != nil && existingEntry.Ttl != newEntry.Ttl:
			// TTL has changed
			outdated++
		default:
			// SVID is good
			return false
		}

		return true
	})

	// TODO: this values are not real, we may remove
	if expiring > 0 {
		telemetry_agent.AddCacheManagerExpiredSVIDsSample(m.c.Metrics, float32(expiring))
		m.c.Log.WithField(telemetry.ExpiringSVIDs, expiring).Debug("Updating expiring SVIDs in cache")
	}
	if outdated > 0 {
		telemetry_agent.AddCacheManagerOutdatedSVIDsSample(m.c.Metrics, float32(outdated))
		m.c.Log.WithField(telemetry.OutdatedSVIDs, outdated).Debug("Updating SVIDs with outdated attributes in cache")
	}

	staleEntries := m.cache.GetStaleEntries()
	if len(staleEntries) > 0 {
		for staleEntry, expiresAt := range staleEntries {
			// we've exceeded the CSR limit, don't make any more CSRs
			if len(csrs) >= node.CSRLimit {
				break
			}

			csrs = append(csrs, csrRequest{
				EntryID:              staleEntry.EntryId,
				SpiffeID:             staleEntry.SpiffeId,
				CurrentSVIDExpiresAt: expiresAt,
			})
		}

		update, err := m.fetchSVIDs(ctx, csrs)
		if err != nil {
			return err
		}
		// the values in `update` now belong to the cache. DO NOT MODIFY.
		m.cache.UpdateSVIDs(update)
	}
	return nil
}

func (m *manager) fetchSVIDs(ctx context.Context, csrs []csrRequest) (_ *cache.UpdateSVIDs, err error) {
	// Put all the CSRs in an array to make just one call with all the CSRs.
	counter := telemetry_agent.StartManagerFetchSVIDsUpdatesCall(m.c.Metrics)
	defer counter.Done(&err)

	req := &node.FetchX509SVIDRequest{
		Csrs: make(map[string][]byte),
	}

	privateKeys := make(map[string]*ecdsa.PrivateKey, len(csrs))
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
		privateKey, csrBytes, err := newCSR(csr.SpiffeID)
		if err != nil {
			return nil, err
		}
		privateKeys[csr.EntryID] = privateKey
		req.Csrs[csr.EntryID] = csrBytes
	}

	update, err := m.client.FetchUpdates(ctx, req, false)
	if err != nil {
		return nil, err
	}

	byEntryID := make(map[string]*cache.X509SVID, len(update.SVIDs))
	for entryID, svid := range update.SVIDs {
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

func (m *manager) fetchEntries(ctx context.Context) (_ *cache.UpdateEntries, err error) {
	// Put all the CSRs in an array to make just one call with all the CSRs.
	counter := telemetry_agent.StartManagerFetchEntriesUpdatesCall(m.c.Metrics)
	defer counter.Done(&err)

	req := &node.FetchX509SVIDRequest{
		Csrs: make(map[string][]byte),
	}

	update, err := m.client.FetchUpdates(ctx, req, false)
	if err != nil {
		return nil, err
	}

	bundles, err := parseBundles(update.Bundles)
	if err != nil {
		return nil, err
	}

	return &cache.UpdateEntries{
		Bundles:             bundles,
		RegistrationEntries: update.Entries,
	}, nil
}

func newCSR(spiffeID string) (pk *ecdsa.PrivateKey, csr []byte, err error) {
	pk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	csr, err = util.MakeCSR(pk, spiffeID)
	if err != nil {
		return nil, nil, err
	}
	return
}

func parseBundles(bundles map[string]*common.Bundle) (map[string]*cache.Bundle, error) {
	out := make(map[string]*cache.Bundle, len(bundles))
	for _, bundle := range bundles {
		bundle, err := bundleutil.BundleFromProto(bundle)
		if err != nil {
			return nil, err
		}
		out[bundle.TrustDomainID()] = bundle
	}
	return out, nil
}

// stringsEqual determines whether two string slices are equal or not
func stringsEqual(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}

	for i, s := range x {
		if s != y[i] {
			return false
		}
	}

	return true
}
