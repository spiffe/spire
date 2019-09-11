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
	update, err := m.fetchUpdates(ctx, nil)
	if err != nil {
		return err
	}

	// update the cache and build a list of CSRs that need to be processed
	// in this interval.
	//
	// the values in `update` now belong to the cache. DO NOT MODIFY.
	var csrs []csrRequest
	var expiring int
	m.cache.Update(update, func(entry *common.RegistrationEntry, svid *cache.X509SVID) {
		var expiresAt time.Time
		switch {
		case svid == nil:
			// no SVID
		case len(svid.Chain) == 0:
			// SVID has an empty chain. this is not expected to happen.
			m.c.Log.WithFields(logrus.Fields{
				telemetry.RegistrationID: entry.EntryId,
				telemetry.SPIFFEID:       entry.SpiffeId,
			}).Warn("cached X509 SVID is empty")
		case isSVIDStale(m.c.Clk.Now(), svid.Chain[0]):
			// SVID has expired
			expiresAt = svid.Chain[0].NotAfter
			expiring++
		default:
			// SVID is good
			return
		}
		// we've exceeded the CSR limit, don't make any more CSRs
		if len(csrs) < node.CSRLimit {
			csrs = append(csrs, csrRequest{
				EntryID:              entry.EntryId,
				SpiffeID:             entry.SpiffeId,
				CurrentSVIDExpiresAt: expiresAt,
			})
		}
	})
	telemetry_agent.AddCacheManagerExpiredSVIDsSample(m.c.Metrics, float32(expiring))
	m.c.Log.WithField(telemetry.ExpiringSVIDs, expiring).Debug("Updated SVIDs in cache")

	if len(csrs) > 0 {
		update, err := m.fetchUpdates(ctx, csrs)
		if err != nil {
			return err
		}
		// the values in `update` now belong to the cache. DO NOT MODIFY.
		m.cache.Update(update, nil)
	}
	return nil
}

func (m *manager) fetchUpdates(ctx context.Context, csrs []csrRequest) (_ *cache.CacheUpdate, err error) {
	// Put all the CSRs in an array to make just one call with all the CSRs.
	counter := telemetry_agent.StartManagerFetchUpdatesCall(m.c.Metrics)
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
		counter.AddLabel(telemetry.SPIFFEID, csr.SpiffeID)
		counter.AddLabel(telemetry.RegistrationID, csr.EntryID)

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

	bundles, err := parseBundles(update.Bundles)
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

	return &cache.CacheUpdate{
		Bundles:             bundles,
		RegistrationEntries: update.Entries,
		X509SVIDs:           byEntryID,
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

func isSVIDStale(now time.Time, svid *x509.Certificate) bool {
	ttl := svid.NotAfter.Sub(now)
	lifetime := svid.NotAfter.Sub(svid.NotBefore)
	return ttl < lifetime/2
}
