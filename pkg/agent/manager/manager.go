package manager

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	observer "github.com/imkira/go-observer"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/svid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
)

// Cache Manager errors
var (
	ErrNotCached = errors.New("not cached")
)

// Manager provides cache management functionalities for agents.
type Manager interface {
	// Initialize initializes the manager.
	Initialize(ctx context.Context) error

	// Run runs the manager. It will block until the context is cancelled.
	Run(ctx context.Context) error

	// SubscribeToCacheChanges returns a Subscriber on which cache entry updates are sent
	// for a particular set of selectors.
	SubscribeToCacheChanges(key cache.Selectors) cache.Subscriber

	// SubscribeToSVIDChanges returns a new observer.Stream on which svid.State instances are received
	// each time an SVID rotation finishes.
	SubscribeToSVIDChanges() observer.Stream

	// SubscribeToBundleChanges returns a new bundle stream on which
	// map[string][]*x509.Certificate instances are received each time the
	// bundle changes.
	SubscribeToBundleChanges() *cache.BundleStream

	// MatchingEntries takes a slice of selectors, and iterates over all the in force entries
	// in order to find matching cache entries. A cache entry is matched when its RegistrationEntry's
	// selectors are included in the set of selectors passed as parameter.
	MatchingEntries(selectors []*common.Selector) []*cache.Entry

	// FetchWorkloadUpdates gets the latest workload update for the selectors
	FetchWorkloadUpdate(selectors []*common.Selector) *cache.WorkloadUpdate

	// FetchJWTSVID returns a JWT SVID for the specified SPIFFEID and audience. If there
	// is no JWT cached, the manager will get one signed upstream.
	FetchJWTSVID(ctx context.Context, spiffeID string, audience []string) (*client.JWTSVID, error)
}

type manager struct {
	c *Config

	// Fields protected by mtx mutex.
	mtx *sync.RWMutex

	cache cache.Cache
	svid  svid.Rotator

	spiffeID string

	svidCachePath   string
	bundleCachePath string

	client client.Client

	clk clock.Clock
}

func (m *manager) Initialize(ctx context.Context) error {
	m.storeSVID(m.svid.State().SVID)
	m.storeBundle(m.cache.Bundle())

	return m.synchronize(ctx)
}

func (m *manager) Run(ctx context.Context) error {
	defer m.client.Release()

	err := util.RunTasks(ctx,
		m.runSynchronizer,
		m.runSVIDObserver,
		m.runBundleObserver,
		m.svid.Run)
	if err != nil && err != context.Canceled {
		m.c.Log.Errorf("cache manager crashed: %v", err)
		return err
	}

	m.c.Log.Info("cache manager stopped")
	return nil
}

func (m *manager) SubscribeToCacheChanges(selectors cache.Selectors) cache.Subscriber {
	return m.cache.Subscribe(selectors)
}

func (m *manager) SubscribeToSVIDChanges() observer.Stream {
	return m.svid.Subscribe()
}

func (m *manager) SubscribeToBundleChanges() *cache.BundleStream {
	return m.cache.SubscribeToBundleChanges()
}

func (m *manager) MatchingEntries(selectors []*common.Selector) (entries []*cache.Entry) {
	for _, entry := range m.cache.Entries() {
		regEntrySelectors := selector.NewSetFromRaw(entry.RegistrationEntry.Selectors)
		if selector.NewSetFromRaw(selectors).IncludesSet(regEntrySelectors) {
			entries = append(entries, entry)
		}
	}
	return entries
}

// FetchWorkloadUpdates gets the latest workload update for the selectors
func (m *manager) FetchWorkloadUpdate(selectors []*common.Selector) *cache.WorkloadUpdate {
	return m.cache.FetchWorkloadUpdate(selectors)
}

func (m *manager) FetchJWTSVID(ctx context.Context, spiffeID string, audience []string) (*client.JWTSVID, error) {
	now := m.clk.Now()

	cachedSVID, ok := m.cache.GetJWTSVID(spiffeID, audience)
	if ok && !jwtSVIDExpiresSoon(cachedSVID, now) {
		return cachedSVID, nil
	}

	newSVID, err := m.client.FetchJWTSVID(ctx, &node.JSR{
		SpiffeId: spiffeID,
		Audience: audience,
	})
	switch {
	case err == nil:
	case cachedSVID == nil:
		return nil, err
	case jwtSVIDExpired(cachedSVID, now):
		return nil, fmt.Errorf("unable to renew JWT for %q (err=%v)", spiffeID, err)
	default:
		m.c.Log.Warnf("unable to renew JWT for %q; returning cached copy (err=%v)", spiffeID, err)
		return cachedSVID, nil
	}

	m.cache.SetJWTSVID(spiffeID, audience, newSVID)
	return newSVID, nil
}

func (m *manager) runSynchronizer(ctx context.Context) error {
	t := m.clk.Ticker(m.c.SyncInterval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			err := m.synchronize(ctx)
			if err != nil {
				// Just log the error to keep waiting for next sinchronization...
				m.c.Log.Errorf("synchronize failed: %v", err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *manager) runSVIDObserver(ctx context.Context) error {
	svidStream := m.SubscribeToSVIDChanges()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-svidStream.Changes():
			s := svidStream.Next().(svid.State)
			m.storeSVID(s.SVID)
		}
	}
}

func (m *manager) runBundleObserver(ctx context.Context) error {
	bundleStream := m.SubscribeToBundleChanges()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-bundleStream.Changes():
			b := bundleStream.Next()
			m.storeBundle(b[m.c.TrustDomain.String()])
		}
	}
}

func (m *manager) storeSVID(svidChain []*x509.Certificate) {
	err := StoreSVID(m.svidCachePath, svidChain)
	if err != nil {
		m.c.Log.Warnf("could not store SVID: %v", err)
	}
}

func (m *manager) storeBundle(bundle *bundleutil.Bundle) {
	var rootCAs []*x509.Certificate
	if bundle != nil {
		rootCAs = bundle.RootCAs()
	}
	err := StoreBundle(m.bundleCachePath, rootCAs)
	if err != nil {
		m.c.Log.Errorf("could not store bundle: %v", err)
	}
}

func jwtSVIDExpiresSoon(svid *client.JWTSVID, now time.Time) bool {
	if jwtSVIDExpired(svid, now) {
		return true
	}

	// if the SVID has less than half of its lifetime left, consider it
	// as expiring soon
	if !now.Before(svid.IssuedAt.Add(svid.ExpiresAt.Sub(svid.IssuedAt) / 2)) {
		return true
	}

	return false
}

func jwtSVIDExpired(svid *client.JWTSVID, now time.Time) bool {
	return !now.Before(svid.ExpiresAt)
}
