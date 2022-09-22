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
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/common/backoff"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/manager/storecache"
	"github.com/spiffe/spire/pkg/agent/storage"
	"github.com/spiffe/spire/pkg/agent/svid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
)

// Manager provides cache management functionalities for agents.
type Manager interface {
	// Initialize initializes the manager.
	Initialize(ctx context.Context) error

	// Run runs the manager. It will block until the context is cancelled.
	Run(ctx context.Context) error

	// SubscribeToCacheChanges returns a Subscriber on which cache entry updates are sent
	// for a particular set of selectors.
	SubscribeToCacheChanges(ctx context.Context, key cache.Selectors) (cache.Subscriber, error)

	// SubscribeToSVIDChanges returns a new observer.Stream on which svid.State instances are received
	// each time an SVID rotation finishes.
	SubscribeToSVIDChanges() observer.Stream

	// SubscribeToBundleChanges returns a new bundle stream on which
	// map[string][]*x509.Certificate instances are received each time the
	// bundle changes.
	SubscribeToBundleChanges() *cache.BundleStream

	// GetRotationMtx returns a mutex that locks in SVIDs rotations
	GetRotationMtx() *sync.RWMutex

	// GetCurrentCredentials returns the current SVID and key
	GetCurrentCredentials() svid.State

	// SetRotationFinishedHook sets a hook that will be called when a rotation finished
	SetRotationFinishedHook(func())

	// MatchingRegistrationEntries returns all of the cached registration entries whose
	// selectors are a subset of the passed selectors.
	MatchingRegistrationEntries(selectors []*common.Selector) []*common.RegistrationEntry

	// FetchWorkloadUpdates gets the latest workload update for the selectors
	FetchWorkloadUpdate(selectors []*common.Selector) *cache.WorkloadUpdate

	// FetchJWTSVID returns a JWT SVID for the specified SPIFFEID and audience. If there
	// is no JWT cached, the manager will get one signed upstream.
	FetchJWTSVID(ctx context.Context, spiffeID spiffeid.ID, audience []string) (*client.JWTSVID, error)

	// CountSVIDs returns the amount of X509 SVIDs on memory
	CountSVIDs() int

	// GetLastSync returns the last successful rotation timestamp
	GetLastSync() time.Time

	// GetBundle get latest cached bundle
	GetBundle() *cache.Bundle
}

// Cache stores each registration entry, signed X509-SVIDs for those entries,
// bundles, and JWT SVIDs for the agent.
type Cache interface {
	SVIDCache

	// Bundle gets latest cached bundle
	Bundle() *bundleutil.Bundle

	// SyncSVIDsWithSubscribers syncs SVID cache
	SyncSVIDsWithSubscribers()

	// SubscribeToWorkloadUpdates creates a subscriber for given selector set.
	SubscribeToWorkloadUpdates(ctx context.Context, selectors cache.Selectors) (cache.Subscriber, error)

	// SubscribeToBundleChanges creates a stream for providing bundle changes
	SubscribeToBundleChanges() *cache.BundleStream

	// MatchingRegistrationEntries with given selectors
	MatchingRegistrationEntries(selectors []*common.Selector) []*common.RegistrationEntry

	// CountSVIDs in cache stored
	CountSVIDs() int

	// FetchWorkloadUpdate for given selectors
	FetchWorkloadUpdate(selectors []*common.Selector) *cache.WorkloadUpdate

	// GetJWTSVID provides JWT-SVID
	GetJWTSVID(id spiffeid.ID, audience []string) (*client.JWTSVID, bool)

	// SetJWTSVID adds JWT-SVID to cache
	SetJWTSVID(id spiffeid.ID, audience []string, svid *client.JWTSVID)

	// Entries get all registration entries
	Entries() []*common.RegistrationEntry

	// Identities get all identities in cache
	Identities() []cache.Identity
}

type manager struct {
	c *Config

	// Fields protected by mtx mutex.
	mtx *sync.RWMutex
	// Protects multiple goroutines from requesting SVID signings at the same time
	updateSVIDMu sync.RWMutex

	cache Cache
	svid  svid.Rotator

	storage storage.Storage

	// synchronizeBackoff calculator for fetch interval, backing off if error is returned on
	// fetch attempt
	synchronizeBackoff backoff.BackOff
	svidSyncBackoff    backoff.BackOff

	client client.Client

	clk clock.Clock

	// Saves last success sync
	lastSync time.Time

	// Cache for 'storable' SVIDs
	svidStoreCache *storecache.Cache
}

func (m *manager) Initialize(ctx context.Context) error {
	m.storeSVID(m.svid.State().SVID, m.svid.State().Reattestable)
	m.storeBundle(m.cache.Bundle())

	m.synchronizeBackoff = backoff.NewBackoff(m.clk, m.c.SyncInterval)
	m.svidSyncBackoff = backoff.NewBackoff(m.clk, cache.SVIDSyncInterval)

	err := m.synchronize(ctx)
	if nodeutil.ShouldAgentReattest(err) {
		m.c.Log.WithError(err).Error("Agent needs to re-attest: removing SVID and shutting down")
		m.deleteSVID()
	}
	if nodeutil.ShouldAgentShutdown(err) {
		m.c.Log.WithError(err).Error("Agent is banned: removing SVID and shutting down")
		m.deleteSVID()
	}
	return err
}

func (m *manager) Run(ctx context.Context) error {
	defer m.client.Release()

	err := util.RunTasks(ctx,
		m.runSynchronizer,
		m.runSyncSVIDs,
		m.runSVIDObserver,
		m.runBundleObserver,
		m.svid.Run)

	switch {
	case err == nil || errors.Is(err, context.Canceled):
		m.c.Log.Info("Cache manager stopped")
		return nil
	case nodeutil.ShouldAgentReattest(err):
		m.c.Log.WithError(err).Warn("Agent needs to re-attest; removing SVID and shutting down")
		m.deleteSVID()
		return err
	case nodeutil.ShouldAgentShutdown(err):
		m.c.Log.WithError(err).Warn("Agent is banned: removing SVID and shutting down")
		m.deleteSVID()
		return err
	default:
		m.c.Log.WithError(err).Error("Cache manager crashed")
		return err
	}
}

func (m *manager) SubscribeToCacheChanges(ctx context.Context, selectors cache.Selectors) (cache.Subscriber, error) {
	return m.cache.SubscribeToWorkloadUpdates(ctx, selectors)
}

func (m *manager) SubscribeToSVIDChanges() observer.Stream {
	return m.svid.Subscribe()
}

func (m *manager) SubscribeToBundleChanges() *cache.BundleStream {
	return m.cache.SubscribeToBundleChanges()
}

func (m *manager) GetRotationMtx() *sync.RWMutex {
	return m.svid.GetRotationMtx()
}

func (m *manager) GetCurrentCredentials() svid.State {
	return m.svid.State()
}

func (m *manager) SetRotationFinishedHook(f func()) {
	m.svid.SetRotationFinishedHook(f)
}

func (m *manager) MatchingRegistrationEntries(selectors []*common.Selector) []*common.RegistrationEntry {
	return m.cache.MatchingRegistrationEntries(selectors)
}

func (m *manager) CountSVIDs() int {
	return m.cache.CountSVIDs()
}

// FetchWorkloadUpdates gets the latest workload update for the selectors
func (m *manager) FetchWorkloadUpdate(selectors []*common.Selector) *cache.WorkloadUpdate {
	return m.cache.FetchWorkloadUpdate(selectors)
}

func (m *manager) FetchJWTSVID(ctx context.Context, spiffeID spiffeid.ID, audience []string) (*client.JWTSVID, error) {
	now := m.clk.Now()

	cachedSVID, ok := m.cache.GetJWTSVID(spiffeID, audience)
	if ok && !rotationutil.JWTSVIDExpiresSoon(cachedSVID, now) {
		return cachedSVID, nil
	}

	entryID := m.getEntryID(spiffeID.String())
	if entryID == "" {
		return nil, errors.New("no entry found")
	}

	newSVID, err := m.client.NewJWTSVID(ctx, entryID, audience)
	switch {
	case err == nil:
	case cachedSVID == nil:
		return nil, err
	case rotationutil.JWTSVIDExpired(cachedSVID, now):
		return nil, fmt.Errorf("unable to renew JWT for %q (err=%w)", spiffeID, err)
	default:
		m.c.Log.WithError(err).WithField(telemetry.SPIFFEID, spiffeID).Warn("Unable to renew JWT; returning cached copy")
		return cachedSVID, nil
	}

	m.cache.SetJWTSVID(spiffeID, audience, newSVID)
	return newSVID, nil
}

func (m *manager) getEntryID(spiffeID string) string {
	for _, entry := range m.cache.Entries() {
		if entry.SpiffeId == spiffeID {
			return entry.EntryId
		}
	}
	return ""
}

func (m *manager) runSynchronizer(ctx context.Context) error {
	for {
		select {
		case <-m.clk.After(m.synchronizeBackoff.NextBackOff()):
		case <-ctx.Done():
			return nil
		}

		err := m.synchronize(ctx)
		switch {
		case err != nil && nodeutil.ShouldAgentReattest(err):
			m.c.Log.WithError(err).Error("Synchronize failed")
			return err
		case nodeutil.ShouldAgentShutdown(err):
			m.c.Log.WithError(err).Error("Synchronize failed")
			return err
		case err != nil:
			// Just log the error and wait for next synchronization
			m.c.Log.WithError(err).Error("Synchronize failed")
		default:
			m.synchronizeBackoff.Reset()
		}
	}
}

func (m *manager) runSyncSVIDs(ctx context.Context) error {
	for {
		select {
		case <-m.clk.After(m.svidSyncBackoff.NextBackOff()):
		case <-ctx.Done():
			return nil
		}

		err := m.syncSVIDs(ctx)
		switch {
		case err != nil:
			// Just log the error and wait for next synchronization
			m.c.Log.WithError(err).Error("SVID sync failed")
		default:
			m.svidSyncBackoff.Reset()
		}
	}
}

func (m *manager) setLastSync() {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.lastSync = m.clk.Now()
}

func (m *manager) GetLastSync() time.Time {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return m.lastSync
}

func (m *manager) GetBundle() *cache.Bundle {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return m.cache.Bundle()
}

func (m *manager) runSVIDObserver(ctx context.Context) error {
	svidStream := m.SubscribeToSVIDChanges()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-svidStream.Changes():
			s := svidStream.Next().(svid.State)
			m.storeSVID(s.SVID, s.Reattestable)
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
			m.storeBundle(b[m.c.TrustDomain])
		}
	}
}

func (m *manager) storeSVID(svidChain []*x509.Certificate, reattestable bool) {
	if err := m.storage.StoreSVID(svidChain, reattestable); err != nil {
		m.c.Log.WithError(err).Warn("Could not store SVID")
	}
}

func (m *manager) storeBundle(bundle *bundleutil.Bundle) {
	var rootCAs []*x509.Certificate
	if bundle != nil {
		rootCAs = bundle.RootCAs()
	}
	if err := m.storage.StoreBundle(rootCAs); err != nil {
		m.c.Log.WithError(err).Error("Could not store bundle")
	}
}

func (m *manager) deleteSVID() {
	if err := m.storage.DeleteSVID(); err != nil {
		m.c.Log.WithError(err).Error("Failed to remove SVID")
	}
}
