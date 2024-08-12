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
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/common/backoff"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/manager/storecache"
	"github.com/spiffe/spire/pkg/agent/storage"
	"github.com/spiffe/spire/pkg/agent/svid"
	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/api/limits"
	"github.com/spiffe/spire/proto/spire/common"
)

const (
	maxSVIDSyncInterval = 4 * time.Minute
	// for sync interval of 5 sec this will result in max of 4 mins of backoff
	synchronizeMaxIntervalMultiple = 48
	// for larger sync interval set max interval as 8 mins
	synchronizeMaxInterval = 8 * time.Minute
	// default sync interval is used between retries of initial sync
	defaultSyncInterval = 5 * time.Second
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
	FetchJWTSVID(ctx context.Context, entry *common.RegistrationEntry, audience []string) (*client.JWTSVID, error)

	// CountX509SVIDs returns the amount of X509 SVIDs on memory
	CountX509SVIDs() int

	// CountJWTSVIDs returns the amount of JWT SVIDs on memory
	CountJWTSVIDs() int

	// CountSVIDStoreX509SVIDs returns the amount of x509 SVIDs on SVIDStore in-memory cache
	CountSVIDStoreX509SVIDs() int

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
	Bundle() *spiffebundle.Bundle

	// SyncSVIDsWithSubscribers syncs SVID cache
	SyncSVIDsWithSubscribers()

	// SubscribeToWorkloadUpdates creates a subscriber for given selector set.
	SubscribeToWorkloadUpdates(ctx context.Context, selectors cache.Selectors) (cache.Subscriber, error)

	// SubscribeToBundleChanges creates a stream for providing bundle changes
	SubscribeToBundleChanges() *cache.BundleStream

	// MatchingRegistrationEntries with given selectors
	MatchingRegistrationEntries(selectors []*common.Selector) []*common.RegistrationEntry

	// CountX509SVIDs in cache stored
	CountX509SVIDs() int

	// CountJWTSVIDs in cache stored
	CountJWTSVIDs() int

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
	// csrSizeLimitedBackoff backs off the number of csrs if error is returned on fetch svid attempt
	csrSizeLimitedBackoff backoff.SizeLimitedBackOff

	client client.Client

	clk clock.Clock

	// Saves last success sync
	lastSync time.Time

	// Cache for 'storable' SVIDs
	svidStoreCache *storecache.Cache

	// These two maps hold onto the synced entries and bundles. They are used
	// to do efficient revision-based syncing and are updated with any changes
	// during each sync event. They are also used as the inputs to update the
	// cache.
	syncedEntries map[string]*common.RegistrationEntry
	syncedBundles map[string]*common.Bundle
}

func (m *manager) Initialize(ctx context.Context) error {
	m.storeSVID(m.svid.State().SVID, m.svid.State().Reattestable)
	m.storeBundle(m.cache.Bundle())

	// upper limit of backoff is 8 mins
	synchronizeBackoffMaxInterval := min(synchronizeMaxInterval, synchronizeMaxIntervalMultiple*m.c.SyncInterval)

	m.synchronizeBackoff = backoff.NewBackoff(m.clk, m.c.SyncInterval, backoff.WithMaxInterval(synchronizeBackoffMaxInterval))
	m.svidSyncBackoff = backoff.NewBackoff(m.clk, cache.SVIDSyncInterval, backoff.WithMaxInterval(maxSVIDSyncInterval))
	m.csrSizeLimitedBackoff = backoff.NewSizeLimitedBackOff(limits.SignLimitPerIP)
	m.syncedEntries = make(map[string]*common.RegistrationEntry)
	m.syncedBundles = make(map[string]*common.Bundle)

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

	for {
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
			m.c.Log.WithError(err).Warn("Agent needs to re-attest; will attempt to re-attest")
			reattestError := m.svid.Reattest(ctx)
			if reattestError != nil {
				m.c.Log.WithError(reattestError).Error("Agent failed re-attestation; removing SVID and shutting down")
				m.deleteSVID()
				return err
			}
		case nodeutil.ShouldAgentShutdown(err):
			m.c.Log.WithError(err).Warn("Agent is banned: removing SVID and shutting down")
			m.deleteSVID()
			return err
		default:
			m.c.Log.WithError(err).Error("Cache manager crashed")
			return err
		}
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

func (m *manager) CountX509SVIDs() int {
	return m.cache.CountX509SVIDs()
}

func (m *manager) CountJWTSVIDs() int {
	return m.cache.CountJWTSVIDs()
}

func (m *manager) CountSVIDStoreX509SVIDs() int {
	return m.svidStoreCache.CountX509SVIDs()
}

// FetchWorkloadUpdates gets the latest workload update for the selectors
func (m *manager) FetchWorkloadUpdate(selectors []*common.Selector) *cache.WorkloadUpdate {
	return m.cache.FetchWorkloadUpdate(selectors)
}

func (m *manager) FetchJWTSVID(ctx context.Context, entry *common.RegistrationEntry, audience []string) (*client.JWTSVID, error) {
	spiffeID, err := spiffeid.FromString(entry.SpiffeId)
	if err != nil {
		return nil, errors.New("Invalid SPIFFE ID: " + err.Error())
	}

	now := m.clk.Now()
	cachedSVID, ok := m.cache.GetJWTSVID(spiffeID, audience)
	if ok && !m.c.RotationStrategy.JWTSVIDExpiresSoon(cachedSVID, now) {
		return cachedSVID, nil
	}

	newSVID, err := m.client.NewJWTSVID(ctx, entry.EntryId, audience)
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

func (m *manager) runSynchronizer(ctx context.Context) error {
	syncInterval := min(m.synchronizeBackoff.NextBackOff(), defaultSyncInterval)
	for {
		select {
		case <-m.clk.After(syncInterval):
		case <-ctx.Done():
			return nil
		}

		err := m.synchronize(ctx)
		switch {
		case nodeutil.IsUnknownAuthorityError(err):
			m.c.Log.WithError(err).Info("Synchronize failed, non-recoverable error")
			return fmt.Errorf("failed to sync with SPIRE Server: %w", err)
		case err != nil && nodeutil.ShouldAgentReattest(err):
			fallthrough
		case nodeutil.ShouldAgentShutdown(err):
			m.c.Log.WithError(err).Error("Synchronize failed")
			return err
		case err != nil:
			m.c.Log.WithError(err).Error("Synchronize failed")
			// Increase sync interval and wait for next synchronization
			syncInterval = m.synchronizeBackoff.NextBackOff()
		default:
			m.synchronizeBackoff.Reset()
			syncInterval = m.synchronizeBackoff.NextBackOff()

			// Clamp the sync interval to the default value when the agent doesn't have any SVIDs cached
			// AND the previous sync request succeeded
			if m.cache.CountX509SVIDs() == 0 {
				syncInterval = min(syncInterval, defaultSyncInterval)
			}
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

func (m *manager) storeBundle(bundle *spiffebundle.Bundle) {
	var rootCAs []*x509.Certificate
	if bundle != nil {
		rootCAs = bundle.X509Authorities()
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
