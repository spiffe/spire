package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	observer "github.com/imkira/go-observer"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/common/backoff"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/svid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"
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

	// GetRotationMtx returns a mutex that locks in SVIDs rotations
	GetRotationMtx() *sync.RWMutex

	// GetCurrentCredentials returns the current SVID and key
	GetCurrentCredentials() svid.State

	// SetRotationFinishedHook sets a hook that will be called when a rotation finished
	SetRotationFinishedHook(func())

	// MatchingIdentities returns all of the cached identities whose
	// registration entry selectors are a subset of the passed selectors.
	MatchingIdentities(selectors []*common.Selector) []cache.Identity

	// FetchWorkloadUpdates gets the latest workload update for the selectors
	FetchWorkloadUpdate(selectors []*common.Selector) *cache.WorkloadUpdate

	// FetchJWTSVID returns a JWT SVID for the specified SPIFFEID and audience. If there
	// is no JWT cached, the manager will get one signed upstream.
	FetchJWTSVID(ctx context.Context, spiffeID string, audience []string) (*client.JWTSVID, error)

	// CountSVIDs returns the amount of X509 SVIDs on memory
	CountSVIDs() int

	// GetLastSync returns the last successful rotation timestamp
	GetLastSync() time.Time

	// GetBundle get latest cached bundle
	GetBundle() *cache.Bundle
}

type manager struct {
	c *Config

	// Fields protected by mtx mutex.
	mtx *sync.RWMutex

	cache *cache.Cache
	svid  svid.Rotator

	svidCachePath   string
	bundleCachePath string

	// backoff calculator for fetch interval, backing off if error is returned on
	// fetch attempt
	backoff backoff.BackOff

	client client.Client

	clk clock.Clock

	// Saves last success sync
	lastSync time.Time
}

func (m *manager) Initialize(ctx context.Context) error {
	m.storeSVID(m.svid.State().SVID)
	m.storeBundle(m.cache.Bundle())

	err := m.storePrivateKey(ctx, m.c.SVIDKey)
	if err != nil {
		return fmt.Errorf("failed to store private key: %v", err)
	}

	m.backoff = backoff.NewBackoff(m.clk, m.c.SyncInterval)

	err = m.synchronize(ctx)
	if nodeutil.ShouldAgentReattest(err) {
		m.c.Log.WithError(err).Error("Agent needs to re-attest: removing SVID and shutting down")
		m.deleteSVID()
	}
	return err
}

func (m *manager) Run(ctx context.Context) error {
	defer m.client.Release()

	err := util.RunTasks(ctx,
		m.runSynchronizer,
		m.runSVIDObserver,
		m.runBundleObserver,
		m.svid.Run)

	switch {
	case err == nil || err == context.Canceled:
		m.c.Log.Info("Cache manager stopped")
		return nil
	case nodeutil.ShouldAgentReattest(err):
		m.c.Log.WithError(err).Warn("Agent needs to re-attest; removing SVID and shutting down")
		m.deleteSVID()
		return err
	default:
		m.c.Log.WithError(err).Error("Cache manager crashed")
		return err
	}
}

func (m *manager) SubscribeToCacheChanges(selectors cache.Selectors) cache.Subscriber {
	return m.cache.SubscribeToWorkloadUpdates(selectors)
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

func (m *manager) MatchingIdentities(selectors []*common.Selector) []cache.Identity {
	return m.cache.MatchingIdentities(selectors)
}

func (m *manager) CountSVIDs() int {
	return m.cache.CountSVIDs()
}

// FetchWorkloadUpdates gets the latest workload update for the selectors
func (m *manager) FetchWorkloadUpdate(selectors []*common.Selector) *cache.WorkloadUpdate {
	return m.cache.FetchWorkloadUpdate(selectors)
}

func (m *manager) FetchJWTSVID(ctx context.Context, spiffeID string, audience []string) (*client.JWTSVID, error) {
	now := m.clk.Now()

	cachedSVID, ok := m.cache.GetJWTSVID(spiffeID, audience)
	if ok && !rotationutil.JWTSVIDExpiresSoon(cachedSVID, now) {
		return cachedSVID, nil
	}

	entryID := m.getEntryID(spiffeID)
	if entryID == "" {
		return nil, errors.New("no entry found")
	}

	newSVID, err := m.client.NewJWTSVID(ctx, &node.JSR{
		SpiffeId: spiffeID,
		Audience: audience,
	}, entryID)
	switch {
	case err == nil:
	case cachedSVID == nil:
		return nil, err
	case rotationutil.JWTSVIDExpired(cachedSVID, now):
		return nil, fmt.Errorf("unable to renew JWT for %q (err=%v)", spiffeID, err)
	default:
		m.c.Log.WithError(err).WithField(telemetry.SPIFFEID, spiffeID).Warn("Unable to renew JWT; returning cached copy")
		return cachedSVID, nil
	}

	m.cache.SetJWTSVID(spiffeID, audience, newSVID)
	return newSVID, nil
}

func (m *manager) getEntryID(spiffeID string) string {
	for _, identity := range m.cache.Identities() {
		if identity.Entry.SpiffeId == spiffeID {
			return identity.Entry.EntryId
		}
	}
	return ""
}

func (m *manager) runSynchronizer(ctx context.Context) error {
	for {
		select {
		case <-m.clk.After(m.backoff.NextBackOff()):
		case <-ctx.Done():
			return nil
		}

		err := m.synchronize(ctx)
		switch {
		case err != nil && nodeutil.ShouldAgentReattest(err):
			m.c.Log.WithError(err).Error("Synchronize failed")
			return err
		case err != nil:
			// Just log the error and wait for next synchronization
			m.c.Log.WithError(err).Error("Synchronize failed")
		default:
			m.backoff.Reset()
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

			err := m.storePrivateKey(ctx, s.Key)
			if err != nil {
				m.c.Log.WithError(err).Error("Failed to store private key")
				continue
			}

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
		m.c.Log.WithError(err).Warn("Could not store SVID")
	}
}

func (m *manager) storeBundle(bundle *bundleutil.Bundle) {
	var rootCAs []*x509.Certificate
	if bundle != nil {
		rootCAs = bundle.RootCAs()
	}
	err := StoreBundle(m.bundleCachePath, rootCAs)
	if err != nil {
		m.c.Log.WithError(err).Error("Could not store bundle")
	}
}

func (m *manager) storePrivateKey(ctx context.Context, key *ecdsa.PrivateKey) error {
	km := m.c.Catalog.GetKeyManager()
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	if _, err = km.StorePrivateKey(ctx, &keymanager.StorePrivateKeyRequest{PrivateKey: keyBytes}); err != nil {
		return err
	}

	return nil
}

func (m *manager) deleteSVID() {
	if err := DeleteSVID(m.svidCachePath); err != nil {
		m.c.Log.WithError(err).Error("Failed to remove SVID")
	}
}
