package manager

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/backoff"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/credvalidator"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	publishJWKTimeout         = 5 * time.Second
	safetyThresholdBundle     = 24 * time.Hour
	safetyThresholdCAJournals = time.Hour * 24 * 14 // Two weeks

	thirtyDays                  = 30 * 24 * time.Hour
	preparationThresholdCap     = thirtyDays
	preparationThresholdDivisor = 2

	sevenDays                  = 7 * 24 * time.Hour
	activationThresholdCap     = sevenDays
	activationThresholdDivisor = 6

	taintBackoffInterval       = 5 * time.Second
	taintBackoffMaxElapsedTime = 1 * time.Minute
)

type ManagedCA interface {
	SetX509CA(*ca.X509CA)
	SetJWTKey(*ca.JWTKey)
	NotifyTaintedX509Authorities([]*x509.Certificate)
}

type JwtKeyPublisher interface {
	PublishJWTKey(ctx context.Context, jwtKey *common.PublicKey) ([]*common.PublicKey, error)
}

type AuthorityManager interface {
	GetCurrentJWTKeySlot() Slot
	GetNextJWTKeySlot() Slot
	PrepareJWTKey(ctx context.Context) error
	RotateJWTKey(ctx context.Context)
	GetCurrentX509CASlot() Slot
	GetNextX509CASlot() Slot
	PrepareX509CA(ctx context.Context) error
	RotateX509CA(ctx context.Context)
	IsUpstreamAuthority() bool
	PublishJWTKey(ctx context.Context, jwtKey *common.PublicKey) ([]*common.PublicKey, error)
	NotifyTaintedX509Authority(ctx context.Context, authorityID string) error
	SubscribeToLocalBundle(ctx context.Context) error
}

type Config struct {
	CredBuilder   *credtemplate.Builder
	CredValidator *credvalidator.Validator
	CA            ManagedCA
	Catalog       catalog.Catalog
	TrustDomain   spiffeid.TrustDomain
	X509CAKeyType keymanager.KeyType
	JWTKeyType    keymanager.KeyType
	Dir           string
	Log           logrus.FieldLogger
	Metrics       telemetry.Metrics
	Clock         clock.Clock
}

type Manager struct {
	c                            Config
	caTTL                        time.Duration
	bundleUpdatedCh              chan struct{}
	taintedUpstreamAuthoritiesCh chan []*x509.Certificate
	upstreamClient               *ca.UpstreamClient
	upstreamPluginName           string

	currentX509CA *x509CASlot
	nextX509CA    *x509CASlot
	x509CAMutex   sync.RWMutex

	currentJWTKey *jwtKeySlot
	nextJWTKey    *jwtKeySlot
	jwtKeyMutex   sync.RWMutex

	journal *Journal

	// Used to log a warning only once when the UpstreamAuthority does not support JWT-SVIDs.
	jwtUnimplementedWarnOnce sync.Once

	// Used for testing backoff, must not be set in regular code
	triggerBackOffCh chan error
}

func NewManager(ctx context.Context, c Config) (*Manager, error) {
	if c.Clock == nil {
		c.Clock = clock.New()
	}

	m := &Manager{
		c:                            c,
		caTTL:                        c.CredBuilder.Config().X509CATTL,
		bundleUpdatedCh:              make(chan struct{}, 1),
		taintedUpstreamAuthoritiesCh: make(chan []*x509.Certificate, 1),
	}

	if upstreamAuthority, ok := c.Catalog.GetUpstreamAuthority(); ok {
		m.upstreamClient = ca.NewUpstreamClient(ca.UpstreamClientConfig{
			UpstreamAuthority: upstreamAuthority,
			BundleUpdater: &bundleUpdater{
				log:                         c.Log,
				trustDomainID:               c.TrustDomain.IDString(),
				ds:                          c.Catalog.GetDataStore(),
				updated:                     m.bundleUpdated,
				upstreamAuthoritiesTainted:  m.notifyUpstreamAuthoritiesTainted,
				processedTaintedAuthorities: map[string]struct{}{},
			},
		})
		m.upstreamPluginName = upstreamAuthority.Name()
	}

	loader := &SlotLoader{
		TrustDomain:    c.TrustDomain,
		Log:            c.Log,
		Dir:            c.Dir,
		Catalog:        c.Catalog,
		UpstreamClient: m.upstreamClient,
	}

	journal, slots, err := loader.load(ctx)
	if err != nil {
		return nil, err
	}

	now := m.c.Clock.Now()
	m.journal = journal
	if currentX509CA, ok := slots[CurrentX509CASlot]; ok {
		m.currentX509CA = currentX509CA.(*x509CASlot)

		if !currentX509CA.IsEmpty() && !currentX509CA.ShouldActivateNext(now) {
			// activate the X509CA immediately if it is set and not within
			// activation time of the next X509CA.
			m.activateX509CA(ctx)
		}
	}

	if nextX509CA, ok := slots[NextX509CASlot]; ok {
		m.nextX509CA = nextX509CA.(*x509CASlot)
	}

	if currentJWTKey, ok := slots[CurrentJWTKeySlot]; ok {
		m.currentJWTKey = currentJWTKey.(*jwtKeySlot)

		// TODO: Activation on journal depends on dates, it will need to be
		// refactored to allow to set a status, because when forcing a rotation,
		// we are no longer able to depend on a date.
		if !currentJWTKey.IsEmpty() && !currentJWTKey.ShouldActivateNext(now) {
			// activate the JWT key immediately if it is set and not within
			// activation time of the next JWT key.
			m.activateJWTKey(ctx)
		}
	}

	if nextJWTKey, ok := slots[NextJWTKeySlot]; ok {
		m.nextJWTKey = nextJWTKey.(*jwtKeySlot)
	}

	return m, nil
}

func (m *Manager) Close() {
	if m.upstreamClient != nil {
		_ = m.upstreamClient.Close()
	}
}

func (m *Manager) NotifyTaintedX509Authority(ctx context.Context, authorityID string) error {
	taintedAuthority, err := m.fetchRootCAByAuthorityID(ctx, authorityID)
	if err != nil {
		return err
	}

	m.c.CA.NotifyTaintedX509Authorities([]*x509.Certificate{taintedAuthority})
	return nil
}

func (m *Manager) GetCurrentX509CASlot() Slot {
	m.x509CAMutex.RLock()
	defer m.x509CAMutex.RUnlock()

	return m.currentX509CA
}

func (m *Manager) GetNextX509CASlot() Slot {
	m.x509CAMutex.RLock()
	defer m.x509CAMutex.RUnlock()

	return m.nextX509CA
}

func (m *Manager) PrepareX509CA(ctx context.Context) (err error) {
	counter := telemetry_server.StartServerCAManagerPrepareX509CACall(m.c.Metrics)
	defer counter.Done(&err)

	m.x509CAMutex.Lock()
	defer m.x509CAMutex.Unlock()

	// If current is not empty, prepare the next.
	// If the journal has been started, we will be preparing on next.
	// This is only needed when the journal has not been started.
	slot := m.currentX509CA
	if !slot.IsEmpty() {
		slot = m.nextX509CA
	}

	log := m.c.Log.WithField(telemetry.Slot, slot.id)
	log.Debug("Preparing X509 CA")

	slot.Reset()

	now := m.c.Clock.Now()
	km := m.c.Catalog.GetKeyManager()
	signer, err := km.GenerateKey(ctx, slot.KmKeyID(), m.c.X509CAKeyType)
	if err != nil {
		return err
	}

	var x509CA *ca.X509CA
	if m.upstreamClient != nil {
		x509CA, err = m.upstreamSignX509CA(ctx, signer)
		if err != nil {
			return err
		}
	} else {
		x509CA, err = m.selfSignX509CA(ctx, signer)
		if err != nil {
			return err
		}
	}

	slot.issuedAt = now
	slot.x509CA = x509CA
	slot.status = journal.Status_PREPARED
	// Set key from new CA, to be able to get it after
	// slot moved to old state
	slot.authorityID = x509util.SubjectKeyIDToString(x509CA.Certificate.SubjectKeyId)
	slot.upstreamAuthorityID = x509util.SubjectKeyIDToString(x509CA.Certificate.AuthorityKeyId)
	slot.publicKey = slot.x509CA.Certificate.PublicKey
	slot.notAfter = slot.x509CA.Certificate.NotAfter

	if err := m.journal.AppendX509CA(ctx, slot.id, slot.issuedAt, slot.x509CA); err != nil {
		log.WithError(err).Error("Unable to append X509 CA to journal")
	}

	m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:                slot.id,
		telemetry.IssuedAt:            slot.issuedAt,
		telemetry.Expiration:          slot.x509CA.Certificate.NotAfter,
		telemetry.SelfSigned:          m.upstreamClient == nil,
		telemetry.LocalAuthorityID:    slot.authorityID,
		telemetry.UpstreamAuthorityID: slot.upstreamAuthorityID,
	}).Info("X509 CA prepared")
	return nil
}

func (m *Manager) IsUpstreamAuthority() bool {
	return m.upstreamClient != nil
}

func (m *Manager) ActivateX509CA(ctx context.Context) {
	m.x509CAMutex.RLock()
	defer m.x509CAMutex.RUnlock()

	m.activateX509CA(ctx)
}

func (m *Manager) RotateX509CA(ctx context.Context) {
	m.x509CAMutex.Lock()
	defer m.x509CAMutex.Unlock()

	m.currentX509CA, m.nextX509CA = m.nextX509CA, m.currentX509CA
	m.nextX509CA.Reset()
	if err := m.journal.UpdateX509CAStatus(ctx, m.nextX509CA.AuthorityID(), journal.Status_OLD); err != nil {
		m.c.Log.WithError(err).Error("Failed to update status on X509CA journal entry")
	}

	m.activateX509CA(ctx)
}

func (m *Manager) GetCurrentJWTKeySlot() Slot {
	m.jwtKeyMutex.RLock()
	defer m.jwtKeyMutex.RUnlock()

	return m.currentJWTKey
}

func (m *Manager) GetNextJWTKeySlot() Slot {
	m.jwtKeyMutex.RLock()
	defer m.jwtKeyMutex.RUnlock()

	return m.nextJWTKey
}

func (m *Manager) PrepareJWTKey(ctx context.Context) (err error) {
	counter := telemetry_server.StartServerCAManagerPrepareJWTKeyCall(m.c.Metrics)
	defer counter.Done(&err)

	m.jwtKeyMutex.Lock()
	defer m.jwtKeyMutex.Unlock()

	// If current slot is not empty, use next to prepare
	slot := m.currentJWTKey
	if !slot.IsEmpty() {
		slot = m.nextJWTKey
	}

	log := m.c.Log.WithField(telemetry.Slot, slot.id)
	log.Debug("Preparing JWT key")

	slot.Reset()

	now := m.c.Clock.Now()
	notAfter := now.Add(m.caTTL)

	km := m.c.Catalog.GetKeyManager()
	signer, err := km.GenerateKey(ctx, slot.KmKeyID(), m.c.JWTKeyType)
	if err != nil {
		return err
	}

	jwtKey, err := newJWTKey(signer, notAfter)
	if err != nil {
		return err
	}

	publicKey, err := publicKeyFromJWTKey(jwtKey)
	if err != nil {
		return err
	}

	if _, err := m.PublishJWTKey(ctx, publicKey); err != nil {
		return err
	}

	slot.issuedAt = now
	slot.jwtKey = jwtKey
	slot.status = journal.Status_PREPARED
	slot.authorityID = jwtKey.Kid
	slot.notAfter = jwtKey.NotAfter

	if err := m.journal.AppendJWTKey(ctx, slot.id, slot.issuedAt, slot.jwtKey); err != nil {
		log.WithError(err).Error("Unable to append JWT key to journal")
	}

	m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:             slot.id,
		telemetry.IssuedAt:         slot.issuedAt,
		telemetry.Expiration:       slot.jwtKey.NotAfter,
		telemetry.LocalAuthorityID: slot.authorityID,
	}).Info("JWT key prepared")
	return nil
}

func (m *Manager) ActivateJWTKey(ctx context.Context) {
	m.jwtKeyMutex.RLock()
	defer m.jwtKeyMutex.RUnlock()

	m.activateJWTKey(ctx)
}

func (m *Manager) RotateJWTKey(ctx context.Context) {
	m.jwtKeyMutex.Lock()
	defer m.jwtKeyMutex.Unlock()

	m.currentJWTKey, m.nextJWTKey = m.nextJWTKey, m.currentJWTKey
	m.nextJWTKey.Reset()

	if err := m.journal.UpdateJWTKeyStatus(ctx, m.nextJWTKey.AuthorityID(), journal.Status_OLD); err != nil {
		m.c.Log.WithError(err).Error("Failed to update status on JWTKey journal entry")
	}

	m.activateJWTKey(ctx)
}

// PublishJWTKey publishes the passed JWK to the upstream server using the configured
// UpstreamAuthority plugin, then appends to the bundle the JWKs returned by the upstream server,
// and finally it returns the updated list of JWT keys contained in the bundle.
//
// The following cases may arise when calling this function:
//
// - The UpstreamAuthority plugin doesn't implement PublishJWTKey, in which case we receive an
// Unimplemented error from the upstream server, and hence we log a one time warning about this,
// append the passed JWK to the bundle, and return the updated list of JWT keys.
//
// - The UpstreamAuthority plugin returned an error, then we return the error.
//
// - There is no UpstreamAuthority plugin configured, then assumes we are the root server and
// just appends the passed JWK to the bundle and returns the updated list of JWT keys.
func (m *Manager) PublishJWTKey(ctx context.Context, jwtKey *common.PublicKey) ([]*common.PublicKey, error) {
	if m.upstreamClient != nil {
		publishCtx, cancel := context.WithTimeout(ctx, publishJWKTimeout)
		defer cancel()
		upstreamJWTKeys, err := m.upstreamClient.PublishJWTKey(publishCtx, jwtKey)
		switch {
		case status.Code(err) == codes.Unimplemented:
			// JWT Key publishing is not supported by the upstream plugin.
			// Issue a one-time warning and then fall through to the
			// appendBundle call below as if an upstream client was not
			// configured so the JWT key gets pushed into the local bundle.
			m.jwtUnimplementedWarnOnce.Do(func() {
				m.c.Log.WithField("plugin_name", m.upstreamPluginName).Warn("UpstreamAuthority plugin does not support JWT-SVIDs. Workloads managed " +
					"by this server may have trouble communicating with workloads outside " +
					"this cluster when using JWT-SVIDs.")
			})
		case err != nil:
			return nil, err
		default:
			return upstreamJWTKeys, nil
		}
	}

	bundle, err := m.appendBundle(ctx, nil, []*common.PublicKey{jwtKey})
	if err != nil {
		return nil, err
	}

	return bundle.JwtSigningKeys, nil
}

func (m *Manager) SubscribeToLocalBundle(ctx context.Context) error {
	if m.upstreamClient == nil {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			err := m.upstreamClient.SubscribeToLocalBundle(ctx)
			switch {
			case status.Code(err) == codes.Unimplemented:
				return nil
			case err != nil:
				return err
			default:
				return nil
			}
		}
	}
}

func (m *Manager) PruneBundle(ctx context.Context) (err error) {
	counter := telemetry_server.StartCAManagerPruneBundleCall(m.c.Metrics)
	defer counter.Done(&err)

	ds := m.c.Catalog.GetDataStore()
	expiresBefore := m.c.Clock.Now().Add(-safetyThresholdBundle)

	changed, err := ds.PruneBundle(ctx, m.c.TrustDomain.IDString(), expiresBefore)
	if err != nil {
		return fmt.Errorf("unable to prune bundle: %w", err)
	}

	if changed {
		telemetry_server.IncrManagerPrunedBundleCounter(m.c.Metrics)
		m.c.Log.Debug("Expired certificates were successfully pruned from bundle")
		m.bundleUpdated()
	}

	return nil
}

func (m *Manager) PruneCAJournals(ctx context.Context) (err error) {
	counter := telemetry_server.StartCAManagerPruneBundleCall(m.c.Metrics)
	defer counter.Done(&err)

	ds := m.c.Catalog.GetDataStore()
	expiresBefore := m.c.Clock.Now().Add(-safetyThresholdCAJournals)

	err = ds.PruneCAJournals(ctx, expiresBefore.Unix())
	if err != nil {
		return fmt.Errorf("unable to prune CA journals: %w", err)
	}
	return nil
}

// ProcessBundleUpdates Notify any bundle update, or process tainted authorities
func (m *Manager) ProcessBundleUpdates(ctx context.Context) {
	for {
		select {
		case <-m.bundleUpdatedCh:
			if err := m.notifyBundleUpdated(ctx); err != nil {
				m.c.Log.WithError(err).Warn("Failed to notify on bundle update")
			}
		case taintedAuthorities := <-m.taintedUpstreamAuthoritiesCh:
			if err := m.notifyTaintedAuthorities(ctx, taintedAuthorities); err != nil {
				m.c.Log.WithError(err).Error("Failed to force intermediate bundle rotation")
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (m *Manager) NotifyBundleLoaded(ctx context.Context) error {
	// if initialization has triggered a "bundle updated" event (e.g. server CA
	// was rotated), we want to drain it now as we're about to emit the initial
	// bundle loaded event.  otherwise, plugins will get an immediate "bundle
	// updated" event right after "bundle loaded".
	m.dropBundleUpdated()

	var bundle *common.Bundle
	return m.notify(ctx, "bundle loaded", true,
		func(ctx context.Context) (err error) {
			bundle, err = m.fetchRequiredBundle(ctx)
			return err
		},
		func(ctx context.Context, n notifier.Notifier) error {
			return n.NotifyAndAdviseBundleLoaded(ctx, bundle)
		},
	)
}

func (m *Manager) activateJWTKey(ctx context.Context) {
	log := m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:             m.currentJWTKey.id,
		telemetry.IssuedAt:         m.currentJWTKey.issuedAt,
		telemetry.Expiration:       m.currentJWTKey.jwtKey.NotAfter,
		telemetry.LocalAuthorityID: m.currentJWTKey.authorityID,
	})
	log.Info("JWT key activated")
	telemetry_server.IncrActivateJWTKeyManagerCounter(m.c.Metrics)

	m.currentJWTKey.status = journal.Status_ACTIVE
	if err := m.journal.UpdateJWTKeyStatus(ctx, m.currentJWTKey.AuthorityID(), journal.Status_ACTIVE); err != nil {
		log.WithError(err).Error("Failed to update to activated status on JWTKey journal entry")
	}

	m.c.CA.SetJWTKey(m.currentJWTKey.jwtKey)
}

func (m *Manager) activateX509CA(ctx context.Context) {
	log := m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:                m.currentX509CA.id,
		telemetry.IssuedAt:            m.currentX509CA.issuedAt,
		telemetry.Expiration:          m.currentX509CA.x509CA.Certificate.NotAfter,
		telemetry.LocalAuthorityID:    m.currentX509CA.authorityID,
		telemetry.UpstreamAuthorityID: m.currentX509CA.upstreamAuthorityID,
	})
	log.Info("X509 CA activated")
	telemetry_server.IncrActivateX509CAManagerCounter(m.c.Metrics)

	m.currentX509CA.status = journal.Status_ACTIVE
	if err := m.journal.UpdateX509CAStatus(ctx, m.currentX509CA.AuthorityID(), journal.Status_ACTIVE); err != nil {
		log.WithError(err).Error("Failed to update to activated status on X509CA journal entry")
	}

	ttl := m.currentX509CA.x509CA.Certificate.NotAfter.Sub(m.c.Clock.Now())
	telemetry_server.SetX509CARotateGauge(m.c.Metrics, m.c.TrustDomain.Name(), float32(ttl.Seconds()))
	m.c.Log.WithFields(logrus.Fields{
		telemetry.TrustDomainID: m.c.TrustDomain.IDString(),
		telemetry.TTL:           ttl.Seconds(),
	}).Debug("Successfully rotated X.509 CA")

	m.c.CA.SetX509CA(m.currentX509CA.x509CA)
}

func (m *Manager) bundleUpdated() {
	select {
	case m.bundleUpdatedCh <- struct{}{}:
	default:
	}
}

func (m *Manager) dropBundleUpdated() {
	select {
	case <-m.bundleUpdatedCh:
	default:
	}
}

func (m *Manager) notifyUpstreamAuthoritiesTainted(taintedAuthorities []*x509.Certificate) {
	select {
	case m.taintedUpstreamAuthoritiesCh <- taintedAuthorities:
	default:
	}
}

func (m *Manager) fetchRootCAByAuthorityID(ctx context.Context, authorityID string) (*x509.Certificate, error) {
	bundle, err := m.fetchRequiredBundle(ctx)
	if err != nil {
		return nil, err
	}

	for _, rootCA := range bundle.RootCas {
		if rootCA.TaintedKey {
			cert, err := x509.ParseCertificate(rootCA.DerBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse RootCA: %w", err)
			}

			skID := x509util.SubjectKeyIDToString(cert.SubjectKeyId)
			if authorityID == skID {
				return cert, nil
			}
		}
	}

	return nil, fmt.Errorf("no tainted root CA found with authority ID: %q", authorityID)
}

func (m *Manager) notifyTaintedAuthorities(ctx context.Context, taintedAuthorities []*x509.Certificate) error {
	taintBackoff := backoff.NewBackoff(
		m.c.Clock,
		taintBackoffInterval,
		backoff.WithMaxElapsedTime(taintBackoffMaxElapsedTime),
	)

	for {
		err := m.processTaintedUpstreamAuthorities(ctx, taintedAuthorities)
		if err == nil {
			break
		}

		nextDuration := taintBackoff.NextBackOff()
		if nextDuration == backoff.Stop {
			return err
		}
		m.c.Log.WithError(err).Warn("Failed to process tainted keys on upstream authority")
		if m.triggerBackOffCh != nil {
			m.triggerBackOffCh <- err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.c.Clock.After(nextDuration):
			continue
		}
	}

	return nil
}

func (m *Manager) processTaintedUpstreamAuthorities(ctx context.Context, taintedAuthorities []*x509.Certificate) error {
	// Nothing to rotate if no upstream authority is used
	if m.upstreamClient == nil {
		return errors.New("processing of tainted upstream authorities must not be reached when not using an upstream authority; please report this bug")
	}

	if len(taintedAuthorities) == 0 {
		// No tainted keys found
		return nil
	}

	m.c.Log.Debug("Processing tainted keys on upstream authority")

	currentSlotCA := m.currentX509CA.x509CA
	if ok := isX509AuthorityTainted(currentSlotCA, taintedAuthorities); ok {
		m.c.Log.Info("Current root CA is signed by a tainted upstream authority, preparing rotation")
		if ok := m.shouldPrepareX509CA(taintedAuthorities); ok {
			if err := m.PrepareX509CA(ctx); err != nil {
				return fmt.Errorf("failed to prepare x509 authority: %w", err)
			}
		}

		// Activate the prepared X.509 authority
		m.RotateX509CA(ctx)
	}

	// Now that we have rotated the intermediate, we can notify about the
	// tainted authorities, so agents and downstream servers can start forcing
	// the rotation of their SVIDs.
	ds := m.c.Catalog.GetDataStore()
	for _, each := range taintedAuthorities {
		skID := x509util.SubjectKeyIDToString(each.SubjectKeyId)
		if err := ds.TaintX509CA(ctx, m.c.TrustDomain.IDString(), skID); err != nil {
			return fmt.Errorf("could not taint X509 CA in datastore: %w", err)
		}
	}

	// Intermediate is safe. Notify rotator to force rotation
	// of tainted X.509 SVID.
	m.c.CA.NotifyTaintedX509Authorities(taintedAuthorities)

	return nil
}

func (m *Manager) notifyBundleUpdated(ctx context.Context) error {
	var bundle *common.Bundle
	return m.notify(ctx, "bundle updated", false,
		func(ctx context.Context) (err error) {
			bundle, err = m.fetchRequiredBundle(ctx)
			return err
		},
		func(ctx context.Context, n notifier.Notifier) error {
			return n.NotifyBundleUpdated(ctx, bundle)
		},
	)
}

func (m *Manager) notify(ctx context.Context, event string, advise bool, pre func(context.Context) error, do func(context.Context, notifier.Notifier) error) error {
	notifiers := m.c.Catalog.GetNotifiers()
	if len(notifiers) == 0 {
		return nil
	}

	if pre != nil {
		if err := pre(ctx); err != nil {
			return err
		}
	}

	errsCh := make(chan error, len(notifiers))
	for _, n := range notifiers {
		go func(n notifier.Notifier) {
			err := do(ctx, n)
			f := m.c.Log.WithFields(logrus.Fields{
				telemetry.Notifier: n.Name(),
				telemetry.Event:    event,
			})
			if err == nil {
				f.Debug("Notifier handled event")
			} else {
				f := f.WithError(err)
				if advise {
					f.Error("Notifier failed to handle event")
				} else {
					f.Warn("Notifier failed to handle event")
				}
			}
			errsCh <- err
		}(n)
	}

	var allErrs error
	for range notifiers {
		// don't select on the ctx here as we can rely on the plugins to
		// respond to context cancellation and return an error.
		if err := <-errsCh; err != nil {
			allErrs = errors.Join(allErrs, err)
		}
	}
	if allErrs != nil {
		return fmt.Errorf("one or more notifiers returned an error: %w", allErrs)
	}

	return nil
}

func (m *Manager) fetchRequiredBundle(ctx context.Context) (*common.Bundle, error) {
	bundle, err := m.fetchOptionalBundle(ctx)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return nil, errors.New("trust domain bundle is missing")
	}
	return bundle, nil
}

func (m *Manager) fetchOptionalBundle(ctx context.Context) (*common.Bundle, error) {
	ds := m.c.Catalog.GetDataStore()
	bundle, err := ds.FetchBundle(ctx, m.c.TrustDomain.IDString())
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

func (m *Manager) upstreamSignX509CA(ctx context.Context, signer crypto.Signer) (*ca.X509CA, error) {
	template, err := m.c.CredBuilder.BuildUpstreamSignedX509CACSR(ctx, credtemplate.UpstreamSignedX509CAParams{
		PublicKey: signer.Public(),
	})
	if err != nil {
		return nil, err
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return nil, err
	}

	validator := ca.X509CAValidator{
		TrustDomain:   m.c.TrustDomain,
		CredValidator: m.c.CredValidator,
		Signer:        signer,
		Clock:         m.c.Clock,
	}

	caChain, err := m.upstreamClient.MintX509CA(ctx, csr, m.caTTL, validator.ValidateUpstreamX509CA)
	if err != nil {
		return nil, err
	}

	return &ca.X509CA{
		Signer:        signer,
		Certificate:   caChain[0],
		UpstreamChain: caChain,
	}, nil
}

func (m *Manager) selfSignX509CA(ctx context.Context, signer crypto.Signer) (*ca.X509CA, error) {
	template, err := m.c.CredBuilder.BuildSelfSignedX509CATemplate(ctx, credtemplate.SelfSignedX509CAParams{
		PublicKey: signer.Public(),
	})
	if err != nil {
		return nil, err
	}

	cert, err := x509util.CreateCertificate(template, template, signer.Public(), signer)
	if err != nil {
		return nil, err
	}

	if err := m.c.CredValidator.ValidateX509CA(cert); err != nil {
		return nil, fmt.Errorf("invalid downstream X509 CA: %w", err)
	}

	if _, err := m.appendBundle(ctx, []*x509.Certificate{cert}, nil); err != nil {
		return nil, err
	}

	return &ca.X509CA{
		Signer:      signer,
		Certificate: cert,
	}, nil
}

func (m *Manager) appendBundle(ctx context.Context, caChain []*x509.Certificate, jwtSigningKeys []*common.PublicKey) (*common.Bundle, error) {
	var rootCAs []*common.Certificate
	for _, caCert := range caChain {
		rootCAs = append(rootCAs, &common.Certificate{
			DerBytes: caCert.Raw,
		})
	}

	ds := m.c.Catalog.GetDataStore()
	res, err := ds.AppendBundle(ctx, &common.Bundle{
		TrustDomainId:  m.c.TrustDomain.IDString(),
		RootCas:        rootCAs,
		JwtSigningKeys: jwtSigningKeys,
	})
	if err != nil {
		return nil, err
	}

	m.bundleUpdated()
	return res, nil
}

func (m *Manager) shouldPrepareX509CA(taintedAuthorities []*x509.Certificate) bool {
	slot := m.nextX509CA
	switch {
	case slot.IsEmpty():
		return true
	case slot.Status() == journal.Status_PREPARED:
		isTainted := isX509AuthorityTainted(slot.x509CA, taintedAuthorities)
		m.c.Log.Info("Next authority is tainted, prepare new X.509 authority")
		return isTainted
	default:
		return false
	}
}

// MaxSVIDTTL returns the maximum SVID lifetime that can be guaranteed to not
// be cut artificially short by a scheduled rotation.
func MaxSVIDTTL() time.Duration {
	return activationThresholdCap
}

// MaxSVIDTTLForCATTL returns the maximum SVID TTL that can be guaranteed given
// a specific CA TTL. In other words, given a CA TTL, what is the largest SVID
// TTL that is guaranteed to not be cut artificially short by a scheduled
// rotation?
func MaxSVIDTTLForCATTL(caTTL time.Duration) time.Duration {
	return min(caTTL/activationThresholdDivisor, activationThresholdCap)
}

// MinCATTLForSVIDTTL returns the minimum CA TTL necessary to guarantee an SVID
// TTL of the provided value. In other words, given an SVID TTL, what is the
// minimum CA TTL that will guarantee that the SVIDs lifetime won't be cut
// artificially short by a scheduled rotation?
func MinCATTLForSVIDTTL(svidTTL time.Duration) time.Duration {
	return svidTTL * activationThresholdDivisor
}

type bundleUpdater struct {
	log                         logrus.FieldLogger
	trustDomainID               string
	ds                          datastore.DataStore
	updated                     func()
	upstreamAuthoritiesTainted  func([]*x509.Certificate)
	processedTaintedAuthorities map[string]struct{}
}

func (u *bundleUpdater) SyncX509Roots(ctx context.Context, roots []*x509certificate.X509Authority) error {
	bundle := &common.Bundle{
		TrustDomainId: u.trustDomainID,
		RootCas:       make([]*common.Certificate, 0, len(roots)),
	}

	x509Authorities, err := u.fetchX509Authorities(ctx)
	if err != nil {
		return err
	}

	newAuthorities := make(map[string]struct{}, len(roots))
	var taintedAuthorities []*x509.Certificate
	for _, root := range roots {
		skID := x509util.SubjectKeyIDToString(root.Certificate.SubjectKeyId)
		// Collect all skIDs
		newAuthorities[skID] = struct{}{}

		// Verify if new root ca is tainted
		if root.Tainted {
			// Taint x.509 authority, if required
			if found, ok := x509Authorities[skID]; ok && !found.Tainted {
				_, alreadyProcessed := u.processedTaintedAuthorities[skID]
				if !alreadyProcessed {
					u.processedTaintedAuthorities[skID] = struct{}{}
					// Add to the list of new tainted authorities
					taintedAuthorities = append(taintedAuthorities, found.Certificate)
					u.log.WithField(telemetry.SubjectKeyID, skID).Info("X.509 authority tainted")
				}
				// Prevent to add tainted keys, since status is updated before
				continue
			}
		}

		bundle.RootCas = append(bundle.RootCas, &common.Certificate{
			DerBytes:   root.Certificate.Raw,
			TaintedKey: root.Tainted,
		})
	}

	// Notify about tainted authorities to force the rotation of
	// intermediates and update the database. This is done in a separate thread
	// to prevent agents and downstream servers to start the rotation before the
	// current server starts the rotation of the intermediate.
	if len(taintedAuthorities) > 0 {
		u.upstreamAuthoritiesTainted(taintedAuthorities)
	}

	for skID, authority := range x509Authorities {
		// Only tainted keys can ke revoked
		if authority.Tainted {
			// In case a stored tainted authority is not found,
			// from latest bundle update, then revoke it
			if _, found := newAuthorities[skID]; !found {
				if err := u.ds.RevokeX509CA(ctx, u.trustDomainID, skID); err != nil {
					return fmt.Errorf("failed to revoke a tainted key %q: %w", skID, err)
				}
				u.log.WithField(telemetry.SubjectKeyID, skID).Info("X.509 authority revoked")
			}
		}
	}

	if _, err := u.appendBundle(ctx, bundle); err != nil {
		return err
	}
	return nil
}

func (u *bundleUpdater) AppendJWTKeys(ctx context.Context, keys []*common.PublicKey) ([]*common.PublicKey, error) {
	bundle, err := u.appendBundle(ctx, &common.Bundle{
		TrustDomainId:  u.trustDomainID,
		JwtSigningKeys: keys,
	})
	if err != nil {
		return nil, err
	}
	return bundle.JwtSigningKeys, nil
}

func (u *bundleUpdater) LogError(err error, msg string) {
	u.log.WithError(err).Error(msg)
}

func (u *bundleUpdater) fetchX509Authorities(ctx context.Context) (map[string]*x509certificate.X509Authority, error) {
	bundle, err := u.ds.FetchBundle(ctx, u.trustDomainID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bundle: %w", err)
	}
	// Bundle not found
	if bundle == nil {
		return nil, nil
	}

	authorities := map[string]*x509certificate.X509Authority{}
	for _, eachRoot := range bundle.RootCas {
		cert, err := x509.ParseCertificate(eachRoot.DerBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse root certificate: %w", err)
		}

		authorities[x509util.SubjectKeyIDToString(cert.SubjectKeyId)] = &x509certificate.X509Authority{
			Certificate: cert,
			Tainted:     eachRoot.TaintedKey,
		}
	}

	return authorities, nil
}

func (u *bundleUpdater) appendBundle(ctx context.Context, bundle *common.Bundle) (*common.Bundle, error) {
	dsBundle, err := u.ds.AppendBundle(ctx, bundle)
	if err != nil {
		return nil, err
	}
	u.updated()
	return dsBundle, nil
}

func newJWTKey(signer crypto.Signer, expiresAt time.Time) (*ca.JWTKey, error) {
	kid, err := newKeyID()
	if err != nil {
		return nil, err
	}

	return &ca.JWTKey{
		Signer:   signer,
		Kid:      kid,
		NotAfter: expiresAt,
	}, nil
}

func newKeyID() (string, error) {
	choices := make([]byte, 32)
	_, err := rand.Read(choices)
	if err != nil {
		return "", err
	}
	return keyIDFromBytes(choices), nil
}

func keyIDFromBytes(choices []byte) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf := new(bytes.Buffer)
	for _, choice := range choices {
		buf.WriteByte(alphabet[int(choice)%len(alphabet)])
	}
	return buf.String()
}

func publicKeyFromJWTKey(jwtKey *ca.JWTKey) (*common.PublicKey, error) {
	pkixBytes, err := x509.MarshalPKIXPublicKey(jwtKey.Signer.Public())
	if err != nil {
		return nil, err
	}

	return &common.PublicKey{
		PkixBytes: pkixBytes,
		Kid:       jwtKey.Kid,
		NotAfter:  jwtKey.NotAfter.Unix(),
	}, nil
}

// isX509AuthorityTainted verifies if the provided X.509 authority is tainted
func isX509AuthorityTainted(x509CA *ca.X509CA, taintedAuthorities []*x509.Certificate) bool {
	rootPool := x509.NewCertPool()
	for _, taintedKey := range taintedAuthorities {
		rootPool.AddCert(taintedKey)
	}

	intermediatePool := x509.NewCertPool()
	for _, intermediateCA := range x509CA.UpstreamChain {
		intermediatePool.AddCert(intermediateCA)
	}

	// Verify certificate chain, using tainted authority as root
	_, err := x509CA.Certificate.Verify(x509.VerifyOptions{
		Intermediates: intermediatePool,
		Roots:         rootPool,
	})

	return err == nil
}
