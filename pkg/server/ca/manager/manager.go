package manager

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
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
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	publishJWKTimeout = 5 * time.Second
	safetyThreshold   = 24 * time.Hour

	thirtyDays                  = 30 * 24 * time.Hour
	preparationThresholdCap     = thirtyDays
	preparationThresholdDivisor = 2

	sevenDays                  = 7 * 24 * time.Hour
	activationThresholdCap     = sevenDays
	activationThresholdDivisor = 6
)

type ManagedCA interface {
	SetX509CA(*ca.X509CA)
	SetJWTKey(*ca.JWTKey)
}

type JwtKeyPublisher interface {
	PublishJWTKey(ctx context.Context, jwtKey *common.PublicKey) ([]*common.PublicKey, error)
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
	c                  Config
	caTTL              time.Duration
	bundleUpdatedCh    chan struct{}
	upstreamClient     *ca.UpstreamClient
	upstreamPluginName string

	currentX509CA *X509CASlot
	nextX509CA    *X509CASlot
	x509CAMutex   sync.RWMutex

	currentJWTKey *JwtKeySlot
	nextJWTKey    *JwtKeySlot
	jwtKeyMutex   sync.RWMutex

	journal *Journal

	// Used to log a warning only once when the UpstreamAuthority does not support JWT-SVIDs.
	jwtUnimplementedWarnOnce sync.Once
}

func NewManager(ctx context.Context, c Config) (*Manager, error) {
	if c.Clock == nil {
		c.Clock = clock.New()
	}

	m := &Manager{
		c:               c,
		caTTL:           c.CredBuilder.Config().X509CATTL,
		bundleUpdatedCh: make(chan struct{}, 1),
	}

	if upstreamAuthority, ok := c.Catalog.GetUpstreamAuthority(); ok {
		m.upstreamClient = ca.NewUpstreamClient(ca.UpstreamClientConfig{
			UpstreamAuthority: upstreamAuthority,
			BundleUpdater: &bundleUpdater{
				log:           c.Log,
				trustDomainID: c.TrustDomain.IDString(),
				ds:            c.Catalog.GetDataStore(),
				updated:       m.bundleUpdated,
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

	journal, slots, err := loader.Load(ctx)
	if err != nil {
		return nil, err
	}

	now := m.c.Clock.Now()
	m.journal = journal
	if currentX509CA, ok := slots[CurrentX509CASlot]; ok {
		m.currentX509CA = currentX509CA.(*X509CASlot)

		if !currentX509CA.IsEmpty() && !currentX509CA.ShouldActivateNext(now) {
			// activate the X509CA immediately if it is set and not within
			// activation time of the next X509CA.
			m.activateX509CA()
		}
	}

	if nextX509CA, ok := slots[NextX509CASlot]; ok {
		m.nextX509CA = nextX509CA.(*X509CASlot)
	}

	if currentJWTKey, ok := slots[CurrentJWTKeySlot]; ok {
		m.currentJWTKey = currentJWTKey.(*JwtKeySlot)

		// TODO: Activation on journal depends on dates, it will need to be
		// refactored to allow to set a status, because when forcing a rotation,
		// we are no longer able to depend on a date.
		if !currentJWTKey.IsEmpty() && !currentJWTKey.ShouldActivateNext(now) {
			// activate the JWT key immediately if it is set and not within
			// activation time of the next JWT key.
			m.activateJWTKey()
		}
	}

	if nextJWTKey, ok := slots[NextJWTKeySlot]; ok {
		m.nextJWTKey = nextJWTKey.(*JwtKeySlot)
	}

	return m, nil
}

func (m *Manager) Close() {
	if m.upstreamClient != nil {
		_ = m.upstreamClient.Close()
	}
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
	slot.publicKey = slot.x509CA.Certificate.PublicKey
	slot.notAfter = slot.x509CA.Certificate.NotAfter

	if err := m.journal.AppendX509CA(slot.id, slot.issuedAt, slot.x509CA); err != nil {
		log.WithError(err).Error("Unable to append X509 CA to journal")
	}

	m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:             slot.id,
		telemetry.IssuedAt:         slot.issuedAt,
		telemetry.Expiration:       slot.x509CA.Certificate.NotAfter,
		telemetry.SelfSigned:       m.upstreamClient == nil,
		telemetry.LocalAuthorityID: slot.authorityID,
	}).Info("X509 CA prepared")
	return nil
}

func (m *Manager) ActivateX509CA() {
	m.x509CAMutex.RLock()
	defer m.x509CAMutex.RUnlock()

	m.activateX509CA()
}

func (m *Manager) RotateX509CA() {
	m.x509CAMutex.Lock()
	defer m.x509CAMutex.Unlock()

	m.currentX509CA, m.nextX509CA = m.nextX509CA, m.currentX509CA
	m.nextX509CA.Reset()
	if err := m.journal.UpdateX509CAStatus(m.nextX509CA.issuedAt, journal.Status_OLD); err != nil {
		m.c.Log.WithError(err).Error("Failed to update status on X509CA journal entry")
	}

	m.activateX509CA()
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

	if err := m.journal.AppendJWTKey(slot.id, slot.issuedAt, slot.jwtKey); err != nil {
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

func (m *Manager) ActivateJWTKey() {
	m.jwtKeyMutex.RLock()
	defer m.jwtKeyMutex.RUnlock()

	m.activateJWTKey()
}

func (m *Manager) RotateJWTKey() {
	m.jwtKeyMutex.Lock()
	defer m.jwtKeyMutex.Unlock()

	m.currentJWTKey, m.nextJWTKey = m.nextJWTKey, m.currentJWTKey
	m.nextJWTKey.Reset()

	if err := m.journal.UpdateJWTKeyStatus(m.nextJWTKey.issuedAt, journal.Status_OLD); err != nil {
		m.c.Log.WithError(err).Error("Failed to update status on JWTKey journal entry")
	}

	m.activateJWTKey()
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

func (m *Manager) PruneBundle(ctx context.Context) (err error) {
	counter := telemetry_server.StartCAManagerPruneBundleCall(m.c.Metrics)
	defer counter.Done(&err)

	ds := m.c.Catalog.GetDataStore()
	expiresBefore := m.c.Clock.Now().Add(-safetyThreshold)

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

func (m *Manager) NotifyOnBundleUpdate(ctx context.Context) {
	for {
		select {
		case <-m.bundleUpdatedCh:
			if err := m.notifyBundleUpdated(ctx); err != nil {
				m.c.Log.WithError(err).Warn("Failed to notify on bundle update")
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

func (m *Manager) activateJWTKey() {
	log := m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:             m.currentJWTKey.id,
		telemetry.IssuedAt:         m.currentJWTKey.issuedAt,
		telemetry.Expiration:       m.currentJWTKey.jwtKey.NotAfter,
		telemetry.LocalAuthorityID: m.currentJWTKey.authorityID,
	})
	log.Info("JWT key activated")
	telemetry_server.IncrActivateJWTKeyManagerCounter(m.c.Metrics)

	m.currentJWTKey.status = journal.Status_ACTIVE
	if err := m.journal.UpdateJWTKeyStatus(m.currentJWTKey.issuedAt, journal.Status_ACTIVE); err != nil {
		log.WithError(err).Error("Failed to update to activated status on JWTKey journal entry")
	}

	m.c.CA.SetJWTKey(m.currentJWTKey.jwtKey)
}

func (m *Manager) activateX509CA() {
	log := m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:             m.currentX509CA.id,
		telemetry.IssuedAt:         m.currentX509CA.issuedAt,
		telemetry.Expiration:       m.currentX509CA.x509CA.Certificate.NotAfter,
		telemetry.LocalAuthorityID: m.currentX509CA.authorityID,
	})
	log.Info("X509 CA activated")
	telemetry_server.IncrActivateX509CAManagerCounter(m.c.Metrics)

	m.currentX509CA.status = journal.Status_ACTIVE
	if err := m.journal.UpdateX509CAStatus(m.currentX509CA.issuedAt, journal.Status_ACTIVE); err != nil {
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

	var allErrs errs.Group
	for i := 0; i < len(notifiers); i++ {
		// don't select on the ctx here as we can rely on the plugins to
		// respond to context cancelation and return an error.
		if err := <-errsCh; err != nil {
			allErrs.Add(err)
		}
	}
	if err := allErrs.Err(); err != nil {
		return errs.New("one or more notifiers returned an error: %v", err)
	}
	return nil
}

func (m *Manager) fetchRequiredBundle(ctx context.Context) (*common.Bundle, error) {
	bundle, err := m.fetchOptionalBundle(ctx)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return nil, errs.New("trust domain bundle is missing")
	}
	return bundle, nil
}

func (m *Manager) fetchOptionalBundle(ctx context.Context) (*common.Bundle, error) {
	ds := m.c.Catalog.GetDataStore()
	bundle, err := ds.FetchBundle(ctx, m.c.TrustDomain.IDString())
	if err != nil {
		return nil, errs.Wrap(err)
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
	maxTTL := caTTL / activationThresholdDivisor
	if maxTTL > activationThresholdCap {
		maxTTL = activationThresholdCap
	}

	return maxTTL
}

// MinCATTLForSVIDTTL returns the minimum CA TTL necessary to guarantee an SVID
// TTL of the provided value. In other words, given an SVID TTL, what is the
// minimum CA TTL that will guarantee that the SVIDs lifetime won't be cut
// artificially short by a scheduled rotation?
func MinCATTLForSVIDTTL(svidTTL time.Duration) time.Duration {
	return svidTTL * activationThresholdDivisor
}

type bundleUpdater struct {
	log           logrus.FieldLogger
	trustDomainID string
	ds            datastore.DataStore
	updated       func()
}

func (u *bundleUpdater) AppendX509Roots(ctx context.Context, roots []*x509.Certificate) error {
	bundle := &common.Bundle{
		TrustDomainId: u.trustDomainID,
		RootCas:       make([]*common.Certificate, 0, len(roots)),
	}

	for _, root := range roots {
		bundle.RootCas = append(bundle.RootCas, &common.Certificate{
			DerBytes: root.Raw,
		})
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
		return nil, errs.Wrap(err)
	}

	return &common.PublicKey{
		PkixBytes: pkixBytes,
		Kid:       jwtKey.Kid,
		NotAfter:  jwtKey.NotAfter.Unix(),
	}, nil
}
