package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"path/filepath"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamca"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
)

const (
	DefaultCATTL    = 24 * time.Hour
	backdate        = 10 * time.Second
	rotateInterval  = 10 * time.Second
	pruneInterval   = 6 * time.Hour
	safetyThreshold = 24 * time.Hour

	thirtyDays              = 30 * 24 * time.Hour
	preparationThresholdCap = thirtyDays

	sevenDays              = 7 * 24 * time.Hour
	activationThresholdCap = sevenDays
)

type ManagedCA interface {
	SetX509CA(*X509CA)
	SetJWTKey(*JWTKey)
}

type ManagerConfig struct {
	CA             ManagedCA
	Catalog        catalog.Catalog
	TrustDomain    url.URL
	UpstreamBundle bool
	CATTL          time.Duration
	X509CAKeyType  keymanager.KeyType
	JWTKeyType     keymanager.KeyType
	CASubject      pkix.Name
	Dir            string
	Log            logrus.FieldLogger
	Metrics        telemetry.Metrics
	Clock          clock.Clock
}

type Manager struct {
	c               ManagerConfig
	bundleUpdatedCh chan struct{}

	currentX509CA *x509CASlot
	nextX509CA    *x509CASlot
	currentJWTKey *jwtKeySlot
	nextJWTKey    *jwtKeySlot

	journal *Journal
}

func NewManager(c ManagerConfig) *Manager {
	if c.CATTL <= 0 {
		c.CATTL = DefaultCATTL
	}
	if c.Clock == nil {
		c.Clock = clock.New()
	}
	if c.X509CAKeyType == 0 {
		c.X509CAKeyType = keymanager.KeyType_EC_P384
	}
	if c.JWTKeyType == 0 {
		c.JWTKeyType = keymanager.KeyType_EC_P256
	}

	return &Manager{
		c:               c,
		bundleUpdatedCh: make(chan struct{}, 1),
	}
}

func (m *Manager) Initialize(ctx context.Context) error {
	if err := m.loadJournal(ctx); err != nil {
		return err
	}
	if err := m.rotate(ctx); err != nil {
		return err
	}
	return nil
}

func (m *Manager) Run(ctx context.Context) error {
	if err := m.notifyBundleLoaded(ctx); err != nil {
		return err
	}
	err := util.RunTasks(ctx,
		func(ctx context.Context) error {
			return m.rotateEvery(ctx, rotateInterval)
		},
		func(ctx context.Context) error {
			return m.pruneBundleEvery(ctx, pruneInterval)
		},
		func(ctx context.Context) error {
			// notifyOnBundleUpdate does not fail but rather logs any errors
			// encountered while notifying
			m.notifyOnBundleUpdate(ctx)
			return nil
		},
	)
	if err == context.Canceled {
		err = nil
	}
	return err
}

func (m *Manager) rotateEvery(ctx context.Context, interval time.Duration) error {
	ticker := m.c.Clock.Ticker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// rotate() errors are logged by rotate() and shouldn't cause the
			// manager run task to bail so ignore them here. The error returned
			// by rotate is used by the unit tests, so we need to keep it for
			// now.
			_ = m.rotate(ctx)
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *Manager) rotate(ctx context.Context) error {
	x509CAErr := m.rotateX509CA(ctx)
	if x509CAErr != nil {
		m.c.Log.WithError(x509CAErr).Error("Unable to rotate X509 CA")
	}

	jwtKeyErr := m.rotateJWTKey(ctx)
	if jwtKeyErr != nil {
		m.c.Log.WithError(jwtKeyErr).Error("Unable to rotate JWT key")
	}

	return errs.Combine(x509CAErr, jwtKeyErr)
}

func (m *Manager) rotateX509CA(ctx context.Context) error {
	now := m.c.Clock.Now()

	// if there is no current keypair set, generate one
	if m.currentX509CA.IsEmpty() {
		if err := m.prepareX509CA(ctx, m.currentX509CA); err != nil {
			return err
		}
		m.activateX509CA()
	}

	// if there is no next keypair set and the current is within the
	// preparation threshold, generate one.
	if m.nextX509CA.IsEmpty() && m.currentX509CA.ShouldPrepareNext(now) {
		if err := m.prepareX509CA(ctx, m.nextX509CA); err != nil {
			return err
		}
	}

	if m.currentX509CA.ShouldActivateNext(now) {
		m.currentX509CA, m.nextX509CA = m.nextX509CA, m.currentX509CA
		m.nextX509CA.Reset()
		m.activateX509CA()
	}

	return nil
}

func (m *Manager) prepareX509CA(ctx context.Context, slot *x509CASlot) (err error) {
	counter := telemetry_server.StartServerCAManagerPrepareX509CACall(m.c.Metrics)
	defer counter.Done(&err)

	log := m.c.Log.WithField(telemetry.Slot, slot.id)
	log.Debug("Preparing X509 CA")

	slot.Reset()

	now := m.c.Clock.Now()
	km := m.c.Catalog.GetKeyManager()
	signer, err := cryptoutil.GenerateKeyAndSigner(ctx, km, slot.KmKeyID(), m.c.X509CAKeyType)
	if err != nil {
		return err
	}

	var x509CA *X509CA
	var trustBundle []*x509.Certificate
	upstreamCA, useUpstream := m.c.Catalog.GetUpstreamCA()
	if useUpstream {
		x509CA, trustBundle, err = UpstreamSignX509CA(ctx, signer, m.c.TrustDomain.Host, m.c.CASubject, upstreamCA, m.c.UpstreamBundle, m.c.CATTL)
	} else {
		notBefore := now.Add(-backdate)
		notAfter := now.Add(m.c.CATTL)
		x509CA, trustBundle, err = SelfSignX509CA(ctx, signer, m.c.TrustDomain.Host, m.c.CASubject, notBefore, notAfter)
	}
	if err != nil {
		return err
	}

	if err := m.appendBundle(ctx, trustBundle, nil); err != nil {
		return err
	}

	slot.issuedAt = now
	slot.x509CA = x509CA

	if err := m.journal.AppendX509CA(slot.id, slot.issuedAt, slot.x509CA); err != nil {
		log.WithError(err).Error("Unable to append X509 CA to journal")
	}

	m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:           slot.id,
		telemetry.IssuedAt:       timeField(slot.issuedAt),
		telemetry.Expiration:     timeField(slot.x509CA.Certificate.NotAfter),
		telemetry.SelfSigned:     !useUpstream,
		telemetry.UpstreamBundle: m.c.UpstreamBundle,
	}).Info("X509 CA prepared")
	return nil
}

func (m *Manager) activateX509CA() {
	m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:       m.currentX509CA.id,
		telemetry.IssuedAt:   timeField(m.currentX509CA.issuedAt),
		telemetry.Expiration: timeField(m.currentX509CA.x509CA.Certificate.NotAfter),
	}).Info("X509 CA activated")
	telemetry_server.IncrActivateX509CAManagerCounter(m.c.Metrics)

	ttl := m.currentX509CA.x509CA.Certificate.NotAfter.Sub(m.c.Clock.Now())
	telemetry_server.SetX509CARotateGauge(m.c.Metrics, m.c.TrustDomain.String(), float32(ttl.Seconds()))
	m.c.Log.WithFields(logrus.Fields{
		telemetry.TrustDomainID: m.c.TrustDomain.String(),
		telemetry.TTL:           ttl.Seconds(),
	}).Debug("Successfully rotated X.509 CA")

	m.c.CA.SetX509CA(m.currentX509CA.x509CA)
}

func (m *Manager) rotateJWTKey(ctx context.Context) error {
	now := m.c.Clock.Now()

	// if there is no current keypair set, generate one
	if m.currentJWTKey.IsEmpty() {
		if err := m.prepareJWTKey(ctx, m.currentJWTKey); err != nil {
			return err
		}
		m.activateJWTKey()
	}

	// if there is no next keypair set and the current is within the
	// preparation threshold, generate one.
	if m.nextJWTKey.IsEmpty() && m.currentJWTKey.ShouldPrepareNext(now) {
		if err := m.prepareJWTKey(ctx, m.nextJWTKey); err != nil {
			return err
		}
	}

	if m.currentJWTKey.ShouldActivateNext(now) {
		m.currentJWTKey, m.nextJWTKey = m.nextJWTKey, m.currentJWTKey
		m.nextJWTKey.Reset()
		m.activateJWTKey()
	}

	return nil
}

func (m *Manager) prepareJWTKey(ctx context.Context, slot *jwtKeySlot) (err error) {
	counter := telemetry_server.StartServerCAManagerPrepareJWTKeyCall(m.c.Metrics)
	defer counter.Done(&err)

	log := m.c.Log.WithField(telemetry.Slot, slot.id)
	log.Debug("Preparing JWT key")

	slot.Reset()

	now := m.c.Clock.Now()
	notAfter := now.Add(m.c.CATTL)

	km := m.c.Catalog.GetKeyManager()
	signer, err := cryptoutil.GenerateKeyAndSigner(ctx, km, slot.KmKeyID(), m.c.JWTKeyType)
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

	if err := m.appendBundle(ctx, nil, publicKey); err != nil {
		return err
	}

	slot.issuedAt = now
	slot.jwtKey = jwtKey

	if err := m.journal.AppendJWTKey(slot.id, slot.issuedAt, slot.jwtKey); err != nil {
		log.WithError(err).Error("Unable to append JWT key to journal")
	}

	m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:       slot.id,
		telemetry.IssuedAt:   timeField(slot.issuedAt),
		telemetry.Expiration: timeField(slot.jwtKey.NotAfter),
	}).Info("JWT key prepared")
	return nil
}

func (m *Manager) activateJWTKey() {
	m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:       m.currentJWTKey.id,
		telemetry.IssuedAt:   timeField(m.currentJWTKey.issuedAt),
		telemetry.Expiration: timeField(m.currentJWTKey.jwtKey.NotAfter),
	}).Info("JWT key activated")
	telemetry_server.IncrActivateJWTKeyManagerCounter(m.c.Metrics)
	m.c.CA.SetJWTKey(m.currentJWTKey.jwtKey)
}

func (m *Manager) pruneBundleEvery(ctx context.Context, interval time.Duration) error {
	ticker := m.c.Clock.Ticker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.pruneBundle(ctx); err != nil {
				m.c.Log.WithError(err).Error("Could not prune CA certificates")
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *Manager) pruneBundle(ctx context.Context) (err error) {
	counter := telemetry_server.StartCAManagerPruneBundleCall(m.c.Metrics)
	defer counter.Done(&err)

	ds := m.c.Catalog.GetDataStore()
	expiresBefore := m.c.Clock.Now().Add(-safetyThreshold)

	resp, err := ds.PruneBundle(ctx, &datastore.PruneBundleRequest{
		TrustDomainId: m.c.TrustDomain.String(),
		ExpiresBefore: expiresBefore.Unix(),
	})

	if err != nil {
		return fmt.Errorf("unable to prune bundle: %v", err)
	}

	if resp.BundleChanged {
		telemetry_server.IncrManagerPrunedBundleCounter(m.c.Metrics)
		m.c.Log.Debug("Expired certificates were successfully pruned from bundle")
		m.bundleUpdated()
	}

	return nil
}

func (m *Manager) appendBundle(ctx context.Context, caChain []*x509.Certificate, jwtSigningKey *common.PublicKey) error {
	var rootCAs []*common.Certificate
	for _, caCert := range caChain {
		rootCAs = append(rootCAs, &common.Certificate{
			DerBytes: caCert.Raw,
		})
	}

	var jwtSigningKeys []*common.PublicKey
	if jwtSigningKey != nil {
		jwtSigningKeys = append(jwtSigningKeys, jwtSigningKey)
	}

	ds := m.c.Catalog.GetDataStore()
	if _, err := ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
		Bundle: &common.Bundle{
			TrustDomainId:  m.c.TrustDomain.String(),
			RootCas:        rootCAs,
			JwtSigningKeys: jwtSigningKeys,
		},
	}); err != nil {
		return err
	}

	m.bundleUpdated()
	return nil
}

func (m *Manager) loadJournal(ctx context.Context) error {
	jsonPath := filepath.Join(m.c.Dir, "certs.json")
	if ok, err := migrateJSONFile(jsonPath, m.journalPath()); err != nil {
		return errs.New("failed to migrate old JSON data: %v", err)
	} else if ok {
		m.c.Log.Info("Migrated data to journal")
	}

	// Load the journal and see if we can figure out the next and current
	// X509CA and JWTKey entries, if any.
	m.c.Log.WithField(telemetry.Path, m.journalPath()).Debug("Loading journal")
	journal, err := LoadJournal(m.journalPath())
	if err != nil {
		return err
	}

	m.journal = journal

	entries := journal.Entries()

	now := m.c.Clock.Now()

	m.c.Log.WithFields(logrus.Fields{
		telemetry.X509CAs: len(entries.X509CAs),
		telemetry.JWTKeys: len(entries.JwtKeys),
	}).Info("Journal loaded")

	if len(entries.X509CAs) > 0 {
		m.nextX509CA, err = m.tryLoadX509CASlotFromEntry(ctx, entries.X509CAs[len(entries.X509CAs)-1])
		if err != nil {
			return err
		}
		// if the last entry is ok, then consider the next entry
		if m.nextX509CA != nil && len(entries.X509CAs) > 1 {
			m.currentX509CA, err = m.tryLoadX509CASlotFromEntry(ctx, entries.X509CAs[len(entries.X509CAs)-2])
			if err != nil {
				return err
			}
		}
	}
	switch {
	case m.currentX509CA != nil:
		// both current and next are set
	case m.nextX509CA != nil:
		// next is set but not current. swap them and initialize next with an empty slot.
		m.currentX509CA, m.nextX509CA = m.nextX509CA, newX509CASlot(otherSlotID(m.nextX509CA.id))
	default:
		// neither are set. initialize them with empty slots.
		m.currentX509CA = newX509CASlot("A")
		m.nextX509CA = newX509CASlot("B")
	}

	if !m.currentX509CA.IsEmpty() && !m.currentX509CA.ShouldActivateNext(now) {
		// activate the X509CA immediately if it is set and not within
		// activation time of the next X509CA.
		m.activateX509CA()
	}

	if len(entries.JwtKeys) > 0 {
		m.nextJWTKey, err = m.tryLoadJWTKeySlotFromEntry(ctx, entries.JwtKeys[len(entries.JwtKeys)-1])
		if err != nil {
			return err
		}
		// if the last entry is ok, then consider the next entry
		if m.nextJWTKey != nil && len(entries.JwtKeys) > 1 {
			m.currentJWTKey, err = m.tryLoadJWTKeySlotFromEntry(ctx, entries.JwtKeys[len(entries.JwtKeys)-2])
			if err != nil {
				return err
			}
		}
	}
	switch {
	case m.currentJWTKey != nil:
		// both current and next are set
	case m.nextJWTKey != nil:
		// next is set but not current. swap them and initialize next with an empty slot.
		m.currentJWTKey, m.nextJWTKey = m.nextJWTKey, newJWTKeySlot(otherSlotID(m.nextJWTKey.id))
	default:
		// neither are set. initialize them with empty slots.
		m.currentJWTKey = newJWTKeySlot("A")
		m.nextJWTKey = newJWTKeySlot("B")
	}

	if !m.currentJWTKey.IsEmpty() && !m.currentJWTKey.ShouldActivateNext(now) {
		// activate the JWT key immediately if it is set and not within
		// activation time of the next JWT key.
		m.activateJWTKey()
	}

	return nil
}

func (m *Manager) journalPath() string {
	return filepath.Join(m.c.Dir, "journal.pem")
}

func (m *Manager) tryLoadX509CASlotFromEntry(ctx context.Context, entry *X509CAEntry) (*x509CASlot, error) {
	slot, badReason, err := m.loadX509CASlotFromEntry(ctx, entry)
	if err != nil {
		m.c.Log.WithError(err).WithFields(logrus.Fields{
			telemetry.Slot: entry.SlotId,
		}).Error("X509CA slot failed to load")
		return nil, err
	}
	if badReason != "" {
		m.c.Log.WithError(errors.New(badReason)).WithFields(logrus.Fields{
			telemetry.Slot: entry.SlotId,
		}).Warn("X509CA slot unusable")
		return nil, nil
	}
	return slot, nil
}

func (m *Manager) loadX509CASlotFromEntry(ctx context.Context, entry *X509CAEntry) (*x509CASlot, string, error) {
	if entry.SlotId == "" {
		return nil, "no slot id", nil
	}

	cert, err := x509.ParseCertificate(entry.Certificate)
	if err != nil {
		return nil, "", errs.New("unable to parse CA certificate: %v", err)
	}

	var upstreamChain []*x509.Certificate
	for _, certDER := range entry.UpstreamChain {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, "", errs.New("unable to parse upstream chain certificate: %v", err)
		}
		upstreamChain = append(upstreamChain, cert)
	}

	signer, err := m.makeSigner(ctx, x509CAKmKeyID(entry.SlotId))
	if err != nil {
		return nil, "", err
	}

	switch {
	case signer == nil:
		return nil, "no key manager key", nil
	case !publicKeyEqual(cert.PublicKey, signer.Public()):
		return nil, "public key does not match key manager key", nil
	}

	return &x509CASlot{
		id:       entry.SlotId,
		issuedAt: time.Unix(entry.IssuedAt, 0),
		x509CA: &X509CA{
			Signer:        signer,
			Certificate:   cert,
			UpstreamChain: upstreamChain,
		},
	}, "", nil
}

func (m *Manager) tryLoadJWTKeySlotFromEntry(ctx context.Context, entry *JWTKeyEntry) (*jwtKeySlot, error) {
	slot, badReason, err := m.loadJWTKeySlotFromEntry(ctx, entry)
	if err != nil {
		m.c.Log.WithError(err).WithFields(logrus.Fields{
			telemetry.Slot: entry.SlotId,
		}).Error("JWT key slot failed to load")
		return nil, err
	}
	if badReason != "" {
		m.c.Log.WithError(errors.New(badReason)).WithFields(logrus.Fields{
			telemetry.Slot: entry.SlotId,
		}).Warn("JWT key slot unusable")
		return nil, nil
	}
	return slot, nil
}

func (m *Manager) loadJWTKeySlotFromEntry(ctx context.Context, entry *JWTKeyEntry) (*jwtKeySlot, string, error) {
	if entry.SlotId == "" {
		return nil, "no slot id", nil
	}

	publicKey, err := x509.ParsePKIXPublicKey(entry.PublicKey)
	if err != nil {
		return nil, "", errs.Wrap(err)
	}

	signer, err := m.makeSigner(ctx, jwtKeyKmKeyID(entry.SlotId))
	if err != nil {
		return nil, "", err
	}

	switch {
	case signer == nil:
		return nil, "no key manager key", nil
	case !publicKeyEqual(publicKey, signer.Public()):
		return nil, "public key does not match key manager key", nil
	}

	return &jwtKeySlot{
		id:       entry.SlotId,
		issuedAt: time.Unix(entry.IssuedAt, 0),
		jwtKey: &JWTKey{
			Signer:   signer,
			NotAfter: time.Unix(entry.NotAfter, 0),
			Kid:      entry.Kid,
		},
	}, "", nil
}

func (m *Manager) makeSigner(ctx context.Context, keyID string) (crypto.Signer, error) {
	km := m.c.Catalog.GetKeyManager()
	resp, err := km.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: keyID,
	})
	if err != nil {
		return nil, errs.Wrap(err)
	}

	if resp.PublicKey == nil {
		return nil, nil
	}

	publicKey, err := x509.ParsePKIXPublicKey(resp.PublicKey.PkixData)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	return cryptoutil.NewKeyManagerSigner(km, keyID, publicKey), nil
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

func (m *Manager) notifyOnBundleUpdate(ctx context.Context) {
	for {
		select {
		case <-m.bundleUpdatedCh:
			if err := m.notifyBundleUpdated(ctx); err != nil {
				m.c.Log.WithError(err).Warn("failed to notify on bundle update")
			}
		case <-ctx.Done():
			return
		}
	}
}

func (m *Manager) notifyBundleLoaded(ctx context.Context) error {
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
			_, err := n.NotifyAndAdvise(ctx, &notifier.NotifyAndAdviseRequest{
				Event: &notifier.NotifyAndAdviseRequest_BundleLoaded{
					BundleLoaded: &notifier.BundleLoaded{
						Bundle: bundle,
					},
				},
			})
			return err
		},
	)
}

func (m *Manager) notifyBundleUpdated(ctx context.Context) error {
	var bundle *common.Bundle
	return m.notify(ctx, "bundle updated", false,
		func(ctx context.Context) (err error) {
			bundle, err = m.fetchRequiredBundle(ctx)
			return err
		},
		func(ctx context.Context, n notifier.Notifier) error {
			_, err := n.Notify(ctx, &notifier.NotifyRequest{
				Event: &notifier.NotifyRequest_BundleUpdated{
					BundleUpdated: &notifier.BundleUpdated{
						Bundle: bundle,
					},
				},
			})
			return err
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
		go func(n catalog.Notifier) {
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
	resp, err := ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: m.c.TrustDomain.String(),
	})
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return resp.Bundle, nil
}

func x509CAKmKeyID(id string) string {
	return fmt.Sprintf("x509-CA-%s", id)
}

func jwtKeyKmKeyID(id string) string {
	return fmt.Sprintf("JWT-Signer-%s", id)
}

type x509CASlot struct {
	id       string
	issuedAt time.Time
	x509CA   *X509CA
}

func newX509CASlot(id string) *x509CASlot {
	return &x509CASlot{
		id: id,
	}
}

func (s *x509CASlot) KmKeyID() string {
	return x509CAKmKeyID(s.id)
}

func (s *x509CASlot) IsEmpty() bool {
	return s.x509CA == nil
}

func (s *x509CASlot) Reset() {
	s.x509CA = nil
}

func (s *x509CASlot) ShouldPrepareNext(now time.Time) bool {
	return s.x509CA != nil && now.After(preparationThreshold(s.issuedAt, s.x509CA.Certificate.NotAfter))
}

func (s *x509CASlot) ShouldActivateNext(now time.Time) bool {
	return s.x509CA != nil && now.After(KeyActivationThreshold(s.issuedAt, s.x509CA.Certificate.NotAfter))
}

type jwtKeySlot struct {
	id       string
	issuedAt time.Time
	jwtKey   *JWTKey
}

func newJWTKeySlot(id string) *jwtKeySlot {
	return &jwtKeySlot{
		id: id,
	}
}

func (s *jwtKeySlot) KmKeyID() string {
	return jwtKeyKmKeyID(s.id)
}

func (s *jwtKeySlot) IsEmpty() bool {
	return s.jwtKey == nil
}

func (s *jwtKeySlot) Reset() {
	s.jwtKey = nil
}

func (s *jwtKeySlot) ShouldPrepareNext(now time.Time) bool {
	return s.jwtKey == nil || now.After(preparationThreshold(s.issuedAt, s.jwtKey.NotAfter))
}

func (s *jwtKeySlot) ShouldActivateNext(now time.Time) bool {
	return s.jwtKey == nil || now.After(KeyActivationThreshold(s.issuedAt, s.jwtKey.NotAfter))
}

func otherSlotID(id string) string {
	if id == "A" {
		return "B"
	}
	return "A"
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	matches, err := cryptoutil.PublicKeyEqual(a, b)
	if err != nil {
		return false
	}
	return matches
}

func GenerateServerCACSR(signer crypto.Signer, trustDomain string, subject pkix.Name) ([]byte, error) {
	spiffeID := &url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
	}

	// SignatureAlgorithm is not provided. The crypto/x509 package will
	// select the algorithm appropriately based on the signer key type.
	template := x509.CertificateRequest{
		Subject: subject,
		URIs:    []*url.URL{spiffeID},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, signer)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

func SelfSignX509CA(ctx context.Context, signer crypto.Signer, trustDomain string, subject pkix.Name, notBefore, notAfter time.Time) (*X509CA, []*x509.Certificate, error) {
	spiffeID := &url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
	}

	template, err := CreateServerCATemplate(spiffeID.String(), signer.Public(), trustDomain, notBefore, notAfter, big.NewInt(0), subject)
	if err != nil {
		return nil, nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	trustBundle := []*x509.Certificate{cert}

	return &X509CA{
		Signer:      signer,
		Certificate: cert,
	}, trustBundle, nil
}

func UpstreamSignX509CA(ctx context.Context, signer crypto.Signer, trustDomain string, subject pkix.Name, upstreamCA upstreamca.UpstreamCA, upstreamBundle bool, caTTL time.Duration) (*X509CA, []*x509.Certificate, error) {
	csr, err := GenerateServerCACSR(signer, trustDomain, subject)
	if err != nil {
		return nil, nil, err
	}

	resp, err := upstreamCA.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{
		Csr:          csr,
		PreferredTtl: int32(caTTL / time.Second),
	})
	if err != nil {
		return nil, nil, errs.New("upstream CA failed with %v", err)
	}

	caChain, trustBundle, err := parseUpstreamCACSRResponse(resp)
	if err != nil {
		return nil, nil, err
	}

	var upstreamChain []*x509.Certificate
	if upstreamBundle {
		upstreamChain = caChain
	} else {
		// we don't want to join the upstream PKI. Use the server CA as the
		// root, as if the upstreamCA was never configured.
		trustBundle = caChain[:1]
	}

	return &X509CA{
		Signer:        signer,
		Certificate:   caChain[0],
		UpstreamChain: upstreamChain,
	}, trustBundle, nil
}

func parseUpstreamCACSRResponse(resp *upstreamca.SubmitCSRResponse) ([]*x509.Certificate, []*x509.Certificate, error) {
	if resp.SignedCertificate == nil {
		return nil, nil, errs.New("upstream CA returned a nil signed certificate")
	}
	certChain, err := x509.ParseCertificates(resp.SignedCertificate.CertChain)
	if err != nil {
		return nil, nil, err
	}
	if len(certChain) == 0 {
		return nil, nil, errs.New("upstream CA returned an empty cert chain")
	}
	trustBundle, err := x509.ParseCertificates(resp.SignedCertificate.Bundle)
	if err != nil {
		return nil, nil, err
	}
	if len(trustBundle) == 0 {
		return nil, nil, errs.New("upstream CA returned an empty trust bundle")
	}
	return certChain, trustBundle, nil
}

func preparationThreshold(issuedAt, notAfter time.Time) time.Time {
	lifetime := notAfter.Sub(issuedAt)
	threshold := lifetime / 2
	if threshold > preparationThresholdCap {
		threshold = preparationThresholdCap
	}
	return notAfter.Add(-threshold)
}

func KeyActivationThreshold(issuedAt, notAfter time.Time) time.Time {
	lifetime := notAfter.Sub(issuedAt)
	threshold := lifetime / 6
	if threshold > activationThresholdCap {
		threshold = activationThresholdCap
	}
	return notAfter.Add(-threshold)
}

func newJWTKey(signer crypto.Signer, expiresAt time.Time) (*JWTKey, error) {
	kid, err := newKeyID()
	if err != nil {
		return nil, err
	}

	return &JWTKey{
		Signer:   signer,
		Kid:      kid,
		NotAfter: expiresAt,
	}, nil
}

func publicKeyFromJWTKey(jwtKey *JWTKey) (*common.PublicKey, error) {
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

func timeField(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
