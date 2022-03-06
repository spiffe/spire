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
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/catalog"
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
	DefaultCATTL    = 24 * time.Hour
	backdate        = 10 * time.Second
	rotateInterval  = 10 * time.Second
	pruneInterval   = 6 * time.Hour
	safetyThreshold = 24 * time.Hour

	thirtyDays                  = 30 * 24 * time.Hour
	preparationThresholdCap     = thirtyDays
	preparationThresholdDivisor = 2

	sevenDays                  = 7 * 24 * time.Hour
	activationThresholdCap     = sevenDays
	activationThresholdDivisor = 6

	publishJWKTimeout = 5 * time.Second
)

type ManagedCA interface {
	SetX509CA(*X509CA)
	SetJWTKey(*JWTKey)
}

type ManagerConfig struct {
	CA            ManagedCA
	Catalog       catalog.Catalog
	TrustDomain   spiffeid.TrustDomain
	CATTL         time.Duration
	X509CAKeyType keymanager.KeyType
	JWTKeyType    keymanager.KeyType
	CASubject     pkix.Name
	Dir           string
	Log           logrus.FieldLogger
	Metrics       telemetry.Metrics
	Clock         clock.Clock
	HealthChecker health.Checker
}

type Manager struct {
	c                  ManagerConfig
	bundleUpdatedCh    chan struct{}
	upstreamClient     *UpstreamClient
	upstreamPluginName string

	currentX509CA *x509CASlot
	nextX509CA    *x509CASlot
	currentJWTKey *jwtKeySlot
	nextJWTKey    *jwtKeySlot

	journal *Journal

	// For keeping track of number of failed rotations.
	failedRotationNum uint64

	// Used to log a warning only once when the UpstreamAuthority does not support JWT-SVIDs.
	jwtUnimplementedWarnOnce sync.Once
}

func NewManager(c ManagerConfig) *Manager {
	if c.CATTL <= 0 {
		c.CATTL = DefaultCATTL
	}
	if c.Clock == nil {
		c.Clock = clock.New()
	}

	m := &Manager{
		c:               c,
		bundleUpdatedCh: make(chan struct{}, 1),
	}

	if upstreamAuthority, ok := c.Catalog.GetUpstreamAuthority(); ok {
		m.upstreamClient = NewUpstreamClient(UpstreamClientConfig{
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

	_ = c.HealthChecker.AddCheck("server.ca.manager", &managerHealth{m: m})

	return m
}

func (m *Manager) Initialize(ctx context.Context) error {
	if err := m.loadJournal(ctx); err != nil {
		return err
	}
	return m.rotate(ctx)
}

func (m *Manager) Run(ctx context.Context) error {
	// Shut down any open streams in the upstream client when the manager
	// has finished running.
	if m.upstreamClient != nil {
		defer func() { _ = m.upstreamClient.Close() }()
	}

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
	if errors.Is(err, context.Canceled) {
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
		atomic.AddUint64(&m.failedRotationNum, 1)
		m.c.Log.WithError(x509CAErr).Error("Unable to rotate X509 CA")
	}

	jwtKeyErr := m.rotateJWTKey(ctx)
	if jwtKeyErr != nil {
		atomic.AddUint64(&m.failedRotationNum, 1)
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

func (m *Manager) failedRotationResult() uint64 {
	return atomic.LoadUint64(&m.failedRotationNum)
}

func (m *Manager) prepareX509CA(ctx context.Context, slot *x509CASlot) (err error) {
	counter := telemetry_server.StartServerCAManagerPrepareX509CACall(m.c.Metrics)
	defer counter.Done(&err)

	log := m.c.Log.WithField(telemetry.Slot, slot.id)
	log.Debug("Preparing X509 CA")

	slot.Reset()

	now := m.c.Clock.Now()
	km := m.c.Catalog.GetKeyManager()
	signer, err := km.GenerateKey(ctx, slot.KmKeyID(), m.c.X509CAKeyType)
	if err != nil {
		return err
	}

	var x509CA *X509CA
	if m.upstreamClient != nil {
		x509CA, err = UpstreamSignX509CA(ctx, signer, m.c.TrustDomain, m.c.CASubject, m.upstreamClient, m.c.CATTL)
		if err != nil {
			return err
		}
	} else {
		notBefore := now.Add(-backdate)
		notAfter := now.Add(m.c.CATTL)
		var trustBundle []*x509.Certificate
		x509CA, trustBundle, err = SelfSignX509CA(ctx, signer, m.c.TrustDomain, m.c.CASubject, notBefore, notAfter)
		if err != nil {
			return err
		}
		if _, err := m.appendBundle(ctx, trustBundle, nil); err != nil {
			return err
		}
	}

	slot.issuedAt = now
	slot.x509CA = x509CA

	if err := m.journal.AppendX509CA(slot.id, slot.issuedAt, slot.x509CA); err != nil {
		log.WithError(err).Error("Unable to append X509 CA to journal")
	}

	m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:       slot.id,
		telemetry.IssuedAt:   timeField(slot.issuedAt),
		telemetry.Expiration: timeField(slot.x509CA.Certificate.NotAfter),
		telemetry.SelfSigned: m.upstreamClient == nil,
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
		telemetry.TrustDomainID: m.c.TrustDomain.IDString(),
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

	// filter out local JwtKeys and X509CAs that do not exist in the database bundle
	entries.JwtKeys, entries.X509CAs, err = m.filterInvalidEntries(ctx, entries)
	if err != nil {
		return err
	}

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

	key, err := km.GetKey(ctx, keyID)
	switch status.Code(err) {
	case codes.OK:
		return key, nil
	case codes.NotFound:
		return nil, nil
	default:
		return nil, errs.Wrap(err)
	}
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
				m.c.Log.WithError(err).Warn("Failed to notify on bundle update")
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
			return n.NotifyAndAdviseBundleLoaded(ctx, bundle)
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

// filterInvalidEntries takes in a set of journal entries, and removes entries that represent signing keys
// that do not appear in the bundle from the datastore. This prevents SPIRE from entering strange
// and inconsistent states as a result of key mismatch following things like database restore,
// disk/journal manipulation, etc.
//
// If we find such a discrepancy, removing the entry from the journal prior to beginning signing
// operations prevents us from using a signing key that consumers may not be able to validate.
// Instead, we'll rotate into a new one.
func (m *Manager) filterInvalidEntries(ctx context.Context, entries *journal.Entries) ([]*JWTKeyEntry, []*X509CAEntry, error) {
	bundle, err := m.fetchOptionalBundle(ctx)

	if err != nil {
		return nil, nil, err
	}

	if bundle == nil {
		return entries.JwtKeys, entries.X509CAs, nil
	}

	filteredEntriesJwtKeys := []*JWTKeyEntry{}

	for _, entry := range entries.GetJwtKeys() {
		if containsJwtSigningKeyid(bundle.JwtSigningKeys, entry.Kid) {
			filteredEntriesJwtKeys = append(filteredEntriesJwtKeys, entry)
			continue
		}
	}

	// If we have an upstream authority then we're not recovering a root CA, so we do
	// not expect to find our CA certificate in the bundle. Simply proceed.
	if m.upstreamClient != nil {
		return filteredEntriesJwtKeys, entries.X509CAs, nil
	}

	filteredEntriesX509CAs := []*X509CAEntry{}

	for _, entry := range entries.GetX509CAs() {
		if containsX509CA(bundle.RootCas, entry.Certificate) {
			filteredEntriesX509CAs = append(filteredEntriesX509CAs, entry)
			continue
		}
	}

	return filteredEntriesJwtKeys, filteredEntriesX509CAs, nil
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
	return s.x509CA != nil && now.After(keyActivationThreshold(s.issuedAt, s.x509CA.Certificate.NotAfter))
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
	return s.jwtKey == nil || now.After(keyActivationThreshold(s.issuedAt, s.jwtKey.NotAfter))
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

func GenerateServerCACSR(signer crypto.Signer, trustDomain spiffeid.TrustDomain, subject pkix.Name) ([]byte, error) {
	// SignatureAlgorithm is not provided. The crypto/x509 package will
	// select the algorithm appropriately based on the signer key type.
	template := x509.CertificateRequest{
		Subject: subject,
		URIs:    []*url.URL{trustDomain.ID().URL()},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, signer)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

func SelfSignX509CA(ctx context.Context, signer crypto.Signer, trustDomain spiffeid.TrustDomain, subject pkix.Name, notBefore, notAfter time.Time) (*X509CA, []*x509.Certificate, error) {
	serialNumber, err := x509util.NewSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	template, err := CreateServerCATemplate(trustDomain.ID(), signer.Public(), trustDomain, notBefore, notAfter, serialNumber, subject)
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

func UpstreamSignX509CA(ctx context.Context, signer crypto.Signer, trustDomain spiffeid.TrustDomain, subject pkix.Name, upstreamClient *UpstreamClient, caTTL time.Duration) (*X509CA, error) {
	csr, err := GenerateServerCACSR(signer, trustDomain, subject)
	if err != nil {
		return nil, err
	}

	validator := X509CAValidator{
		TrustDomain: trustDomain,
		Signer:      signer,
	}

	caChain, err := upstreamClient.MintX509CA(ctx, csr, caTTL, validator.ValidateUpstreamX509CA)
	if err != nil {
		return nil, err
	}

	return &X509CA{
		Signer:        signer,
		Certificate:   caChain[0],
		UpstreamChain: caChain,
	}, nil
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

func preparationThreshold(issuedAt, notAfter time.Time) time.Time {
	lifetime := notAfter.Sub(issuedAt)
	threshold := lifetime / preparationThresholdDivisor
	if threshold > preparationThresholdCap {
		threshold = preparationThresholdCap
	}
	return notAfter.Add(-threshold)
}

func keyActivationThreshold(issuedAt, notAfter time.Time) time.Time {
	lifetime := notAfter.Sub(issuedAt)
	threshold := lifetime / activationThresholdDivisor
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

func containsJwtSigningKeyid(keys []*common.PublicKey, kid string) bool {
	for _, key := range keys {
		if key.Kid == kid {
			return true
		}
	}

	return false
}

func containsX509CA(rootCAs []*common.Certificate, certificate []byte) bool {
	for _, ca := range rootCAs {
		if bytes.Equal(ca.DerBytes, certificate) {
			return true
		}
	}
	return false
}
