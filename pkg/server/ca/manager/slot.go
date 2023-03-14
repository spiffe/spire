package manager

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SlotPosition int

const (
	CurrentX509CASlot SlotPosition = iota
	NextX509CASlot
	CurrentJWTKeySlot
	NextJWTKeySlot
)

type Slot interface {
	KmKeyID() string
	IsEmpty() bool
	Reset()
	ShouldPrepareNext(now time.Time) bool
	ShouldActivateNext(now time.Time) bool
}

type SlotLoader struct {
	TrustDomain spiffeid.TrustDomain

	Log            logrus.FieldLogger
	Dir            string
	Catalog        catalog.Catalog
	UpstreamClient *ca.UpstreamClient
}

func (s *SlotLoader) Load(ctx context.Context) (*Journal, map[SlotPosition]Slot, error) {
	log := s.Log
	journalPath := s.journalPath()

	var currentX509CA *X509CASlot
	var nextX509CA *X509CASlot
	var currentJWTKey *JwtKeySlot
	var nextJWTKey *JwtKeySlot

	jsonPath := filepath.Join(s.Dir, "certs.json")
	if ok, err := migrateJSONFile(jsonPath, journalPath); err != nil {
		return nil, nil, errs.New("failed to migrate old JSON data: %v", err)
	} else if ok {
		log.Info("Migrated data to journal")
	}

	// Load the journal and see if we can figure out the next and current
	// X509CA and JWTKey entries, if any.
	log.WithField(telemetry.Path, journalPath).Debug("Loading journal")
	journal, err := LoadJournal(journalPath)
	if err != nil {
		return nil, nil, err
	}

	entries := journal.Entries()

	log.WithFields(logrus.Fields{
		telemetry.X509CAs: len(entries.X509CAs),
		telemetry.JWTKeys: len(entries.JwtKeys),
	}).Info("Journal loaded")

	// filter out local JwtKeys and X509CAs that do not exist in the database bundle
	entries.JwtKeys, entries.X509CAs, err = s.filterInvalidEntries(ctx, entries)
	if err != nil {
		return nil, nil, err
	}

	if len(entries.X509CAs) > 0 {
		nextX509CA, err = s.tryLoadX509CASlotFromEntry(ctx, entries.X509CAs[len(entries.X509CAs)-1])
		if err != nil {
			return nil, nil, err
		}
		// if the last entry is ok, then consider the next entry
		if nextX509CA != nil && len(entries.X509CAs) > 1 {
			currentX509CA, err = s.tryLoadX509CASlotFromEntry(ctx, entries.X509CAs[len(entries.X509CAs)-2])
			if err != nil {
				return nil, nil, err
			}
		}
	}
	switch {
	case currentX509CA != nil:
		// both current and next are set
	case nextX509CA != nil:
		// next is set but not current. swap them and initialize next with an empty slot.
		currentX509CA, nextX509CA = nextX509CA, newX509CASlot(otherSlotID(nextX509CA.id))
	default:
		// neither are set. initialize them with empty slots.
		currentX509CA = newX509CASlot("A")
		nextX509CA = newX509CASlot("B")
	}

	if len(entries.JwtKeys) > 0 {
		nextJWTKey, err = s.tryLoadJWTKeySlotFromEntry(ctx, entries.JwtKeys[len(entries.JwtKeys)-1])
		if err != nil {
			return nil, nil, err
		}
		// if the last entry is ok, then consider the next entry
		if nextJWTKey != nil && len(entries.JwtKeys) > 1 {
			currentJWTKey, err = s.tryLoadJWTKeySlotFromEntry(ctx, entries.JwtKeys[len(entries.JwtKeys)-2])
			if err != nil {
				return nil, nil, err
			}
		}
	}
	switch {
	case currentJWTKey != nil:
		// both current and next are set
	case nextJWTKey != nil:
		// next is set but not current. swap them and initialize next with an empty slot.
		currentJWTKey, nextJWTKey = nextJWTKey, newJWTKeySlot(otherSlotID(nextJWTKey.id))
	default:
		// neither are set. initialize them with empty slots.
		currentJWTKey = newJWTKeySlot("A")
		nextJWTKey = newJWTKeySlot("B")
	}

	slots := make(map[SlotPosition]Slot)
	if currentX509CA != nil {
		slots[CurrentX509CASlot] = currentX509CA
	}

	if nextX509CA != nil {
		slots[NextX509CASlot] = nextX509CA
	}

	if currentJWTKey != nil {
		slots[CurrentJWTKeySlot] = currentJWTKey
	}

	if nextJWTKey != nil {
		slots[NextJWTKeySlot] = nextJWTKey
	}

	return journal, slots, nil
}

// filterInvalidEntries takes in a set of journal entries, and removes entries that represent signing keys
// that do not appear in the bundle from the datastore. This prevents SPIRE from entering strange
// and inconsistent states as a result of key mismatch following things like database restore,
// disk/journal manipulation, etc.
//
// If we find such a discrepancy, removing the entry from the journal prior to beginning signing
// operations prevents us from using a signing key that consumers may not be able to validate.
// Instead, we'll rotate into a new one.
func (s *SlotLoader) filterInvalidEntries(ctx context.Context, entries *journal.Entries) ([]*JWTKeyEntry, []*X509CAEntry, error) {
	bundle, err := s.fetchOptionalBundle(ctx)

	if err != nil {
		return nil, nil, err
	}

	if bundle == nil {
		return entries.JwtKeys, entries.X509CAs, nil
	}

	filteredEntriesJwtKeys := []*JWTKeyEntry{}

	for _, entry := range entries.GetJwtKeys() {
		if containsJwtSigningKeyID(bundle.JwtSigningKeys, entry.Kid) {
			filteredEntriesJwtKeys = append(filteredEntriesJwtKeys, entry)
			continue
		}
	}

	// If we have an upstream authority then we're not recovering a root CA, so we do
	// not expect to find our CA certificate in the bundle. Simply proceed.
	if s.UpstreamClient != nil {
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

func (s *SlotLoader) fetchOptionalBundle(ctx context.Context) (*common.Bundle, error) {
	ds := s.Catalog.GetDataStore()
	bundle, err := ds.FetchBundle(ctx, s.TrustDomain.IDString())
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return bundle, nil
}

func (s *SlotLoader) tryLoadX509CASlotFromEntry(ctx context.Context, entry *X509CAEntry) (*X509CASlot, error) {
	slot, badReason, err := s.loadX509CASlotFromEntry(ctx, entry)
	if err != nil {
		s.Log.WithError(err).WithFields(logrus.Fields{
			telemetry.Slot: entry.SlotId,
		}).Error("X509CA slot failed to load")
		return nil, err
	}
	if badReason != "" {
		s.Log.WithError(errors.New(badReason)).WithFields(logrus.Fields{
			telemetry.Slot: entry.SlotId,
		}).Warn("X509CA slot unusable")
		return nil, nil
	}
	return slot, nil
}

func (s *SlotLoader) loadX509CASlotFromEntry(ctx context.Context, entry *X509CAEntry) (*X509CASlot, string, error) {
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

	signer, err := s.makeSigner(ctx, x509CAKmKeyID(entry.SlotId))
	if err != nil {
		return nil, "", err
	}

	switch {
	case signer == nil:
		return nil, "no key manager key", nil
	case !publicKeyEqual(cert.PublicKey, signer.Public()):
		return nil, "public key does not match key manager key", nil
	}

	return &X509CASlot{
		id:       entry.SlotId,
		issuedAt: time.Unix(entry.IssuedAt, 0),
		x509CA: &ca.X509CA{
			Signer:        signer,
			Certificate:   cert,
			UpstreamChain: upstreamChain,
		},
	}, "", nil
}
func (s *SlotLoader) tryLoadJWTKeySlotFromEntry(ctx context.Context, entry *JWTKeyEntry) (*JwtKeySlot, error) {
	slot, badReason, err := s.loadJWTKeySlotFromEntry(ctx, entry)
	if err != nil {
		s.Log.WithError(err).WithFields(logrus.Fields{
			telemetry.Slot: entry.SlotId,
		}).Error("JWT key slot failed to load")
		return nil, err
	}
	if badReason != "" {
		s.Log.WithError(errors.New(badReason)).WithFields(logrus.Fields{
			telemetry.Slot: entry.SlotId,
		}).Warn("JWT key slot unusable")
		return nil, nil
	}
	return slot, nil
}

func (s *SlotLoader) loadJWTKeySlotFromEntry(ctx context.Context, entry *JWTKeyEntry) (*JwtKeySlot, string, error) {
	if entry.SlotId == "" {
		return nil, "no slot id", nil
	}

	publicKey, err := x509.ParsePKIXPublicKey(entry.PublicKey)
	if err != nil {
		return nil, "", errs.Wrap(err)
	}

	signer, err := s.makeSigner(ctx, jwtKeyKmKeyID(entry.SlotId))
	if err != nil {
		return nil, "", err
	}

	switch {
	case signer == nil:
		return nil, "no key manager key", nil
	case !publicKeyEqual(publicKey, signer.Public()):
		return nil, "public key does not match key manager key", nil
	}

	return &JwtKeySlot{
		id:       entry.SlotId,
		issuedAt: time.Unix(entry.IssuedAt, 0),
		jwtKey: &ca.JWTKey{
			Signer:   signer,
			NotAfter: time.Unix(entry.NotAfter, 0),
			Kid:      entry.Kid,
		},
	}, "", nil
}

func (s *SlotLoader) makeSigner(ctx context.Context, keyID string) (crypto.Signer, error) {
	km := s.Catalog.GetKeyManager()

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

func (s *SlotLoader) journalPath() string {
	return filepath.Join(s.Dir, "journal.pem")
}

func x509CAKmKeyID(id string) string {
	return fmt.Sprintf("x509-CA-%s", id)
}

func jwtKeyKmKeyID(id string) string {
	return fmt.Sprintf("JWT-Signer-%s", id)
}

func containsJwtSigningKeyID(keys []*common.PublicKey, kid string) bool {
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

func publicKeyEqual(a, b crypto.PublicKey) bool {
	matches, err := cryptoutil.PublicKeyEqual(a, b)
	if err != nil {
		return false
	}
	return matches
}

func otherSlotID(id string) string {
	if id == "A" {
		return "B"
	}
	return "A"
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

type X509CASlot struct {
	id       string
	issuedAt time.Time
	x509CA   *ca.X509CA
}

func newX509CASlot(id string) *X509CASlot {
	return &X509CASlot{
		id: id,
	}
}

func (s *X509CASlot) KmKeyID() string {
	return x509CAKmKeyID(s.id)
}

func (s *X509CASlot) IsEmpty() bool {
	return s.x509CA == nil
}

func (s *X509CASlot) Reset() {
	s.x509CA = nil
}

func (s *X509CASlot) ShouldPrepareNext(now time.Time) bool {
	return s.x509CA != nil && now.After(preparationThreshold(s.issuedAt, s.x509CA.Certificate.NotAfter))
}

func (s *X509CASlot) ShouldActivateNext(now time.Time) bool {
	return s.x509CA != nil && now.After(keyActivationThreshold(s.issuedAt, s.x509CA.Certificate.NotAfter))
}

type JwtKeySlot struct {
	id       string
	issuedAt time.Time
	jwtKey   *ca.JWTKey
}

func newJWTKeySlot(id string) *JwtKeySlot {
	return &JwtKeySlot{
		id: id,
	}
}

func (s *JwtKeySlot) KmKeyID() string {
	return jwtKeyKmKeyID(s.id)
}

func (s *JwtKeySlot) IsEmpty() bool {
	return s.jwtKey == nil
}

func (s *JwtKeySlot) Reset() {
	s.jwtKey = nil
}

func (s *JwtKeySlot) ShouldPrepareNext(now time.Time) bool {
	return s.jwtKey == nil || now.After(preparationThreshold(s.issuedAt, s.jwtKey.NotAfter))
}

func (s *JwtKeySlot) ShouldActivateNext(now time.Time) bool {
	return s.jwtKey == nil || now.After(keyActivationThreshold(s.issuedAt, s.jwtKey.NotAfter))
}
