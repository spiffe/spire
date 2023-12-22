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
	Status() journal.Status
	AuthorityID() string
	PublicKey() crypto.PublicKey
	NotAfter() time.Time
}

type SlotLoader struct {
	TrustDomain spiffeid.TrustDomain

	Log            logrus.FieldLogger
	Dir            string
	Catalog        catalog.Catalog
	UpstreamClient *ca.UpstreamClient
}

func (s *SlotLoader) load(ctx context.Context) (*Journal, map[SlotPosition]Slot, error) {
	log := s.Log

	jc := &journalConfig{
		cat:      s.Catalog,
		log:      log,
		filePath: s.journalPath(),
	}

	// Load the journal and see if we can figure out the next and current
	// X509CA and JWTKey entries, if any.
	loadedJournal, err := LoadJournal(ctx, jc)
	if err != nil {
		return nil, nil, err
	}

	entries := loadedJournal.getEntries()

	log.WithFields(logrus.Fields{
		telemetry.X509CAs: len(entries.X509CAs),
		telemetry.JWTKeys: len(entries.JwtKeys),
	}).Info("Journal loaded")

	// filter out local JwtKeys and X509CAs that do not exist in the database bundle
	entries.JwtKeys, entries.X509CAs, err = s.filterInvalidEntries(ctx, entries)
	if err != nil {
		return nil, nil, err
	}

	currentX509CA, nextX509CA, err := s.getX509CASlots(ctx, entries.X509CAs)
	if err != nil {
		return nil, nil, err
	}

	currentJWTKey, nextJWTKey, err := s.getJWTKeysSlots(ctx, entries.JwtKeys)
	if err != nil {
		return nil, nil, err
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

	return loadedJournal, slots, nil
}

// getX509CASlots returns X509CA slots based on the status of the slots.
// - If all the statuses are unknown, the two most recent slots are returned.
// - Active entry is returned on current slot if set.
// - The most recent Prepared or Old entry is returned on next slot.
func (s *SlotLoader) getX509CASlots(ctx context.Context, entries []*journal.X509CAEntry) (*x509CASlot, *x509CASlot, error) {
	var current *x509CASlot
	var next *x509CASlot

	// Search from oldest
	for i := len(entries) - 1; i >= 0; i-- {
		slot, err := s.tryLoadX509CASlotFromEntry(ctx, entries[i])
		if err != nil {
			return nil, nil, err
		}

		// Unable to load slot
		// TODO: the previous implementation analized only the last two entries,
		// and if those slots were empty, we created new slots.
		// Now we iterate through all the file, to try to get a useful slot.
		// Maybe there is room for improvement here, by just verifying if the
		// bundle is not expired?
		if slot == nil {
			continue
		}

		switch slot.Status() {
		// ACTIVE entry must go into current slot
		case journal.Status_ACTIVE:
			current = slot

		// Status can be UNKNOWN only after an upgrade when this happens,
		// we must first set next position, and then current is the next one
		// TODO: status in journal has been introduced in v1.7.
		// Keep this validation in v1.7.x and v1.8.x. Remove this in v1.9.
		case journal.Status_UNKNOWN:
			if next == nil {
				next = slot
			} else if current == nil {
				current = slot
			}

		// Set OLD or PREPARED as next slot
		// Get the newest, since Prepared entry must always be located before an Old entry
		default:
			if next == nil {
				next = slot
			}
		}

		// If both are set finish iteration
		if next != nil && current != nil {
			break
		}
	}

	switch {
	case current != nil:
		// current is set, complete next if required
		if next == nil {
			next = newX509CASlot(otherSlotID(current.id))
		}
	case next != nil:
		// next is set but not current. swap them and initialize next with an empty slot.
		current, next = next, newX509CASlot(otherSlotID(next.id))
	default:
		// neither are set. initialize them with empty slots.
		current = newX509CASlot("A")
		next = newX509CASlot("B")
	}

	return current, next, nil
}

// getJWTKeysSlots returns JWTKey slots based on the status of the slots.
// - If all status are unknown, choose the two newest on the list
// - Active entry is returned on current if set
// - Newest Prepared or Old entry is returned on next
func (s *SlotLoader) getJWTKeysSlots(ctx context.Context, entries []*journal.JWTKeyEntry) (*jwtKeySlot, *jwtKeySlot, error) {
	var current *jwtKeySlot
	var next *jwtKeySlot

	// Search from oldest
	for i := len(entries) - 1; i >= 0; i-- {
		slot, err := s.tryLoadJWTKeySlotFromEntry(ctx, entries[i])
		if err != nil {
			return nil, nil, err
		}

		// Unable to load slot
		// TODO: the previous implementation analized only the last two entries,
		// and if those slots were empty, we created new slots.
		// Now we iterate through all the file, to try to get a useful slot.
		// Maybe there is room for improvement here, by just verifying if the
		// bundle is not expired?
		if slot == nil {
			continue
		}

		switch slot.Status() {
		// ACTIVE entry must go into current slot
		case journal.Status_ACTIVE:
			current = slot

		// Status can be UNKNOWN only after an upgrade when this happens,
		// we must first set next position, and then current is the next one
		// TODO: status in journal has been introduced in v1.7.
		// Keep this validation in v1.7.x and v1.8.x. Remove this in v1.9.
		case journal.Status_UNKNOWN:
			if next == nil {
				next = slot
			} else if current == nil {
				current = slot
			}

		// Set OLD or PREPARED as next slot
		// Get the newest, since Prepared entry must always be located before an Old entry
		default:
			if next == nil {
				next = slot
			}
		}

		// If both are set finish iteration
		if next != nil && current != nil {
			break
		}
	}

	switch {
	case current != nil:
		// current is set, complete next if required
		if next == nil {
			next = newJWTKeySlot(otherSlotID(current.id))
		}
	case next != nil:
		// next is set but not current. swap them and initialize next with an empty slot.
		current, next = next, newJWTKeySlot(otherSlotID(next.id))
	default:
		// neither are set. initialize them with empty slots.
		current = newJWTKeySlot("A")
		next = newJWTKeySlot("B")
	}

	return current, next, nil
}

// filterInvalidEntries takes in a set of journal entries, and removes entries that represent signing keys
// that do not appear in the bundle from the datastore. This prevents SPIRE from entering strange
// and inconsistent states as a result of key mismatch following things like database restore,
// disk/journal manipulation, etc.
//
// If we find such a discrepancy, removing the entry from the journal prior to beginning signing
// operations prevents us from using a signing key that consumers may not be able to validate.
// Instead, we'll rotate into a new one.
func (s *SlotLoader) filterInvalidEntries(ctx context.Context, entries *journal.Entries) ([]*journal.JWTKeyEntry, []*journal.X509CAEntry, error) {
	bundle, err := s.fetchOptionalBundle(ctx)

	if err != nil {
		return nil, nil, err
	}

	if bundle == nil {
		return entries.JwtKeys, entries.X509CAs, nil
	}

	filteredEntriesJwtKeys := []*journal.JWTKeyEntry{}

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

	filteredEntriesX509CAs := []*journal.X509CAEntry{}

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

func (s *SlotLoader) tryLoadX509CASlotFromEntry(ctx context.Context, entry *journal.X509CAEntry) (*x509CASlot, error) {
	slot, badReason, err := s.loadX509CASlotFromEntry(ctx, entry)
	if err != nil {
		s.Log.WithError(err).WithFields(logrus.Fields{
			telemetry.Slot:             entry.SlotId,
			telemetry.IssuedAt:         time.Unix(entry.IssuedAt, 0),
			telemetry.Status:           entry.Status,
			telemetry.LocalAuthorityID: entry.AuthorityId,
		}).Error("X509CA slot failed to load")
		return nil, err
	}
	if badReason != "" {
		s.Log.WithError(errors.New(badReason)).WithFields(logrus.Fields{
			telemetry.Slot:             entry.SlotId,
			telemetry.IssuedAt:         time.Unix(entry.IssuedAt, 0),
			telemetry.Status:           entry.Status,
			telemetry.LocalAuthorityID: entry.AuthorityId,
		}).Warn("X509CA slot unusable")
		return nil, nil
	}
	return slot, nil
}

func (s *SlotLoader) loadX509CASlotFromEntry(ctx context.Context, entry *journal.X509CAEntry) (*x509CASlot, string, error) {
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

	return &x509CASlot{
		id:       entry.SlotId,
		issuedAt: time.Unix(entry.IssuedAt, 0),
		x509CA: &ca.X509CA{
			Signer:        signer,
			Certificate:   cert,
			UpstreamChain: upstreamChain,
		},
		status:      entry.Status,
		authorityID: entry.AuthorityId,
		publicKey:   signer.Public(),
		notAfter:    cert.NotAfter,
	}, "", nil
}

func (s *SlotLoader) tryLoadJWTKeySlotFromEntry(ctx context.Context, entry *journal.JWTKeyEntry) (*jwtKeySlot, error) {
	slot, badReason, err := s.loadJWTKeySlotFromEntry(ctx, entry)
	if err != nil {
		s.Log.WithError(err).WithFields(logrus.Fields{
			telemetry.Slot:             entry.SlotId,
			telemetry.IssuedAt:         time.Unix(entry.IssuedAt, 0),
			telemetry.Status:           entry.Status,
			telemetry.LocalAuthorityID: entry.AuthorityId,
		}).Error("JWT key slot failed to load")
		return nil, err
	}
	if badReason != "" {
		s.Log.WithError(errors.New(badReason)).WithFields(logrus.Fields{
			telemetry.Slot:             entry.SlotId,
			telemetry.IssuedAt:         time.Unix(entry.IssuedAt, 0),
			telemetry.Status:           entry.Status,
			telemetry.LocalAuthorityID: entry.AuthorityId,
		}).Warn("JWT key slot unusable")
		return nil, nil
	}
	return slot, nil
}

func (s *SlotLoader) loadJWTKeySlotFromEntry(ctx context.Context, entry *journal.JWTKeyEntry) (*jwtKeySlot, string, error) {
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

	return &jwtKeySlot{
		id:       entry.SlotId,
		issuedAt: time.Unix(entry.IssuedAt, 0),
		jwtKey: &ca.JWTKey{
			Signer:   signer,
			NotAfter: time.Unix(entry.NotAfter, 0),
			Kid:      entry.Kid,
		},
		status:      entry.Status,
		authorityID: entry.AuthorityId,
		notAfter:    time.Unix(entry.NotAfter, 0),
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

type x509CASlot struct {
	id          string
	issuedAt    time.Time
	x509CA      *ca.X509CA
	status      journal.Status
	authorityID string
	publicKey   crypto.PublicKey
	notAfter    time.Time
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
	return s.x509CA == nil || s.status == journal.Status_OLD
}

func (s *x509CASlot) Reset() {
	s.x509CA = nil
	s.status = journal.Status_OLD
}

func (s *x509CASlot) ShouldPrepareNext(now time.Time) bool {
	return s.x509CA != nil && now.After(preparationThreshold(s.issuedAt, s.x509CA.Certificate.NotAfter))
}

func (s *x509CASlot) ShouldActivateNext(now time.Time) bool {
	return s.x509CA != nil && now.After(keyActivationThreshold(s.issuedAt, s.x509CA.Certificate.NotAfter))
}

func (s *x509CASlot) Status() journal.Status {
	return s.status
}

func (s *x509CASlot) AuthorityID() string {
	return s.authorityID
}

func (s *x509CASlot) PublicKey() crypto.PublicKey {
	return s.publicKey
}

func (s *x509CASlot) NotAfter() time.Time {
	return s.notAfter
}

type jwtKeySlot struct {
	id          string
	issuedAt    time.Time
	jwtKey      *ca.JWTKey
	status      journal.Status
	authorityID string
	notAfter    time.Time
}

func newJWTKeySlot(id string) *jwtKeySlot {
	return &jwtKeySlot{
		id: id,
	}
}

func (s *jwtKeySlot) KmKeyID() string {
	return jwtKeyKmKeyID(s.id)
}

func (s *jwtKeySlot) Status() journal.Status {
	return s.status
}

func (s *jwtKeySlot) AuthorityID() string {
	return s.authorityID
}

func (s *jwtKeySlot) PublicKey() crypto.PublicKey {
	if s.jwtKey == nil {
		return nil
	}
	return s.jwtKey.Signer.Public()
}

func (s *jwtKeySlot) IsEmpty() bool {
	return s.jwtKey == nil || s.status == journal.Status_OLD
}

func (s *jwtKeySlot) Reset() {
	s.jwtKey = nil
	s.status = journal.Status_OLD
}

func (s *jwtKeySlot) ShouldPrepareNext(now time.Time) bool {
	return s.jwtKey == nil || now.After(preparationThreshold(s.issuedAt, s.jwtKey.NotAfter))
}

func (s *jwtKeySlot) ShouldActivateNext(now time.Time) bool {
	return s.jwtKey == nil || now.After(keyActivationThreshold(s.issuedAt, s.jwtKey.NotAfter))
}

func (s *jwtKeySlot) NotAfter() time.Time {
	return s.notAfter
}
