package manager

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/zeebo/errs"
	"google.golang.org/protobuf/proto"
)

const (
	// journalCap is the maximum number of entries per type that we'll
	// hold onto.
	journalCap = 10

	// journalPEMType is the type in the PEM header
	journalPEMType = "SPIRE CA JOURNAL"
)

type JournalEntries = journal.Entries
type X509CAEntry = journal.X509CAEntry
type JWTKeyEntry = journal.JWTKeyEntry

// Journal stores X509 CAs and JWT keys on disk as they are rotated by the
// manager. The data format on disk is a PEM encoded protocol buffer.
type Journal struct {
	path string

	mu      sync.RWMutex
	entries *JournalEntries
}

func LoadJournal(path string) (*Journal, error) {
	j := &Journal{
		path:    path,
		entries: new(JournalEntries),
	}

	pemBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return j, nil
		}
		return nil, errs.Wrap(err)
	}
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errs.New("invalid PEM block")
	}
	if pemBlock.Type != journalPEMType {
		return nil, errs.New("invalid PEM block type %q", pemBlock.Type)
	}

	if err := proto.Unmarshal(pemBlock.Bytes, j.entries); err != nil {
		return nil, errs.New("unable to unmarshal entries: %v", err)
	}

	return j, nil
}

func (j *Journal) Entries() *JournalEntries {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return proto.Clone(j.entries).(*JournalEntries)
}

func (j *Journal) AppendX509CA(slotID string, issuedAt time.Time, x509CA *ca.X509CA) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	backup := j.entries.X509CAs
	j.entries.X509CAs = append(j.entries.X509CAs, &X509CAEntry{
		SlotId:        slotID,
		IssuedAt:      issuedAt.Unix(),
		Certificate:   x509CA.Certificate.Raw,
		UpstreamChain: chainDER(x509CA.UpstreamChain),
		Status:        journal.Status_PREPARED,
		AuthorityId:   x509util.SubjectKeyIDToString(x509CA.Certificate.SubjectKeyId),
	})

	exceeded := len(j.entries.X509CAs) - journalCap
	if exceeded > 0 {
		// make a new slice so we keep growing the backing array to drop the first
		x509CAs := make([]*X509CAEntry, journalCap)
		copy(x509CAs, j.entries.X509CAs[exceeded:])
		j.entries.X509CAs = x509CAs
	}

	if err := j.save(); err != nil {
		j.entries.X509CAs = backup
		return err
	}

	return nil
}

// UpdateX509CAStatus updates a stored X509CA entry to have the given status, updating the journal file.
func (j *Journal) UpdateX509CAStatus(issuedAt time.Time, status journal.Status) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	backup := j.entries.X509CAs

	// Once we have the authorityID, we can use it to search for an entry,
	// but for now, we depend on issuedAt.
	issuedAtUnix := issuedAt.Unix()

	var found bool
	for i := len(j.entries.X509CAs) - 1; i >= 0; i-- {
		entry := j.entries.X509CAs[i]
		if issuedAtUnix == entry.IssuedAt {
			found = true
			entry.Status = status
			break
		}
	}

	if !found {
		return fmt.Errorf("no journal entry found issued at: %v", issuedAtUnix)
	}

	if err := j.save(); err != nil {
		j.entries.X509CAs = backup
		return err
	}

	return nil
}

func (j *Journal) AppendJWTKey(slotID string, issuedAt time.Time, jwtKey *ca.JWTKey) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	pkixBytes, err := x509.MarshalPKIXPublicKey(jwtKey.Signer.Public())
	if err != nil {
		return errs.Wrap(err)
	}

	backup := j.entries.JwtKeys
	j.entries.JwtKeys = append(j.entries.JwtKeys, &JWTKeyEntry{
		SlotId:      slotID,
		IssuedAt:    issuedAt.Unix(),
		Kid:         jwtKey.Kid,
		PublicKey:   pkixBytes,
		NotAfter:    jwtKey.NotAfter.Unix(),
		Status:      journal.Status_PREPARED,
		AuthorityId: jwtKey.Kid,
	})

	exceeded := len(j.entries.JwtKeys) - journalCap
	if exceeded > 0 {
		// make a new slice so we keep growing the backing array to drop the first
		jwtKeys := make([]*JWTKeyEntry, journalCap)
		copy(jwtKeys, j.entries.JwtKeys[exceeded:])
		j.entries.JwtKeys = jwtKeys
	}

	if err := j.save(); err != nil {
		j.entries.JwtKeys = backup
		return err
	}

	return nil
}

// UpdateJWTKeyStatus updates a stored JWTKey entry to have the given status, updating the journal file.
func (j *Journal) UpdateJWTKeyStatus(issuedAt time.Time, status journal.Status) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	backup := j.entries.JwtKeys

	// Once we have the authorityID, we can use it to search for an entry,
	// but for now we depend on issuedAt.
	issuedAtUnix := issuedAt.Unix()

	var found bool
	for i := len(j.entries.JwtKeys) - 1; i >= 0; i-- {
		entry := j.entries.JwtKeys[i]
		if issuedAtUnix == entry.IssuedAt {
			found = true
			entry.Status = status
			break
		}
	}

	if !found {
		return fmt.Errorf("no journal entry found issued at: %v", issuedAtUnix)
	}

	if err := j.save(); err != nil {
		j.entries.JwtKeys = backup
		return err
	}

	return nil
}

func (j *Journal) save() error {
	return saveJournalEntries(j.path, j.entries)
}

func saveJournalEntries(path string, entries *JournalEntries) error {
	entriesBytes, err := proto.Marshal(entries)
	if err != nil {
		return errs.Wrap(err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  journalPEMType,
		Bytes: entriesBytes,
	})

	if err := diskutil.AtomicWritePubliclyReadableFile(path, pemBytes); err != nil {
		return errs.Wrap(err)
	}

	return nil
}

func chainDER(chain []*x509.Certificate) [][]byte {
	var der [][]byte
	for _, cert := range chain {
		der = append(der, cert.Raw)
	}
	return der
}
