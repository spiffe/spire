package ca

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
)

const (
	// journalCap is the maximum number of entries per type that we'll
	// hold onto.
	journalCap = 10

	// journalPEMType is the type in the PEM header
	journalPEMType = "SPIRE CA JOURNAL"
)

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

	pemBytes, err := ioutil.ReadFile(path)
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

func (j *Journal) AppendX509CA(slotID string, issuedAt time.Time, x509CA *X509CA) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	var chain [][]byte
	for _, cert := range x509CA.Chain {
		chain = append(chain, cert.Raw)
	}

	backup := j.entries.X509CAs
	j.entries.X509CAs = append(j.entries.X509CAs, &X509CAEntry{
		SlotId:         slotID,
		IssuedAt:       issuedAt.Unix(),
		IsIntermediate: x509CA.IsIntermediate,
		Chain:          chain,
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

func (j *Journal) AppendJWTKey(slotID string, issuedAt time.Time, jwtKey *JWTKey) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	pkixBytes, err := x509.MarshalPKIXPublicKey(jwtKey.Signer.Public())
	if err != nil {
		return errs.Wrap(err)
	}

	backup := j.entries.JwtKeys
	j.entries.JwtKeys = append(j.entries.JwtKeys, &JWTKeyEntry{
		SlotId:    slotID,
		IssuedAt:  issuedAt.Unix(),
		Kid:       jwtKey.Kid,
		PublicKey: pkixBytes,
		NotAfter:  jwtKey.NotAfter.Unix(),
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

	if err := diskutil.AtomicWriteFile(path, pemBytes, 0644); err != nil {
		return errs.Wrap(err)
	}

	return nil
}

func migrateJSONFile(from, to string) (bool, error) {
	type keypairData struct {
		CAs        map[string][]byte `json:"cas"`
		PublicKeys map[string][]byte `json:"public_keys"`
	}

	jsonBytes, err := ioutil.ReadFile(from)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, errs.New("error reading JSON file: %v", err)
	}

	data := new(keypairData)
	if err := json.Unmarshal(jsonBytes, data); err != nil {
		return false, errs.New("unable to decode JSON: %v", err)
	}

	parseX509CA := func(slotID string) (*X509CAEntry, error) {
		certsBytes := data.CAs[x509CAKmKeyId(slotID)]
		if len(certsBytes) == 0 {
			return nil, nil
		}
		chain, err := x509.ParseCertificates(certsBytes)
		if err != nil {
			return nil, errs.New("failed to parse slot %q certificates: %v", slotID, err)
		}
		if len(chain) == 0 {
			return nil, nil
		}
		// The chain is in one of three states:
		// 1) single self-signed cert
		// 2) single upstream-signed cert, implying upstream_bundle=false
		// 3) an upstream-signed cert followed by any intermediates and a root
		//
		// The ca should only be considered an "intermediate" in case #3, so a
		// check for more than one cert should be sufficient for that. However
		// we don't want the the root in the chain anymore, so remove it.
		isIntermediate := len(chain) > 1
		if len(chain) > 1 {
			chain = chain[:len(chain)-1]
		}

		var chainDER [][]byte
		for _, cert := range chain {
			chainDER = append(chainDER, cert.Raw)
		}
		return &X509CAEntry{
			SlotId: slotID,
			// Using NotBefore as IssuedAt is a close enough estimation.
			IssuedAt:       chain[0].NotBefore.Unix(),
			Chain:          chainDER,
			IsIntermediate: isIntermediate,
		}, nil
	}

	parseJWTKey := func(slotID string) (*JWTKeyEntry, error) {
		entryData := data.PublicKeys[jwtKeyKmKeyId(slotID)]
		if len(entryData) == 0 {
			return nil, nil
		}
		publicKey := new(common.PublicKey)
		if err := proto.Unmarshal(entryData, publicKey); err != nil {
			return nil, errs.New("failed to parse slot %q public key: %v", slotID, err)
		}
		// Return a JWTKeyEntry w/o the IssuedAt. The CA and JWT key used to
		// rotate at the same time, so the code below will estimate it based
		// on the CA for the same lost.
		return &JWTKeyEntry{
			SlotId:    slotID,
			PublicKey: publicKey.PkixBytes,
			Kid:       publicKey.Kid,
			NotAfter:  publicKey.NotAfter,
		}, nil
	}

	aX509CA, err := parseX509CA("A")
	if err != nil {
		return false, err
	}

	bX509CA, err := parseX509CA("B")
	if err != nil {
		return false, err
	}

	aJWTKey, err := parseJWTKey("A")
	if err != nil {
		return false, err
	}

	bJWTKey, err := parseJWTKey("B")
	if err != nil {
		return false, err
	}

	// either both X509CA and JWTKey must be valid for each slot or we should
	// discard the other since the old rotation code rotated them together and
	// we need the X509CA to estimate the JWTKey "issued at" time.
	entries := new(JournalEntries)
	if aX509CA != nil && aJWTKey != nil {
		aJWTKey.IssuedAt = aX509CA.IssuedAt
		entries.X509CAs = append(entries.X509CAs, aX509CA)
		entries.JwtKeys = append(entries.JwtKeys, aJWTKey)
	}

	if bX509CA != nil && bJWTKey != nil {
		bJWTKey.IssuedAt = bX509CA.IssuedAt
		entries.X509CAs = append(entries.X509CAs, bX509CA)
		entries.JwtKeys = append(entries.JwtKeys, bJWTKey)
	}

	// sort in ascending "issued at" order
	sort.Slice(entries.X509CAs, func(a, b int) bool {
		return entries.X509CAs[a].IssuedAt < entries.X509CAs[b].IssuedAt
	})
	sort.Slice(entries.JwtKeys, func(a, b int) bool {
		return entries.JwtKeys[a].IssuedAt < entries.JwtKeys[b].IssuedAt
	})

	// save the journal and remove the JSON file
	if err := saveJournalEntries(to, entries); err != nil {
		return false, err
	}
	if err := os.Remove(from); err != nil {
		return false, errs.New("unable to remove old JSON file: %v", err)
	}

	return true, nil
}
