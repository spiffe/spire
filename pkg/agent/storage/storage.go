package storage

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
)

var (
	ErrNotCached = errors.New("not cached")
)

type Storage interface {
	// LoadSVID loads the SVID from storage. Returns ErrNotCached if the SVID
	// does not exist in the cache.
	LoadSVID() ([]*x509.Certificate, error)

	// StoreSVID stores the SVID.
	StoreSVID(certs []*x509.Certificate) error

	// DeleteSVID deletes the SVID.
	DeleteSVID() error

	// LoadBundle loads the SVID from storage. Returns ErrNotCached if the
	// bundle does not exist in the cache.
	LoadBundle() ([]*x509.Certificate, error)

	// StoreBundle stores the bundle.
	StoreBundle(certs []*x509.Certificate) error
}

func Open(dir string) (Storage, error) {
	legacySVID, legacySVIDTime, err := loadLegacySVID(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	legacyBundle, legacyBundleTime, err := loadLegacyBundle(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	data, dataTime, err := loadData(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	storeNow := false

	if !legacySVIDTime.IsZero() && (dataTime.IsZero() || dataTime.Before(legacySVIDTime)) {
		storeNow = true
		data.SVID = legacySVID
	}

	if !legacyBundleTime.IsZero() && (dataTime.IsZero() || dataTime.Before(legacyBundleTime)) {
		storeNow = true
		data.Bundle = legacyBundle
	}

	if storeNow {
		if err := storeData(dir, data); err != nil {
			return nil, err
		}
	}

	return &storage{
		dir:  dir,
		data: data,
	}, nil
}

type storage struct {
	dir string

	mtx  sync.RWMutex
	data storageData
}

func (s *storage) LoadBundle() ([]*x509.Certificate, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	if len(s.data.Bundle) == 0 {
		return nil, ErrNotCached
	}
	return s.data.Bundle, nil
}

func (s *storage) StoreBundle(bundle []*x509.Certificate) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if err := storeLegacyBundle(s.dir, bundle); err != nil {
		return err
	}

	data := s.data
	data.Bundle = bundle

	if err := storeData(s.dir, data); err != nil {
		return err
	}

	s.data = data
	return nil
}

func (s *storage) LoadSVID() ([]*x509.Certificate, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	if len(s.data.SVID) == 0 {
		return nil, ErrNotCached
	}
	return s.data.SVID, nil
}

func (s *storage) StoreSVID(svid []*x509.Certificate) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if err := storeLegacySVID(s.dir, svid); err != nil {
		return err
	}

	data := s.data
	data.SVID = svid

	if err := storeData(s.dir, data); err != nil {
		return err
	}

	s.data = data
	return nil
}

func (s *storage) DeleteSVID() error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if err := deleteLegacySVID(s.dir); err != nil {
		return err
	}

	data := s.data
	data.SVID = nil
	if err := storeData(s.dir, data); err != nil {
		return err
	}

	s.data = data
	return nil
}

func readFile(path string) ([]byte, time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer func() {
		_ = f.Close()
	}()
	fi, err := f.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, time.Time{}, err
	}
	if err := f.Close(); err != nil {
		return nil, time.Time{}, err
	}
	return data, fi.ModTime(), nil
}

type storageJSON struct {
	SVID   [][]byte `json:"svid"`
	Bundle [][]byte `json:"bundle"`
}

type storageData struct {
	SVID   []*x509.Certificate
	Bundle []*x509.Certificate
}

func (d storageData) MarshalJSON() ([]byte, error) {
	svid, err := encodeCertificates(d.SVID)
	if err != nil {
		return nil, err
	}
	bundle, err := encodeCertificates(d.Bundle)
	if err != nil {
		return nil, err
	}
	return json.Marshal(storageJSON{
		SVID:   svid,
		Bundle: bundle,
	})
}

func (d *storageData) UnmarshalJSON(b []byte) error {
	j := new(storageJSON)
	if err := json.Unmarshal(b, j); err != nil {
		return err
	}
	svid, err := parseCertificates(j.SVID)
	if err != nil {
		return err
	}
	bundle, err := parseCertificates(j.Bundle)
	if err != nil {
		return err
	}

	d.SVID = svid
	d.Bundle = bundle
	return nil
}

func storeData(dir string, data storageData) error {
	path := dataPath(dir)

	marshaled, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	if err := diskutil.AtomicWriteFile(path, marshaled, 0600); err != nil {
		return fmt.Errorf("failed to write data file: %w", err)
	}

	return nil
}

func loadData(dir string) (storageData, time.Time, error) {
	path := dataPath(dir)

	marshaled, mtime, err := readFile(path)
	if err != nil {
		return storageData{}, time.Time{}, fmt.Errorf("failed to load data: %w", err)
	}

	var data storageData
	if err := json.Unmarshal(marshaled, &data); err != nil {
		return storageData{}, time.Time{}, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return data, mtime, nil
}

func parseCertificates(certsPEM [][]byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, certPEM := range certsPEM {
		cert, err := pemutil.ParseCertificate(certPEM)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func encodeCertificates(certs []*x509.Certificate) ([][]byte, error) {
	var certsPEM [][]byte
	for _, cert := range certs {
		if _, err := x509.ParseCertificate(cert.Raw); err != nil {
			return nil, err
		}
		certsPEM = append(certsPEM, pemutil.EncodeCertificate(cert))
	}
	return certsPEM, nil
}

func dataPath(dir string) string {
	return filepath.Join(dir, "agent-data.json")
}
