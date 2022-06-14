package storage

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
)

func JSONFile(path string) (Storage, error) {
	rawData, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &jsonFile{path: path}, nil
		}
		return nil, fmt.Errorf("failed to load storage from JSON file: %w", err)
	}

	data := new(jsonData)
	if err := json.Unmarshal(rawData, data); err != nil {
		return nil, fmt.Errorf("failed to decode storage from JSON file: %w", err)
	}

	svid, err := parseCertificates(data.SVID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SVID from JSON file: %w", err)
	}

	bundle, err := parseCertificates(data.Bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to decode bundle from JSON file: %w", err)
	}

	return &jsonFile{
		path:   path,
		svid:   svid,
		bundle: bundle,
	}, nil
}

type jsonFile struct {
	mtx  sync.RWMutex
	path string

	svid   []*x509.Certificate
	bundle []*x509.Certificate
}

func (j *jsonFile) LoadBundle() ([]*x509.Certificate, error) {
	j.mtx.RLock()
	defer j.mtx.RUnlock()

	if len(j.bundle) == 0 {
		return nil, ErrNotCached
	}
	return j.bundle, nil
}

func (j *jsonFile) StoreBundle(bundle []*x509.Certificate) error {
	j.mtx.Lock()
	defer j.mtx.Unlock()

	if err := j.store(j.svid, bundle); err != nil {
		return err
	}

	j.bundle = bundle
	return nil
}

func (j *jsonFile) LoadSVID() ([]*x509.Certificate, error) {
	j.mtx.RLock()
	defer j.mtx.RUnlock()

	if len(j.svid) == 0 {
		return nil, ErrNotCached
	}
	return j.svid, nil
}

func (j *jsonFile) StoreSVID(svid []*x509.Certificate) error {
	j.mtx.Lock()
	defer j.mtx.Unlock()

	return j.storeSVID(svid)
}

func (j *jsonFile) DeleteSVID() error {
	j.mtx.Lock()
	defer j.mtx.Unlock()

	return j.storeSVID(nil)
}

func (j *jsonFile) storeSVID(svid []*x509.Certificate) error {
	if err := j.store(svid, j.bundle); err != nil {
		return err
	}

	j.svid = svid
	return nil
}

func (j *jsonFile) store(svid, bundle []*x509.Certificate) error {
	encodedSVID, err := encodeCertificates(svid)
	if err != nil {
		return fmt.Errorf("failed to encode SVID certificates: %w", err)
	}

	encodedBundle, err := encodeCertificates(bundle)
	if err != nil {
		return fmt.Errorf("failed to encode bundle certificates: %w", err)
	}

	data, err := json.Marshal(jsonData{
		SVID:   encodedSVID,
		Bundle: encodedBundle,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	if err := diskutil.AtomicWriteFile(j.path, data, 0600); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

type jsonData struct {
	SVID   [][]byte `json:"svid"`
	Bundle [][]byte `json:"bundle"`
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
