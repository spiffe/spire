package storage

import (
	"crypto/x509"
	"path/filepath"
)

func Backcompat(dir string) (Storage, error) {
	j, err := JSONFile(filepath.Join(dir, "data.json"))
	if err != nil {
		return nil, err
	}
	return &backcompat{
		jsonFile: j,
		legacy:   LegacyDir(dir),
	}, nil
}

type backcompat struct {
	jsonFile Storage
	legacy   Storage
}

func (b *backcompat) LoadBundle() ([]*x509.Certificate, error) {
	return b.jsonFile.LoadBundle()
}

func (b *backcompat) StoreBundle(bundle []*x509.Certificate) error {
	if err := b.jsonFile.StoreBundle(bundle); err != nil {
		return err
	}
	if err := b.legacy.StoreBundle(bundle); err != nil {
		return err
	}
	return nil
}

func (b *backcompat) LoadSVID() ([]*x509.Certificate, error) {
	return b.jsonFile.LoadSVID()
}

func (b *backcompat) StoreSVID(svid []*x509.Certificate) error {
	if err := b.jsonFile.StoreSVID(svid); err != nil {
		return err
	}
	if err := b.legacy.StoreSVID(svid); err != nil {
		return err
	}
	return nil
}

func (b *backcompat) DeleteSVID() error {
	if err := b.jsonFile.DeleteSVID(); err != nil {
		return err
	}
	if err := b.legacy.DeleteSVID(); err != nil {
		return err
	}
	return nil
}
