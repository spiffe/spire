package storage

import (
	"crypto/x509"
	"errors"
)

var (
	ErrNotCached = errors.New("not cached")
)

type Storage interface {
	LoadSVID() ([]*x509.Certificate, error)
	StoreSVID(certs []*x509.Certificate) error
	DeleteSVID() error
	LoadBundle() ([]*x509.Certificate, error)
	StoreBundle(certs []*x509.Certificate) error
}
