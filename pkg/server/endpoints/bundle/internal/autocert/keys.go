package autocert

import (
	"context"
	"crypto"
	"errors"
)

var (
	ErrNoSuchKey = errors.New("no such key")
)

type KeyType int

const (
	RSA2048 KeyType = iota
	EC256
)

type KeyStore interface {
	// GetPrivateKey is used to obtain a private key. If the key does not
	// exist, ErrNoSuchKey is returned.
	GetPrivateKey(ctx context.Context, id string) (crypto.Signer, error)

	// NewPrivateKey is used create a new private key
	NewPrivateKey(ctx context.Context, id string, keyType KeyType) (crypto.Signer, error)
}
