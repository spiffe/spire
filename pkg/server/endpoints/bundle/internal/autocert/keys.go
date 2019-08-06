package autocert

import (
	"context"
	"crypto"
)

type KeyType int

const (
	RSA2048 KeyType = iota
	EC256
)

type KeyStore interface {
	// GetPrivateKey is used to obtain a private key
	GetPrivateKey(ctx context.Context, id string) (crypto.Signer, error)

	// NewPrivateKey is used create a new private key
	NewPrivateKey(ctx context.Context, id string, keyType KeyType) (crypto.Signer, error)
}
