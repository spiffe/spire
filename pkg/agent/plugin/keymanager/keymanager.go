package keymanager

import (
	"context"
	"crypto"
)

// KeyManager is provides a signing key for the agent
type KeyManager interface {
	// GenerateKey generates a temporary key. It will not be the key returned
	// by GetKey until after SetKey has been called.
	GenerateKey(ctx context.Context) (crypto.Signer, error)

	// GetKey returns a Key previously set with SetKey.
	GetKey(ctx context.Context) (crypto.Signer, error)

	// SetKey sets the key is returned by GetKey.
	SetKey(ctx context.Context, key crypto.Signer) error
}
