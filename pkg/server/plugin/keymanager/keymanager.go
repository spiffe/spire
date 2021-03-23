package keymanager

import (
	"context"
	"crypto"

	"github.com/spiffe/spire/pkg/common/catalog"
)

// KeyType represents the types of keys that are supported by the KeyManager.
type KeyType int

const (
	KeyTypeUnset KeyType = iota
	ECP256
	ECP384
	RSA1024
	RSA2048
	RSA4096
)

// Key is a KeyManager-backed key
type Key interface {
	crypto.Signer

	// ID returns the ID of the key in the KeyManager.
	ID() string
}

// KeyManager is the client interface for the service type KeyManager interface.
type KeyManager interface {
	catalog.PluginInfo

	// GenerateKey generates a key with the given ID and key type. If a key
	// with that ID already exists, it is overwritten.
	GenerateKey(ctx context.Context, id string, keyType KeyType) (Key, error)

	// GetKey returns the key with the given ID. If a key with that ID does
	// not exist, a status of codes.NotFound is returned.
	GetKey(ctx context.Context, id string) (Key, error)

	// GetKeys returns all keys managed by the KeyManager.
	GetKeys(ctx context.Context) ([]Key, error)
}
