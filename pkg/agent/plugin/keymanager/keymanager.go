package keymanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/spiffe/spire/pkg/common/catalog"
)

// KeyManager provides either a single or multi-key key manager
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

// Key is a KeyManager-backed key
type Key interface {
	crypto.Signer

	// ID returns the ID of the key in the KeyManager.
	ID() string
}

// KeyType represents the types of keys that are supported by the KeyManager.
type KeyType int

const (
	KeyTypeUnset KeyType = iota
	ECP256
	ECP384
	RSA2048
	RSA4096
	MLDSA44
	MLDSA65
	MLDSA87
)

// GenerateSigner generates a new key for the given key type
func (keyType KeyType) GenerateSigner() (crypto.Signer, error) {
	switch keyType {
	case ECP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ECP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case MLDSA44:
		return mldsa.GenerateKey(mldsa.MLDSA44())
	case MLDSA65:
		return mldsa.GenerateKey(mldsa.MLDSA65())
	case MLDSA87:
		return mldsa.GenerateKey(mldsa.MLDSA87())
	}
	return nil, fmt.Errorf("unknown key type %q", keyType)
}

// String returns the string representation of the key type
func (keyType KeyType) String() string {
	switch keyType {
	case KeyTypeUnset:
		return "UNSET"
	case ECP256:
		return "ec-p256"
	case ECP384:
		return "ec-p384"
	case RSA2048:
		return "rsa-2048"
	case RSA4096:
		return "rsa-4096"
	case MLDSA44:
		return "ml-dsa-44"
	case MLDSA65:
		return "ml-dsa-65"
	case MLDSA87:
		return "ml-dsa-87"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(keyType))
	}
}
