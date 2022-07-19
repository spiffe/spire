package workloadkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
)

func KeyTypeFromString(s string) (KeyType, error) {
	switch strings.ToLower(s) {
	case "rsa-2048":
		return RSA2048, nil
	case "ec-p256":
		return ECP256, nil
	default:
		return KeyTypeUnset, fmt.Errorf("key type %q is unknown; must be one of [rsa-2048, ec-p256]", s)
	}
}

// KeyType represents the types of keys that are supported by the KeyManager.
type KeyType int

const (
	KeyTypeUnset KeyType = iota
	ECP256
	RSA2048
)

// GenerateSigner generates a new key for the given key type
func (keyType KeyType) GenerateSigner() (crypto.Signer, error) {
	switch keyType {
	case ECP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unknown key type %q", keyType)
	}
}

// String returns the string representation of the key type
func (keyType KeyType) String() string {
	switch keyType {
	case KeyTypeUnset:
		return "UNSET"
	case ECP256:
		return "ec-p256"
	case RSA2048:
		return "rsa-2048"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(keyType))
	}
}
