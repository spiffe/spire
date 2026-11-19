package workloadkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
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
	case "ec-p384":
		return ECP384, nil
	case "ml-dsa-44":
		return MLDSA44, nil
	case "ml-dsa-65":
		return MLDSA65, nil
	case "ml-dsa-87":
		return MLDSA87, nil
	default:
		return KeyTypeUnset, fmt.Errorf("key type %q is unknown; must be one of [rsa-2048, ec-p256, ec-p384, ml-dsa-44, ml-dsa-65, ml-dsa-87]", s)
	}
}

// KeyType represents the types of keys that are supported by the KeyManager.
type KeyType int

const (
	KeyTypeUnset KeyType = iota
	ECP256
	RSA2048
	ECP384
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
	case MLDSA44:
		return mldsa.GenerateKey(mldsa.MLDSA44())
	case MLDSA65:
		return mldsa.GenerateKey(mldsa.MLDSA65())
	case MLDSA87:
		return mldsa.GenerateKey(mldsa.MLDSA87())
	default:
		return nil, fmt.Errorf("unknown key type %q", keyType)
	}
}

// SigningAlgorithm returns the JOSE signing algorithm to be used with keys of
// this type.
func (keyType KeyType) SigningAlgorithm() (string, error) {
	switch keyType {
	case ECP256:
		return "ES256", nil
	case ECP384:
		return "ES384", nil
	case RSA2048:
		return "RS256", nil
	case MLDSA44:
		return "ML-DSA-44", nil
	case MLDSA65:
		return "ML-DSA-65", nil
	case MLDSA87:
		return "ML-DSA-87", nil
	default:
		return "", fmt.Errorf("unknown key type %q", keyType.String())
	}
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
