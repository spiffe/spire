package witkey

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

type WITKey struct {
	ID        string
	PublicKey crypto.PublicKey
	ExpiresAt time.Time
	Tainted   bool
}

func toProtoFields(witKey WITKey) (id string, publicKey []byte, expiresAt int64, tainted bool, err error) {
	if witKey.ID == "" {
		return "", nil, 0, false, errors.New("missing key ID for WIT key")
	}

	if witKey.PublicKey == nil {
		return "", nil, 0, false, fmt.Errorf("missing public key for WIT key %q", witKey.ID)
	}
	publicKey, err = x509.MarshalPKIXPublicKey(witKey.PublicKey)
	if err != nil {
		return "", nil, 0, false, fmt.Errorf("failed to marshal public key for WIT key %q: %w", witKey.ID, err)
	}

	if !witKey.ExpiresAt.IsZero() {
		expiresAt = witKey.ExpiresAt.Unix()
	}

	return witKey.ID, publicKey, expiresAt, witKey.Tainted, nil
}

func fromProtoFields(keyID string, publicKeyPKIX []byte, expiresAtUnix int64, tainted bool) (WITKey, error) {
	if keyID == "" {
		return WITKey{}, errors.New("missing key ID for WIT key")
	}

	if len(publicKeyPKIX) == 0 {
		return WITKey{}, fmt.Errorf("missing public key for WIT key %q", keyID)
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyPKIX)
	if err != nil {
		return WITKey{}, fmt.Errorf("failed to unmarshal public key for WIT key %q: %w", keyID, err)
	}

	var expiresAt time.Time
	if expiresAtUnix != 0 {
		expiresAt = time.Unix(expiresAtUnix, 0)
	}

	return WITKey{
		ID:        keyID,
		PublicKey: publicKey,
		ExpiresAt: expiresAt,
		Tainted:   tainted,
	}, nil
}
