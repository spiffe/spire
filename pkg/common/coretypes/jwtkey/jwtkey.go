package jwtkey

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

type JWTKey struct {
	ID        string
	PublicKey crypto.PublicKey
	ExpiresAt time.Time
}

func toProtoFields(jwtKey JWTKey) (string, []byte, int64, error) {
	if jwtKey.ID == "" {
		return "", nil, 0, errors.New("missing key ID for JWT key")
	}

	if jwtKey.PublicKey == nil {
		return "", nil, 0, fmt.Errorf("missing public key for JWT key %q", jwtKey.ID)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(jwtKey.PublicKey)
	if err != nil {
		return "", nil, 0, fmt.Errorf("failed to marshal public key for JWT key %q: %w", jwtKey.ID, err)
	}

	var expiresAt int64
	if !jwtKey.ExpiresAt.IsZero() {
		expiresAt = jwtKey.ExpiresAt.Unix()
	}

	return jwtKey.ID, publicKey, expiresAt, nil
}

func fromProtoFields(keyID string, publicKeyPKIX []byte, expiresAtUnix int64) (JWTKey, error) {
	if keyID == "" {
		return JWTKey{}, errors.New("missing key ID for JWT key")
	}

	if len(publicKeyPKIX) == 0 {
		return JWTKey{}, fmt.Errorf("missing public key for JWT key %q", keyID)
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyPKIX)
	if err != nil {
		return JWTKey{}, fmt.Errorf("failed to unmarshal public key for JWT key %q: %w", keyID, err)
	}

	var expiresAt time.Time
	if expiresAtUnix != 0 {
		expiresAt = time.Unix(expiresAtUnix, 0)
	}

	return JWTKey{
		ID:        keyID,
		PublicKey: publicKey,
		ExpiresAt: expiresAt,
	}, nil
}
