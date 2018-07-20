package jwtsvid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"math/big"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	signingMethodES256 = &signingMethodECDSA{
		SigningMethodECDSA: jwt.SigningMethodES256,
	}
)

// signingMethodECDSA is a copy of the implementation of the JWT package
// modified to accomodate both an *ecdsa.PrivateKey and a crypto.Signer based
// key. It can be thrown away as soon as
// https://github.com/dgrijalva/jwt-go/pull/236 is merged.
type signingMethodECDSA struct {
	*jwt.SigningMethodECDSA
}

func (m *signingMethodECDSA) Sign(signingString string, key interface{}) (string, error) {
	// Get the signer
	signer, ok := key.(crypto.Signer)
	if !ok {
		return "", jwt.ErrInvalidKeyType
	}

	// make sure the signer is for ECDSA
	publicKey, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return "", jwt.ErrInvalidKeyType
	}

	// Create the hasher
	if !m.Hash.Available() {
		return "", jwt.ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	// Sign the string and return r, s
	signatureBytes, err := signer.Sign(rand.Reader, hasher.Sum(nil), m.Hash)
	if err != nil {
		return "", err
	}

	// decode R and S
	signature := struct {
		R, S *big.Int
	}{}
	if _, err := asn1.Unmarshal(signatureBytes, &signature); err != nil {
		return "", err
	}

	curveBits := publicKey.Curve.Params().BitSize

	if m.CurveBits != curveBits {
		return "", jwt.ErrInvalidKey
	}

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	// We serialize the outpus (r and s) into big-endian byte arrays and pad
	// them with zeros on the left to make sure the sizes work out. Both arrays
	// must be keyBytes long, and the output must be 2*keyBytes long.
	rBytes := signature.R.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := signature.S.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	out := append(rBytesPadded, sBytesPadded...)

	return jwt.EncodeSegment(out), nil
}
