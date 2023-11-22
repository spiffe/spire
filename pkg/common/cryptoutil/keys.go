package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"github.com/go-jose/go-jose/v3"
	"github.com/zeebo/errs"
)

func RSAPublicKeyEqual(a, b *rsa.PublicKey) bool {
	return a.E == b.E && a.N.Cmp(b.N) == 0
}

func ECDSAPublicKeyEqual(a, b *ecdsa.PublicKey) bool {
	return a.Curve == b.Curve && a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}

func ECDSAKeyMatches(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) bool {
	return ECDSAPublicKeyEqual(&privateKey.PublicKey, publicKey)
}

func RSAKeyMatches(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) bool {
	return RSAPublicKeyEqual(&privateKey.PublicKey, publicKey)
}

func PublicKeyEqual(a, b crypto.PublicKey) (bool, error) {
	switch a := a.(type) {
	case *rsa.PublicKey:
		rsaPublicKey, ok := b.(*rsa.PublicKey)
		return ok && RSAPublicKeyEqual(a, rsaPublicKey), nil
	case *ecdsa.PublicKey:
		ecdsaPublicKey, ok := b.(*ecdsa.PublicKey)
		return ok && ECDSAPublicKeyEqual(a, ecdsaPublicKey), nil
	default:
		return false, fmt.Errorf("unsupported public key type %T", a)
	}
}

func KeyMatches(privateKey crypto.PrivateKey, publicKey crypto.PublicKey) (bool, error) {
	switch privateKey := privateKey.(type) {
	case *rsa.PrivateKey:
		rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
		return ok && RSAKeyMatches(privateKey, rsaPublicKey), nil
	case *ecdsa.PrivateKey:
		ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
		return ok && ECDSAKeyMatches(privateKey, ecdsaPublicKey), nil
	default:
		return false, fmt.Errorf("unsupported private key type %T", privateKey)
	}
}

func JoseAlgFromPublicKey(publicKey any) (jose.SignatureAlgorithm, error) {
	var alg jose.SignatureAlgorithm
	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		// Prevent the use of keys smaller than 2048 bits
		if publicKey.Size() < 256 {
			return "", errs.New("unsupported RSA key size: %d", publicKey.Size())
		}
		alg = jose.RS256
	case *ecdsa.PublicKey:
		params := publicKey.Params()
		switch params.BitSize {
		case 256:
			alg = jose.ES256
		case 384:
			alg = jose.ES384
		default:
			return "", errs.New("unable to determine signature algorithm for EC public key size %d", params.BitSize)
		}
	default:
		return "", errs.New("unable to determine signature algorithm for public key type %T", publicKey)
	}
	return alg, nil
}
