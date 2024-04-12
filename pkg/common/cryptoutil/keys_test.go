package cryptoutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
)

func TestJoseAlgFromPublicKey(t *testing.T) {
	var algo jose.SignatureAlgorithm
	var err error
	algo, err = JoseAlgFromPublicKey(genRSA(1024).Public())
	require.EqualError(t, err, "unsupported RSA key size: 128")
	require.Empty(t, algo)

	algo, err = JoseAlgFromPublicKey(testkey.NewRSA2048(t).Public())
	require.NoError(t, err)
	require.Equal(t, algo, jose.RS256)

	algo, err = JoseAlgFromPublicKey(testkey.NewEC256(t).Public())
	require.NoError(t, err)
	require.Equal(t, algo, jose.ES256)

	algo, err = JoseAlgFromPublicKey(testkey.NewEC384(t).Public())
	require.NoError(t, err)
	require.Equal(t, algo, jose.ES384)

	algo, err = JoseAlgFromPublicKey(genEC(elliptic.P224()).Public())
	require.EqualError(t, err, "unable to determine signature algorithm for EC public key size 224")
	require.Empty(t, algo)

	algo, err = JoseAlgFromPublicKey(genEC(elliptic.P521()).Public())
	require.EqualError(t, err, "unable to determine signature algorithm for EC public key size 521")
	require.Empty(t, algo)
}

func genRSA(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	check(err)
	return key
}

func genEC(curve elliptic.Curve) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	check(err)
	return key
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
