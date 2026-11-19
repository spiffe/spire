package cryptoutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
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
	require.Equal(t, jose.RS256, algo)

	algo, err = JoseAlgFromPublicKey(testkey.NewEC256(t).Public())
	require.NoError(t, err)
	require.Equal(t, jose.ES256, algo)

	algo, err = JoseAlgFromPublicKey(testkey.NewEC384(t).Public())
	require.NoError(t, err)
	require.Equal(t, jose.ES384, algo)

	for _, tt := range []struct {
		params mldsa.Parameters
		alg    jose.SignatureAlgorithm
	}{
		{params: mldsa.MLDSA44(), alg: jose.MLDSA44},
		{params: mldsa.MLDSA65(), alg: jose.MLDSA65},
		{params: mldsa.MLDSA87(), alg: jose.MLDSA87},
	} {
		algo, err = JoseAlgFromPublicKey(genMLDSA(tt.params).Public())
		require.NoError(t, err)
		require.Equal(t, tt.alg, algo)
	}

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

func TestPublicKeyEqual(t *testing.T) {
	a := genMLDSA(mldsa.MLDSA44())
	b := genMLDSA(mldsa.MLDSA44())

	equal, err := PublicKeyEqual(a.Public(), a.Public())
	require.NoError(t, err)
	require.True(t, equal)

	equal, err = PublicKeyEqual(a.Public(), b.Public())
	require.NoError(t, err)
	require.False(t, equal)

	equal, err = PublicKeyEqual(a.Public(), testkey.NewEC256(t).Public())
	require.NoError(t, err)
	require.False(t, equal)
}

func TestKeyMatches(t *testing.T) {
	a := genMLDSA(mldsa.MLDSA65())
	b := genMLDSA(mldsa.MLDSA65())

	matches, err := KeyMatches(a, a.Public())
	require.NoError(t, err)
	require.True(t, matches)

	matches, err = KeyMatches(a, b.Public())
	require.NoError(t, err)
	require.False(t, matches)
}

func genMLDSA(params mldsa.Parameters) *mldsa.PrivateKey {
	key, err := mldsa.GenerateKey(params)
	check(err)
	return key
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
