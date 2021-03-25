package keymanagertest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

var (
	ctx = context.Background()
)

type CreateFunc = func(t *testing.T) keymanager.KeyManager

func Test(t *testing.T, create CreateFunc) {
	t.Run("GenerateKey", func(t *testing.T) {
		testGenerateKey(t, create)
	})

	t.Run("GetKey", func(t *testing.T) {
		testGetKey(t, create)
	})

	t.Run("GetKeys", func(t *testing.T) {
		testGetKeys(t, create)
	})
}

func testGenerateKey(t *testing.T, create CreateFunc) {
	km := create(t)

	t.Run("EC256", func(t *testing.T) {
		key := requireGenerateKey(t, km, "ec256", keymanager.ECP256)
		testECKey(t, key, "ec256", elliptic.P256())
	})

	t.Run("EC384", func(t *testing.T) {
		key := requireGenerateKey(t, km, "ec384", keymanager.ECP384)
		testECKey(t, key, "ec384", elliptic.P384())
	})

	t.Run("RSA1024", func(t *testing.T) {
		key := requireGenerateKey(t, km, "rsa1024", keymanager.RSA1024)
		testRSAKey(t, key, "rsa1024", 1024)
	})

	t.Run("RSA2048", func(t *testing.T) {
		key := requireGenerateKey(t, km, "rsa2048", keymanager.RSA2048)
		testRSAKey(t, key, "rsa2048", 2048)
	})

	t.Run("RSA4096", func(t *testing.T) {
		key := requireGenerateKey(t, km, "rsa4096", keymanager.RSA4096)
		testRSAKey(t, key, "rsa4096", 4096)
	})

	t.Run("key id is empty", func(t *testing.T) {
		_, err := km.GenerateKey(ctx, "", keymanager.ECP256)
		spiretest.AssertGRPCStatus(t, err, codes.InvalidArgument, plugin.PrefixMessage(km, "key id is required"))
	})

	t.Run("key type is invalid", func(t *testing.T) {
		_, err := km.GenerateKey(ctx, "id", 0)
		spiretest.AssertGRPCStatus(t, err, codes.InvalidArgument, plugin.PrefixMessage(km, "key type is required"))
	})

	t.Run("key id can be overwritten", func(t *testing.T) {
		km := create(t)
		key := requireGenerateKey(t, km, "id", keymanager.ECP256)
		testECKey(t, key, "id", elliptic.P256())
		key = requireGenerateKey(t, km, "id", keymanager.RSA1024)
		testRSAKey(t, key, "id", 1024)
	})
}

func testGetKey(t *testing.T, create CreateFunc) {
	km := create(t)
	requireGenerateKey(t, km, "ec256", keymanager.ECP256)
	requireGenerateKey(t, km, "ec384", keymanager.ECP384)
	requireGenerateKey(t, km, "rsa1024", keymanager.RSA1024)
	requireGenerateKey(t, km, "rsa2048", keymanager.RSA2048)
	requireGenerateKey(t, km, "rsa4096", keymanager.RSA4096)

	t.Run("EC256", func(t *testing.T) {
		key := requireGetKey(t, km, "ec256")
		testECKey(t, key, "ec256", elliptic.P256())
	})

	t.Run("EC384", func(t *testing.T) {
		key := requireGetKey(t, km, "ec384")
		testECKey(t, key, "ec384", elliptic.P384())
	})

	t.Run("RSA1024", func(t *testing.T) {
		key := requireGetKey(t, km, "rsa1024")
		testRSAKey(t, key, "rsa1024", 1024)
	})

	t.Run("RSA2048", func(t *testing.T) {
		key := requireGetKey(t, km, "rsa2048")
		testRSAKey(t, key, "rsa2048", 2048)
	})

	t.Run("RSA4096", func(t *testing.T) {
		key := requireGetKey(t, km, "rsa4096")
		testRSAKey(t, key, "rsa4096", 4096)
	})

	t.Run("key id is empty", func(t *testing.T) {
		_, err := km.GetKey(ctx, "")
		spiretest.AssertGRPCStatus(t, err, codes.InvalidArgument, plugin.PrefixMessage(km, "key id is required"))
	})

	t.Run("no such key", func(t *testing.T) {
		_, err := km.GetKey(ctx, "nope")
		spiretest.AssertGRPCStatus(t, err, codes.NotFound, plugin.PrefixMessage(km, `private key "nope" not found`))
	})
}

func testGetKeys(t *testing.T, create CreateFunc) {
	km := create(t)

	t.Run("no keys", func(t *testing.T) {
		require.Empty(t, requireGetKeys(t, km))
	})

	requireGenerateKey(t, km, "ec256", keymanager.ECP256)
	requireGenerateKey(t, km, "ec384", keymanager.ECP384)
	requireGenerateKey(t, km, "rsa1024", keymanager.RSA1024)
	requireGenerateKey(t, km, "rsa2048", keymanager.RSA2048)
	requireGenerateKey(t, km, "rsa4096", keymanager.RSA4096)

	t.Run("many keys", func(t *testing.T) {
		keys := make(map[string]keymanager.Key)
		for _, key := range requireGetKeys(t, km) {
			keys[key.ID()] = key
		}
		require.Len(t, keys, 5)
		testECKey(t, keys["ec256"], "ec256", elliptic.P256())
		testECKey(t, keys["ec384"], "ec384", elliptic.P384())
		testRSAKey(t, keys["rsa1024"], "rsa1024", 1024)
		testRSAKey(t, keys["rsa2048"], "rsa2048", 2048)
		testRSAKey(t, keys["rsa4096"], "rsa4096", 4096)
	})
}

func testECKey(t *testing.T, key keymanager.Key, expectID string, expectCurve elliptic.Curve) {
	testKey(t, key, expectID)
	assertECKey(t, key, expectCurve)
	testSignCertificates(t, key,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	)
}

func testRSAKey(t *testing.T, key keymanager.Key, expectID string, expectBits int) {
	testKey(t, key, expectID)
	assertRSAKey(t, key, expectBits)

	signatureAlgorithms := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA,
		x509.SHA384WithRSA,
		x509.SHA512WithRSA,
	}
	if expectBits > 1024 {
		signatureAlgorithms = append(signatureAlgorithms,
			x509.SHA256WithRSAPSS,
			x509.SHA384WithRSAPSS,
			x509.SHA512WithRSAPSS,
		)
	}
	testSignCertificates(t, key, signatureAlgorithms...)
}

func testKey(t *testing.T, key keymanager.Key, expectID string) {
	t.Run("id matches", func(t *testing.T) {
		require.Equal(t, expectID, key.ID())
	})
}

func requireGenerateKey(t *testing.T, km keymanager.KeyManager, id string, keyType keymanager.KeyType) keymanager.Key {
	key, err := km.GenerateKey(ctx, id, keyType)
	require.NoError(t, err)
	return key
}

func requireGetKey(t *testing.T, km keymanager.KeyManager, id string) keymanager.Key {
	key, err := km.GetKey(ctx, id)
	require.NoError(t, err)
	return key
}

func requireGetKeys(t *testing.T, km keymanager.KeyManager) []keymanager.Key {
	keys, err := km.GetKeys(ctx)
	require.NoError(t, err)
	return keys
}

func assertECKey(t *testing.T, key keymanager.Key, curve elliptic.Curve) {
	publicKey, ok := key.Public().(*ecdsa.PublicKey)
	require.True(t, ok, "type %T is not ECDSA public key", key.Public())
	require.Equal(t, curve, publicKey.Curve, "unexpected curve")
}

func assertRSAKey(t *testing.T, key keymanager.Key, bits int) {
	publicKey, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok, "type %T is not RSA public key", key.Public())
	require.Equal(t, bits, publicKey.N.BitLen(), "unexpected bits")
}

func testSignCertificates(t *testing.T, key keymanager.Key, signatureAlgorithms ...x509.SignatureAlgorithm) {
	for _, signatureAlgorithm := range signatureAlgorithms {
		signatureAlgorithm := signatureAlgorithm
		t.Run("sign data "+signatureAlgorithm.String(), func(t *testing.T) {
			assertSignCertificate(t, key, signatureAlgorithm)
		})
	}
}

func assertSignCertificate(t *testing.T, key keymanager.Key, signatureAlgorithm x509.SignatureAlgorithm) {
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		SignatureAlgorithm: signatureAlgorithm,
	}
	_, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	assert.NoError(t, err, "failed to sign certificate with key", key.ID())
}
