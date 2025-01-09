package keymanagertest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"os"
	"strconv"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	keymanagerbase "github.com/spiffe/spire/pkg/agent/plugin/keymanager/base"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

type keyAlgorithm int

const (
	keyAlgorithmEC keyAlgorithm = iota
	keyAlgorithmRSA
)

var (
	ctx = context.Background()

	keyTypes = map[keymanager.KeyType]keyAlgorithm{
		keymanager.ECP256:  keyAlgorithmEC,
		keymanager.ECP384:  keyAlgorithmEC,
		keymanager.RSA2048: keyAlgorithmRSA,
		keymanager.RSA4096: keyAlgorithmRSA,
	}

	expectCurve = map[keymanager.KeyType]elliptic.Curve{
		keymanager.ECP256: elliptic.P256(),
		keymanager.ECP384: elliptic.P384(),
	}

	expectBits = map[keymanager.KeyType]int{
		keymanager.RSA2048: 2048,
		keymanager.RSA4096: 4096,
	}
)

func NewGenerator() keymanagerbase.Generator {
	if nightly, err := strconv.ParseBool(os.Getenv("NIGHTLY")); err == nil && nightly {
		return nil
	}
	return &testkey.Generator{}
}

type CreateFunc = func(t *testing.T) keymanager.KeyManager

type Config struct {
	Create CreateFunc

	// UnsupportedSignatureAlgorithms is a map of algorithms that are
	// unsupported for the given key type.
	UnsupportedSignatureAlgorithms map[keymanager.KeyType][]x509.SignatureAlgorithm

	signatureAlgorithms map[keymanager.KeyType][]x509.SignatureAlgorithm
}

func (config *Config) testKey(t *testing.T, key keymanager.Key, keyType keymanager.KeyType) {
	config.testKeyWithID(t, key, keyType, keyType.String())
}

func (config *Config) testKeyWithID(t *testing.T, key keymanager.Key, keyType keymanager.KeyType, expectID string) {
	t.Run("id matches", func(t *testing.T) {
		require.Equal(t, expectID, key.ID())
	})
	keyAlgorithm := keyTypes[keyType]
	switch keyAlgorithm {
	case keyAlgorithmRSA:
		assertRSAKey(t, key, expectBits[keyType])
	case keyAlgorithmEC:
		assertECKey(t, key, expectCurve[keyType])
	default:
		require.Fail(t, "unexpected key algorithm", "key algorithm", keyAlgorithm)
	}
	testSignCertificates(t, key, config.signatureAlgorithms[keyType])
}

func Test(t *testing.T, config Config) {
	// Build a convenient set to look up unsupported algorithms
	unsupportedSignatureAlgorithms := make(map[keymanager.KeyType]map[x509.SignatureAlgorithm]struct{})
	for keyType, signatureAlgorithms := range config.UnsupportedSignatureAlgorithms {
		unsupportedSignatureAlgorithms[keyType] = make(map[x509.SignatureAlgorithm]struct{})
		for _, signatureAlgorithm := range signatureAlgorithms {
			unsupportedSignatureAlgorithms[keyType][signatureAlgorithm] = struct{}{}
		}
	}

	rsaAlgorithms := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA,
		x509.SHA384WithRSA,
		x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS,
		x509.SHA384WithRSAPSS,
		x509.SHA512WithRSAPSS,
	}

	ecdsaAlgorithms := []x509.SignatureAlgorithm{
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}

	// build up the list of key types and hash algorithms to test
	candidateSignatureAlgorithms := map[keymanager.KeyType][]x509.SignatureAlgorithm{
		keymanager.ECP256:  ecdsaAlgorithms,
		keymanager.ECP384:  ecdsaAlgorithms,
		keymanager.RSA2048: rsaAlgorithms,
		keymanager.RSA4096: rsaAlgorithms,
	}

	config.signatureAlgorithms = make(map[keymanager.KeyType][]x509.SignatureAlgorithm)
	for keyType, signatureAlgorithms := range candidateSignatureAlgorithms {
		for _, signatureAlgorithm := range signatureAlgorithms {
			if _, unsupported := unsupportedSignatureAlgorithms[keyType][signatureAlgorithm]; !unsupported {
				config.signatureAlgorithms[keyType] = append(config.signatureAlgorithms[keyType], signatureAlgorithm)
			}
		}
	}

	t.Run("GenerateKey", func(t *testing.T) {
		testGenerateKey(t, config)
	})

	t.Run("GetKey", func(t *testing.T) {
		testGetKey(t, config)
	})

	t.Run("GetKeys", func(t *testing.T) {
		testGetKeys(t, config)
	})
}

func testGenerateKey(t *testing.T, config Config) {
	km := config.Create(t)

	for keyType := range keyTypes {
		t.Run(keyType.String(), func(t *testing.T) {
			key := requireGenerateKey(t, km, keyType)
			config.testKey(t, key, keyType)
		})
	}

	t.Run("key id is empty", func(t *testing.T) {
		_, err := km.GenerateKey(ctx, "", keymanager.ECP256)
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "key id is required")
	})

	t.Run("key type is invalid", func(t *testing.T) {
		_, err := km.GenerateKey(ctx, "id", 0)
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "key type is required")
	})

	t.Run("key id can be overwritten", func(t *testing.T) {
		km := config.Create(t)
		oldKey := requireGenerateKeyWithID(t, km, keymanager.ECP256, "id")
		config.testKeyWithID(t, oldKey, keymanager.ECP256, "id")
		newKey := requireGenerateKeyWithID(t, km, keymanager.RSA2048, "id")
		config.testKeyWithID(t, newKey, keymanager.RSA2048, "id")

		// Signing with oldKey should fail since it has been overwritten.
		digest := sha256.Sum256([]byte("DATA"))
		_, err := oldKey.Sign(rand.Reader, digest[:], crypto.SHA256)
		spiretest.AssertGRPCStatusContains(t, err, codes.Internal, "does not match", "signing with an overwritten key did not fail as expected")
	})
}

func testGetKey(t *testing.T, config Config) {
	km := config.Create(t)

	for keyType := range keyTypes {
		t.Run(keyType.String(), func(t *testing.T) {
			requireGenerateKey(t, km, keyType)
			key := requireGetKey(t, km, keyType.String())
			config.testKey(t, key, keyType)
		})
	}

	t.Run("key id is empty", func(t *testing.T) {
		_, err := km.GetKey(ctx, "")
		spiretest.AssertGRPCStatus(t, err, codes.InvalidArgument, plugin.PrefixMessage(km, "key id is required"))
	})

	t.Run("no such key", func(t *testing.T) {
		_, err := km.GetKey(ctx, "nope")
		spiretest.AssertGRPCStatus(t, err, codes.NotFound, plugin.PrefixMessage(km, `key "nope" not found`))
	})
}

func testGetKeys(t *testing.T, config Config) {
	km := config.Create(t)

	t.Run("no keys", func(t *testing.T) {
		require.Empty(t, requireGetKeys(t, km))
	})

	for keyType := range keyTypes {
		requireGenerateKey(t, km, keyType)
	}

	t.Run("many keys", func(t *testing.T) {
		keys := make(map[string]keymanager.Key)
		for _, key := range requireGetKeys(t, km) {
			keys[key.ID()] = key
		}
		require.Len(t, keys, len(keyTypes))
		for keyType := range keyTypes {
			config.testKey(t, keys[keyType.String()], keyType)
		}
	})
}

func requireGenerateKey(t *testing.T, km keymanager.KeyManager, keyType keymanager.KeyType) keymanager.Key {
	key, err := km.GenerateKey(ctx, keyType.String(), keyType)
	require.NoError(t, err)
	return key
}

func requireGenerateKeyWithID(t *testing.T, km keymanager.KeyManager, keyType keymanager.KeyType, id string) keymanager.Key {
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

func testSignCertificates(t *testing.T, key keymanager.Key, signatureAlgorithms []x509.SignatureAlgorithm) {
	for _, signatureAlgorithm := range signatureAlgorithms {
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
	assert.NoError(t, err, "failed to sign certificate with key %q", key.ID())
}
