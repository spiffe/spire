package manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeterministicKeyID(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kid1a, err := deterministicKeyID(key1)
	require.NoError(t, err)
	require.NotEmpty(t, kid1a)

	kid1b, err := deterministicKeyID(key1)
	require.NoError(t, err)

	kid2, err := deterministicKeyID(key2)
	require.NoError(t, err)

	assert.Equal(t, kid1a, kid1b, "the same key must yield the same kid")
	assert.NotEqual(t, kid1a, kid2, "different keys must yield different kids")
}
