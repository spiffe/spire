package keymanager_test

import (
	"context"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/test/fakes/fakeagentkeymanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSVIDKeyManager(t *testing.T) {
	km := fakeagentkeymanager.New(t, "")

	svidKM := keymanager.ForSVID(km)

	// Assert that there are no keys
	keys, err := svidKM.GetKeys(context.Background())
	require.NoError(t, err)
	assert.Empty(t, keys)

	// Generate key (without previous key)
	keyA, err := svidKM.GenerateKey(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, "agent-svid-A", keyA.ID(), "key ID does not match the A SVID key ID")

	// Assert that the generated key exists
	keys, err = svidKM.GetKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []keymanager.Key{keyA}, keys)

	// Generate B key (passing A key)
	keyB, err := svidKM.GenerateKey(context.Background(), keyA)
	require.NoError(t, err)
	assert.Equal(t, "agent-svid-B", keyB.ID(), "key ID does not match the B SVID key ID")

	// Assert that both keys are listed
	keys, err = svidKM.GetKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []keymanager.Key{keyA, keyB}, keys)

	// Regenerate the A key (passing the B key)
	keyA, err = svidKM.GenerateKey(context.Background(), keyB)
	require.NoError(t, err)
	assert.Equal(t, "agent-svid-A", keyA.ID(), "key ID does not match the A SVID key ID")
}
