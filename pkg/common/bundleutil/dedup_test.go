package bundleutil

import (
	"testing"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDedupSigningKeysByKid(t *testing.T) {
	t.Run("collapses duplicate kid keeping max NotAfter", func(t *testing.T) {
		bundle := &common.Bundle{
			JwtSigningKeys: []*common.PublicKey{
				{Kid: "A", PkixBytes: []byte("a"), NotAfter: 100},
				{Kid: "A", PkixBytes: []byte("a"), NotAfter: 200},
				{Kid: "B", PkixBytes: []byte("b"), NotAfter: 150},
			},
		}

		changed := DedupSigningKeysByKid(bundle)

		assert.True(t, changed)
		require.Len(t, bundle.JwtSigningKeys, 2)
		assert.Equal(t, "A", bundle.JwtSigningKeys[0].Kid)
		assert.EqualValues(t, 200, bundle.JwtSigningKeys[0].NotAfter)
		assert.Equal(t, "B", bundle.JwtSigningKeys[1].Kid)
	})

	t.Run("no-op when all kids distinct", func(t *testing.T) {
		keys := []*common.PublicKey{
			{Kid: "A", NotAfter: 100},
			{Kid: "B", NotAfter: 200},
		}
		bundle := &common.Bundle{JwtSigningKeys: keys}

		changed := DedupSigningKeysByKid(bundle)

		assert.False(t, changed)
		require.Len(t, bundle.JwtSigningKeys, 2)
	})

	t.Run("merged entry is tainted if any duplicate is tainted", func(t *testing.T) {
		bundle := &common.Bundle{
			JwtSigningKeys: []*common.PublicKey{
				{Kid: "A", NotAfter: 200, TaintedKey: false},
				{Kid: "A", NotAfter: 100, TaintedKey: true},
			},
		}

		changed := DedupSigningKeysByKid(bundle)

		assert.True(t, changed)
		require.Len(t, bundle.JwtSigningKeys, 1)
		assert.EqualValues(t, 200, bundle.JwtSigningKeys[0].NotAfter)
		assert.True(t, bundle.JwtSigningKeys[0].TaintedKey)
	})

	t.Run("dedups WIT signing keys too", func(t *testing.T) {
		bundle := &common.Bundle{
			WitSigningKeys: []*common.PublicKey{
				{Kid: "W", NotAfter: 100},
				{Kid: "W", NotAfter: 300},
			},
		}

		changed := DedupSigningKeysByKid(bundle)

		assert.True(t, changed)
		require.Len(t, bundle.WitSigningKeys, 1)
		assert.EqualValues(t, 300, bundle.WitSigningKeys[0].NotAfter)
	})
}
