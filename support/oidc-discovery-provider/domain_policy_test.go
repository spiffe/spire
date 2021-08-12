package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomainAllowlist(t *testing.T) {
	t.Run("unicode", func(t *testing.T) {
		policy, err := DomainAllowlist("😬.test")
		require.NoError(t, err)
		assert.NoError(t, policy("😬.test"))
		assert.NoError(t, policy("xn--n38h.test"))
		assert.EqualError(t, policy("bad.test"), `domain "bad.test" is not allowed`)
	})

	t.Run("punycode", func(t *testing.T) {
		policy, err := DomainAllowlist("xn--n38h.test")
		require.NoError(t, err)
		assert.NoError(t, policy("😬.test"))
		assert.NoError(t, policy("xn--n38h.test"))
		assert.EqualError(t, policy("bad.test"), `domain "bad.test" is not allowed`)
	})

	t.Run("ascii", func(t *testing.T) {
		policy, err := DomainAllowlist("ascii.test")
		require.NoError(t, err)
		assert.NoError(t, policy("ascii.test"))
		assert.EqualError(t, policy("bad.test"), `domain "bad.test" is not allowed`)
	})
}

func TestAllowAnyDomain(t *testing.T) {
	policy := AllowAnyDomain()
	assert.NoError(t, policy("foo"))
	assert.NoError(t, policy("bar"))
	assert.NoError(t, policy("baz"))
}
