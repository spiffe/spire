package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomainAllowlist(t *testing.T) {
	t.Run("unicode", func(t *testing.T) {
		_, err := DomainAllowlist("😬.test")
		assert.EqualError(t, err, `domain "😬.test" must already be punycode encoded`)
	})

	t.Run("punycode", func(t *testing.T) {
		policy, err := DomainAllowlist("xn--n38h.test")
		require.NoError(t, err)
		assert.EqualError(t, policy("😬.test"), `domain "😬.test" must already be punycode encoded`)
		assert.NoError(t, policy("xn--n38h.test"))
		assert.EqualError(t, policy("bad.test"), `domain "bad.test" is not allowed`)
	})

	t.Run("ascii", func(t *testing.T) {
		policy, err := DomainAllowlist("ascii.test")
		require.NoError(t, err)
		assert.NoError(t, policy("ascii.test"))
		assert.EqualError(t, policy("bad.test"), `domain "bad.test" is not allowed`)
	})

	t.Run("invalid domain in config", func(t *testing.T) {
		_, err := DomainAllowlist("invalid/domain.test")
		assert.EqualError(t, err, `domain "invalid/domain.test" is not a valid domain name: idna: disallowed rune U+002F`)
	})

	t.Run("invalid domain on lookup", func(t *testing.T) {
		policy, err := DomainAllowlist()
		require.NoError(t, err)
		assert.EqualError(t, policy("invalid/domain.test"), `domain "invalid/domain.test" is not a valid domain name: idna: disallowed rune U+002F`)
	})
}

func TestAllowAnyDomain(t *testing.T) {
	policy := AllowAnyDomain()
	assert.NoError(t, policy("foo"))
	assert.NoError(t, policy("bar"))
	assert.NoError(t, policy("baz"))
	assert.EqualError(t, policy("invalid/domain.test"), `domain "invalid/domain.test" is not a valid domain name: idna: disallowed rune U+002F`)
}
