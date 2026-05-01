package x509util

import (
	"testing"

	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
)

var (
	privateKey = testkey.MustEC256()
)

func TestSubjectKeyIDToString(t *testing.T) {
	t.Run("empty ski", func(t *testing.T) {
		str := SubjectKeyIDToString([]byte{})
		require.Empty(t, str)
	})

	t.Run("small byte", func(t *testing.T) {
		str := SubjectKeyIDToString([]byte("foo"))
		require.Equal(t, "666f6f", str)
	})

	t.Run("no odd number", func(t *testing.T) {
		str := SubjectKeyIDToString([]byte{1})
		require.Equal(t, "01", str)
	})

	originalSKISetting := x509utilsha256skid
	defer func() {
		x509utilsha256skid = originalSKISetting
	}()

	x509utilsha256skid = false // fips140.Enabled == false
	realSKI, err := GetSubjectKeyID(privateKey.Public())
	require.NoError(t, err)

	t.Run("real parsed ski, SHA-1 is used by default", func(t *testing.T) {
		str := SubjectKeyIDToString(realSKI)
		require.Equal(t, "42c702d94031c6bc849ec99fa361802a877bdade", str)
	})

	x509utilsha256skid = true // fips140.Enabled == true
	realSKI, err = GetSubjectKeyID(privateKey.Public())
	require.NoError(t, err)

	t.Run("real parsed ski, SHA-256 is used if fips140 is enabled", func(t *testing.T) {
		str := SubjectKeyIDToString(realSKI)
		require.Equal(t, "01236f15caa45918323f309f2651d2cb3989c404", str)
	})
}
