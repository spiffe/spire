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

func TestGetSubjectKeyIDs(t *testing.T) {
	originalSKISetting := x509utilsha256skid
	defer func() {
		x509utilsha256skid = originalSKISetting
	}()

	const (
		sha1ID   = "42c702d94031c6bc849ec99fa361802a877bdade"
		sha256ID = "01236f15caa45918323f309f2651d2cb3989c404"
	)

	for _, tt := range []struct {
		name     string
		sha256   bool
		expected []string
	}{
		{name: "SHA-1 first by default", sha256: false, expected: []string{sha1ID, sha256ID}},
		{name: "SHA-256 first if fips140 is enabled", sha256: true, expected: []string{sha256ID, sha1ID}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			x509utilsha256skid = tt.sha256
			skis, err := GetSubjectKeyIDs(privateKey.Public())
			require.NoError(t, err)
			var actual []string
			for _, ski := range skis {
				actual = append(actual, SubjectKeyIDToString(ski))
			}
			require.Equal(t, tt.expected, actual)

			// The first one is what GetSubjectKeyID returns.
			ski, err := GetSubjectKeyID(privateKey.Public())
			require.NoError(t, err)
			require.Equal(t, skis[0], ski)
		})
	}
}
