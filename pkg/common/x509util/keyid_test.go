package x509util_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
)

var (
	privateKey = testkey.MustEC256()
)

func TestSubjectKeyIDToString(t *testing.T) {
	t.Run("empty ski", func(t *testing.T) {
		str := x509util.SubjectKeyIDToString([]byte{})
		require.Empty(t, str)
	})

	t.Run("small byte", func(t *testing.T) {
		str := x509util.SubjectKeyIDToString([]byte("foo"))
		require.Equal(t, "666f6f", str)
	})

	t.Run("no odd number", func(t *testing.T) {
		str := x509util.SubjectKeyIDToString([]byte{1})
		require.Equal(t, "01", str)
	})

	realSKI, err := x509util.GetSubjectKeyID(privateKey.Public())
	require.NoError(t, err)

	t.Run("real parsed ski", func(t *testing.T) {
		str := x509util.SubjectKeyIDToString(realSKI)
		require.Equal(t, "42c702d94031c6bc849ec99fa361802a877bdade", str)
	})
}
