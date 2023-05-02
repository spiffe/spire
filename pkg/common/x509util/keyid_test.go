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
		require.Equal(t, "66:6f:6f", str)
	})

	realSKI, err := x509util.GetSubjectKeyID(privateKey.Public())
	require.NoError(t, err)

	t.Run("real parsed ski", func(t *testing.T) {
		str := x509util.SubjectKeyIDToString(realSKI)
		require.Equal(t, "42:c7:02:d9:40:31:c6:bc:84:9e:c9:9f:a3:61:80:2a:87:7b:da:de", str)
	})
}
