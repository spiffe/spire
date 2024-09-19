package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadCertPool(t *testing.T) {
	require := require.New(t)

	// expect failure if no certificates are found
	_, err := LoadCertPool("testdata/empty-bundle.pem")
	require.EqualError(err, "no certificates found in file")

	// expect two certificates from mixed bundle. the key in the bundle should
	// be ignored.
	pool, err := LoadCertPool("testdata/mixed-bundle.pem")
	require.NoError(err)
	require.Len(pool.Subjects(), 2)
}
