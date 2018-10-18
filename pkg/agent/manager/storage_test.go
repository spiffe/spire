package manager

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadBundle(t *testing.T) {
	testReadBundle(t, filepath.Join(util.ProjectRoot(), "test", "fixture", "certs", "bundle.proto"))
}

func TestMigrateBundle(t *testing.T) {
	dir, err := ioutil.TempDir("", "spire-agent-manager-storage-")
	require.NoError(t, err)

	defer os.RemoveAll(dir)

	err = copyFile(
		filepath.Join(util.ProjectRoot(), "test", "fixture", "certs", "bundle.der"),
		filepath.Join(dir, "bundle.der"))
	require.NoError(t, err)

	err = MigrateBundle("spiffe://example.org",
		filepath.Join(dir, "bundle.der"),
		filepath.Join(dir, "bundle.proto"))
	require.NoError(t, err)

	// old file should be deleted
	_, err = os.Stat(filepath.Join(dir, "bundle.der"))
	assert.True(t, os.IsNotExist(err))

	// new file should be "readable"
	testReadBundle(t, filepath.Join(dir, "bundle.proto"))
}

func testReadBundle(t *testing.T, bundlePath string) {
	expectedRootCAs, err := util.LoadBundleFixture()
	require.NoError(t, err)

	actualBundle, err := ReadBundle(bundlePath)
	require.NoError(t, err)

	actualRootCAs := actualBundle.RootCAs()
	require.Equal(t, len(expectedRootCAs), len(actualRootCAs), "wrong number of root CAs")

	for i, c := range expectedRootCAs {
		assert.True(t, actualRootCAs[i].Equal(c), "root %d is not as expected", i)
	}
}

func copyFile(src, dst string) error {
	srcBytes, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(dst, srcBytes, 0644)
}
