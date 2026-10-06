//go:build !windows

package containerinfo

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

const (
	testPodUID      = types.UID("00000000-1111-2222-3333-444444444444")
	testContainerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestExtractPodUIDAndContainerID(t *testing.T) {
	log := hclog.NewNullLogger()

	assertFound := func(t *testing.T, rootDir string, wantPodUID types.UID, wantContainerID string) {
		extractor := Extractor{RootDir: rootDir}
		gotPodUID, gotContainerID, err := extractor.GetPodUIDAndContainerID(123, log)
		require.NoError(t, err)
		assert.Equal(t, wantPodUID, gotPodUID)
		assert.Equal(t, wantContainerID, gotContainerID)
	}

	assertNotFound := func(t *testing.T, rootDir string) {
		extractor := Extractor{RootDir: rootDir}
		gotPodUID, gotContainerID, err := extractor.GetPodUIDAndContainerID(123, log)
		require.NoError(t, err)
		assert.Empty(t, gotPodUID)
		assert.Empty(t, gotContainerID)
	}

	assertErrorContains := func(t *testing.T, rootDir string, wantErr string) {
		extractor := Extractor{RootDir: rootDir}
		gotPodUID, gotContainerID, err := extractor.GetPodUIDAndContainerID(123, log)
		assert.ErrorContains(t, err, wantErr)
		assert.Empty(t, gotPodUID)
		assert.Empty(t, gotContainerID)
	}

	t.Run("extracts pod UID and container ID from the cgroup file", func(t *testing.T) {
		assertFound(t, "testdata/cgroup/pod-and-container", testPodUID, testContainerID)
	})

	t.Run("extracts container ID when the cgroup path has no pod UID", func(t *testing.T) {
		assertFound(t, "testdata/cgroup/container-only", "", testContainerID)
	})

	t.Run("no identifiers in the cgroup path", func(t *testing.T) {
		assertNotFound(t, "testdata/cgroup/no-identifiers")
	})

	t.Run("no cgroup file", func(t *testing.T) {
		assertNotFound(t, "testdata/does-not-exist")
	})

	t.Run("pod UID conflict across cgroup entries", func(t *testing.T) {
		assertErrorContains(t, "testdata/cgroup/pod-uid-conflict", "multiple pod UIDs found")
	})

	t.Run("container ID conflict across cgroup entries", func(t *testing.T) {
		assertErrorContains(t, "testdata/cgroup/container-id-conflict", "multiple container IDs found")
	})

	t.Run("entry without a pod UID does not override one that has it", func(t *testing.T) {
		assertFound(t, "testdata/cgroup/pod-uid-override", testPodUID, testContainerID)
	})

	t.Run("mountinfo is ignored", func(t *testing.T) {
		// The cgroup file carries no container ID and the mountinfo file has been
		// crafted to point at another workload's cgroup. mountinfo must not be
		// consulted, so no identity is returned.
		assertNotFound(t, "testdata/cgroup/mountinfo-ignored")
	})
}

func TestExtractContainerID(t *testing.T) {
	log := hclog.NewNullLogger()

	assertFound := func(t *testing.T, rootDir, wantContainerID string) {
		extractor := Extractor{RootDir: rootDir}
		gotContainerID, err := extractor.GetContainerID(123, log)
		require.NoError(t, err)
		assert.Equal(t, wantContainerID, gotContainerID)
	}

	assertNotFound := func(t *testing.T, rootDir string) {
		extractor := Extractor{RootDir: rootDir}
		gotContainerID, err := extractor.GetContainerID(123, log)
		require.NoError(t, err)
		assert.Empty(t, gotContainerID)
	}

	t.Run("extracts container ID from the cgroup file", func(t *testing.T) {
		assertFound(t, "testdata/cgroup/container-only", testContainerID)
	})

	t.Run("no identifiers in the cgroup path", func(t *testing.T) {
		assertNotFound(t, "testdata/cgroup/no-identifiers")
	})

	t.Run("no cgroup file", func(t *testing.T) {
		assertNotFound(t, "testdata/does-not-exist")
	})

	t.Run("mountinfo is ignored", func(t *testing.T) {
		assertNotFound(t, "testdata/cgroup/mountinfo-ignored")
	})
}
