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

	t.Run("cgroups v1", func(t *testing.T) {
		assertFound(t, "testdata/k8s/v1", testPodUID, testContainerID)
	})

	t.Run("cgroups v2", func(t *testing.T) {
		assertFound(t, "testdata/k8s/v2", testPodUID, testContainerID)
	})

	t.Run("no cgroup mount", func(t *testing.T) {
		assertNotFound(t, "testdata/k8s/no-cgroup-mount")
	})

	t.Run("cgroup mount does not match expected format", func(t *testing.T) {
		assertNotFound(t, "testdata/other/malformed")
	})

	t.Run("pod UID conflict", func(t *testing.T) {
		assertErrorContains(t, "testdata/k8s/pod-uid-conflict", "multiple pod UIDs found")
	})

	t.Run("ignore non-pod UID entry after pod UID found", func(t *testing.T) {
		assertFound(t, "testdata/k8s/pod-uid-override", testPodUID, testContainerID)
	})

	t.Run("container ID conflict", func(t *testing.T) {
		assertErrorContains(t, "testdata/k8s/container-id-conflict", "multiple container IDs found")
	})

	t.Run("neither cgroup nor mountinfo exist", func(t *testing.T) {
		assertNotFound(t, "testdata/does-not-exist")
	})

	t.Run("extracts from cgroup file", func(t *testing.T) {
		assertFound(t, "testdata/other/cgroup-primary", "", testContainerID)
	})

	t.Run("falls back to mountinfo", func(t *testing.T) {
		// The cgroup file exists but contains no identifiers, so the
		// information is extracted from mountinfo instead.
		assertFound(t, "testdata/other/mountinfo-fallback", testPodUID, testContainerID)
	})

	t.Run("cgroup takes priority over spoofed mountinfo", func(t *testing.T) {
		// A workload may bind-mount another workload's cgroup into its own
		// mount namespace so that mountinfo reports a different pod/container
		// than the kernel-assigned cgroup. The cgroup file cannot be forged,
		// so it must take priority.
		assertFound(t, "testdata/other/mountinfo-impersonation", "", testContainerID)
	})
}

func TestExtractContainerID(t *testing.T) {
	log := hclog.NewNullLogger()

	assertFound := func(t *testing.T, rootDir, wantContainerID string) {
		extractor := Extractor{RootDir: rootDir}
		gotContainerID, err := extractor.GetContainerID(123, log)
		assert.NoError(t, err)
		assert.Equal(t, wantContainerID, gotContainerID)
	}

	assertNotFound := func(t *testing.T, rootDir string) {
		extractor := Extractor{RootDir: rootDir}
		gotContainerID, err := extractor.GetContainerID(123, log)
		assert.NoError(t, err)
		assert.Empty(t, gotContainerID)
	}

	assertErrorContains := func(t *testing.T, rootDir string, wantErr string) {
		extractor := Extractor{RootDir: rootDir}
		gotPodUID, gotContainerID, err := extractor.GetPodUIDAndContainerID(123, log)
		assert.ErrorContains(t, err, wantErr)
		assert.Empty(t, gotPodUID)
		assert.Empty(t, gotContainerID)
	}

	t.Run("cgroups v1", func(t *testing.T) {
		assertFound(t, "testdata/docker/v1", testContainerID)
	})

	t.Run("cgroups v2", func(t *testing.T) {
		assertFound(t, "testdata/docker/v2", testContainerID)
	})

	t.Run("no cgroup mount", func(t *testing.T) {
		assertNotFound(t, "testdata/docker/no-cgroup-mount")
	})

	t.Run("cgroup mount does not match expected format", func(t *testing.T) {
		assertNotFound(t, "testdata/other/malformed")
	})

	t.Run("container ID conflict", func(t *testing.T) {
		assertErrorContains(t, "testdata/docker/container-id-conflict", "multiple container IDs found")
	})

	t.Run("neither cgroup nor mountinfo exist", func(t *testing.T) {
		assertNotFound(t, "testdata/does-not-exist")
	})

	t.Run("extracts from cgroup file", func(t *testing.T) {
		assertFound(t, "testdata/other/cgroup-primary", testContainerID)
	})

	t.Run("falls back to mountinfo", func(t *testing.T) {
		// The cgroup file exists but contains no identifiers, so the
		// information is extracted from mountinfo instead.
		assertFound(t, "testdata/other/mountinfo-fallback", testContainerID)
	})

	t.Run("cgroup takes priority over spoofed mountinfo", func(t *testing.T) {
		// A workload may bind-mount another workload's cgroup into its own
		// mount namespace so that mountinfo reports a different container
		// than the kernel-assigned cgroup. The cgroup file cannot be forged,
		// so it must take priority.
		assertFound(t, "testdata/other/mountinfo-impersonation", testContainerID)
	})

	t.Run("has multiple cgroup mounts on slash v1", func(t *testing.T) {
		assertFound(t, "testdata/docker/cgroup-mount-at-slash/v1", testContainerID)
	})

	t.Run("has multiple cgroup mounts on slash v2", func(t *testing.T) {
		assertFound(t, "testdata/docker/cgroup-mount-at-slash/v2", testContainerID)
	})

	t.Run("tolerates tmpfs mount with empty source", func(t *testing.T) {
		// Regression test for #7036: a tmpfs mount has no source, which renders
		// as an empty field in /proc/<pid>/mountinfo. The container ID must
		// still be extracted from the cgroup mount on the same file rather than
		// the whole file being rejected.
		assertFound(t, "testdata/docker/tmpfs-empty-source", testContainerID)
	})
}
