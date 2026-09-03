//go:build windows

package trustbundlesources

import (
	"os"
	"path/filepath"
)

const (
	containerMountPointEnvVar = "CONTAINER_SANDBOX_MOUNT_POINT"
)

func getServiceAccountNamespacePath() string {
	mountPoint := os.Getenv(containerMountPointEnvVar)
	if mountPoint == "" {
		return filepath.FromSlash(serviceAccountNamespacePath)
	}
	return filepath.Join(mountPoint, filepath.FromSlash(serviceAccountNamespacePath[1:]))
}
