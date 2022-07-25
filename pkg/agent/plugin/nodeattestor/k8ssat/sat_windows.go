//go:build windows
// +build windows

package k8ssat

import (
	"os"
	"path/filepath"
)

const (
	containerMountPointEnvVar = "CONTAINER_SANDBOX_MOUNT_POINT"
)

func getDefaultTokenPath() string {
	mountPoint := os.Getenv(containerMountPointEnvVar)
	if mountPoint == "" {
		return filepath.FromSlash(defaultTokenPath)
	}
	return filepath.Join(mountPoint, defaultTokenPath)
}
