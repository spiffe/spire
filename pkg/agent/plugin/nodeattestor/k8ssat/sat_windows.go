//go:build windows
// +build windows

package sat

import (
	"os"
	"path"
)

const (
	containerMountPoint = "CONTAINER_SANDBOX_MOUNT_POINT"
)

func getDefaultTokenPath() string {
	mountPoint := os.Getenv(containerMountPoint)
	if mountPoint == "" {
		return defaultTokenPath
	}
	return path.Join(mountPoint, defaultTokenPath)
}
