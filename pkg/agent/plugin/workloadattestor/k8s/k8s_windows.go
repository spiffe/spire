//go:build windows

package k8s

import (
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/container/process"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"
)

const (
	containerMountPointEnvVar = "CONTAINER_SANDBOX_MOUNT_POINT"
)

func createHelper(*Plugin) ContainerHelper {
	return &containerHelper{
		ph: process.CreateHelper(),
	}
}

type containerHelper struct {
	ph process.Helper
}

func (h *containerHelper) Configure(_ *HCLConfig, _ hclog.Logger) error {
	return nil
}

func (h *containerHelper) GetPodUIDAndContainerID(pID int32, log hclog.Logger) (types.UID, string, error) {
	containerID, err := h.ph.GetContainerIDByProcess(pID, log)
	if err != nil {
		return types.UID(""), "", status.Errorf(codes.Internal, "failed to get container ID: %v", err)
	}

	return types.UID(""), containerID, nil
}

func (p *Plugin) defaultKubeletCAPath() string {
	mountPoint := p.getenv(containerMountPointEnvVar)
	return filepath.Join(mountPoint, defaultKubeletCAPath)
}

func (p *Plugin) defaultTokenPath() string {
	mountPoint := p.getenv(containerMountPointEnvVar)
	return filepath.Join(mountPoint, defaultTokenPath)
}
