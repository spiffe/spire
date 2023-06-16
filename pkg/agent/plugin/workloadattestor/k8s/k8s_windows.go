//go:build windows
// +build windows

package k8s

import (
	"context"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/container/process"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
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

func (h *containerHelper) Configure(config *HCLConfig, _ hclog.Logger) error {
	if config.Experimental != nil && config.Experimental.Sigstore != nil {
		return status.Error(codes.InvalidArgument, "sigstore configuration is not supported on windows environment")
	}
	return nil
}

func (h *containerHelper) GetOSSelectors(context.Context, hclog.Logger, *corev1.ContainerStatus) ([]string, error) {
	// No additional selectors on windows
	return nil, nil
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
