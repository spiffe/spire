//go:build windows

package k8s

import (
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/container/process"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
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

func (h *containerHelper) GetPodUIDAndContainerID(ref *anypb.Any, log hclog.Logger) (types.UID, string, bool, error) {
	_, pid, err := extractRelevantReference(ref)
	if err != nil {
		return "", "", false, status.Errorf(codes.Internal, "failed to extract relevant reference: %v", err)
	}

	containerID, err := h.ph.GetContainerIDByProcess(pid, log)
	if err != nil {
		return types.UID(""), "", false, status.Errorf(codes.Internal, "failed to get container ID: %v", err)
	}

	return types.UID(""), containerID, true, nil
}

func (p *Plugin) defaultKubeletCAPath() string {
	mountPoint := p.getenv(containerMountPointEnvVar)
	return filepath.Join(mountPoint, defaultKubeletCAPath)
}

func (p *Plugin) defaultTokenPath() string {
	mountPoint := p.getenv(containerMountPointEnvVar)
	return filepath.Join(mountPoint, defaultTokenPath)
}
