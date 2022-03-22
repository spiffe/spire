//go:build windows
// +build windows

package docker

import (
	hclog "github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker/process"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func createHelper(c *dockerPluginConfig) (*containerHelper, error) {
	return &containerHelper{
		ph: process.CreateHelper(),
	}, nil
}

type containerHelper struct {
	ph process.Helper
}

func (h *containerHelper) getContainerID(pID int32, log hclog.Logger) (string, error) {
	containerID, err := h.ph.GetContainerIDByProcess(pID, log)
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to get container ID: %v", err)
	}
	return containerID, nil
}

func validateOS(c *dockerPluginConfig) error {
	if c.DockerSocketPath != "" {
		return status.Error(codes.InvalidArgument, "invalid configuration: docker_socket_path is not supported in this platform; please use docker_host instead")
	}

	if len(c.ContainerIDCGroupMatchers) > 0 {
		return status.Error(codes.InvalidArgument, "invalid configuration: container_id_cgroup_matchers is not supported in this platform")
	}

	return nil
}

func getDockerHost(c *dockerPluginConfig) string {
	return c.DockerHost
}
