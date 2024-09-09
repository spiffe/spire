//go:build windows

package docker

import (
	hclog "github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/container/process"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type OSConfig struct {
	// DockerHost is the location of the Docker Engine API endpoint on Windows (default: "npipe:////./pipe/docker_engine").
	DockerHost string `hcl:"docker_host" json:"docker_host"`
}

func (p *Plugin) createHelper(*dockerPluginConfig, *pluginconf.Status) *containerHelper {
	return &containerHelper{
		ph: process.CreateHelper(),
	}
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

func getDockerHost(c *dockerPluginConfig) string {
	return c.DockerHost
}
