//go:build windows

package spireplugin

import (
	"errors"
	"net"

	"github.com/spiffe/spire/pkg/common/namedpipe"
	"github.com/spiffe/spire/pkg/common/pluginconf"
)

func (p *Plugin) getWorkloadAPIAddr() (net.Addr, error) {
	if p.config.WorkloadAPISocket != "" {
		return nil, errors.New("configuration: workload_api_socket is not supported in this platform; please use workload_api_named_pipe_name instead")
	}
	if p.config.Experimental.WorkloadAPINamedPipeName == "" {
		return nil, errors.New("configuration: workload_api_named_pipe_name must be set")
	}
	return namedpipe.AddrFromName(p.config.Experimental.WorkloadAPINamedPipeName), nil
}

func validateConfig(c *Configuration, status *pluginconf.Status) {
	if c.WorkloadAPISocket != "" {
		status.ReportError("configuration: workload_api_socket is not supported in this platform; please use workload_api_named_pipe_name instead")
	}
	if c.Experimental.WorkloadAPINamedPipeName == "" {
		status.ReportError("configuration: workload_api_named_pipe_name must be set")
	}
}
