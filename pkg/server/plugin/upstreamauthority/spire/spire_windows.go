//go:build windows

package spireplugin

import (
	"errors"
	"net"

	"github.com/spiffe/spire/pkg/common/namedpipe"
	"github.com/spiffe/spire/pkg/common/pluginconf"
)

func validateWorkloadAPIConfig(config *Configuration, status *pluginconf.Status) {
	if config.WorkloadAPISocket != "" {
		status.ReportError("configuration: workload_api_socket is not supported on this platform; please use workload_api_named_pipe_name instead")
	}
	if config.Experimental.WorkloadAPINamedPipeName == "" {
		status.ReportError("workload_api_named_pipe_name is required")
	}
}

func (p *Plugin) getWorkloadAPIAddr() (net.Addr, error) {
	if p.config.WorkloadAPISocket != "" {
		return nil, errors.New("configuration: workload_api_socket is not supported on this platform; please use workload_api_named_pipe_name instead")
	}
	return namedpipe.AddrFromName(p.config.Experimental.WorkloadAPINamedPipeName), nil
}
