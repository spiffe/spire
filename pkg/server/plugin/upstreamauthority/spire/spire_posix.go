//go:build !windows

package spireplugin

import (
	"errors"
	"net"

	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/common/util"
)

func validateWorkloadAPIConfig(config *Configuration, status *pluginconf.Status) {
	if config.Experimental.WorkloadAPINamedPipeName != "" {
		status.ReportError("configuration: workload_api_named_pipe_name is not supported on this platform; please use workload_api_socket instead")
	}
	if config.WorkloadAPISocket == "" {
		status.ReportError("workload_api_socket is required")
	}
}

func (p *Plugin) getWorkloadAPIAddr() (net.Addr, error) {
	if p.config.Experimental.WorkloadAPINamedPipeName != "" {
		return nil, errors.New("configuration: workload_api_named_pipe_name is not supported on this platform; please use workload_api_socket instead")
	}
	return util.GetUnixAddrWithAbsPath(p.config.WorkloadAPISocket)
}
