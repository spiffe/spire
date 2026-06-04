//go:build !windows

package spireplugin

import (
	"errors"
	"net"

	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/common/util"
)

func (p *Plugin) getWorkloadAPIAddr() (net.Addr, error) {
	if p.config.Experimental.WorkloadAPINamedPipeName != "" {
		return nil, errors.New("configuration: workload_api_named_pipe_name is not supported in this platform; please use workload_api_socket instead")
	}
	if p.config.WorkloadAPISocket == "" {
		return nil, errors.New("configuration: workload_api_socket must be set")
	}
	return util.GetUnixAddrWithAbsPath(p.config.WorkloadAPISocket)
}

func validateConfig(c *Configuration, status *pluginconf.Status) {
	if c.Experimental.WorkloadAPINamedPipeName != "" {
		status.ReportError("configuration: workload_api_named_pipe_name is not supported in this platform; please use workload_api_socket instead")
	}
	if c.WorkloadAPISocket == "" {
		status.ReportError("configuration: workload_api_socket must be set")
	}
}
