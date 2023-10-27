//go:build !windows

package spireplugin

import (
	"errors"
	"net"

	"github.com/spiffe/spire/pkg/common/util"
)

func (p *Plugin) getWorkloadAPIAddr() (net.Addr, error) {
	if p.config.Experimental.WorkloadAPINamedPipeName != "" {
		return nil, errors.New("configuration: workload_api_named_pipe_name is not supported in this platform; please use workload_api_socket instead")
	}
	return util.GetUnixAddrWithAbsPath(p.config.WorkloadAPISocket)
}
