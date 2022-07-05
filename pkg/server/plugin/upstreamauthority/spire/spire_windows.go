//go:build windows
// +build windows

package spireplugin

import (
	"errors"
	"net"

	"github.com/spiffe/spire/pkg/common/util"
)

func (p *Plugin) getWorkloadAPIAddr() (net.Addr, error) {
	if p.config.WorkloadAPISocket != "" {
		return nil, errors.New("configuration: workload_api_socket is not supported in this platform; please use workload_api_named_pipe_name instead")
	}
	return util.GetNamedPipeAddr(p.config.Experimental.WorkloadAPINamedPipeName), nil
}
