//go:build windows

package run

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"unsafe"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/common/namedpipe"
	"golang.org/x/sys/windows"
)

var (
	// We can't use the AdjustTokenPrivileges function from x/sys/windows because
	// it currently does not handle the ERROR_NOT_ALL_ASSIGNED error. Based on testing
	// it seems to return a nil error even if fails to adjust the privileges.
	procAdjustTokenPrivileges = windows.NewLazySystemDLL("advapi32.dll").NewProc("AdjustTokenPrivileges")
)

func (c *agentConfig) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.Experimental.NamedPipeName, "namedPipeName", "", "Pipe name to bind the SPIRE Agent API named pipe")
}

func (c *agentConfig) setPlatformDefaults() {
	c.Experimental.NamedPipeName = common.DefaultNamedPipeName
}

func (c *agentConfig) getAddr() (net.Addr, error) {
	return namedpipe.AddrFromName(c.Experimental.NamedPipeName), nil
}

func (c *agentConfig) getAdminAddr() (net.Addr, error) {
	return namedpipe.AddrFromName(c.Experimental.AdminNamedPipeName), nil
}

func (c *agentConfig) hasAdminAddr() bool {
	return c.Experimental.AdminNamedPipeName != ""
}

// brokerSocketAddr resolves the UDS branch of broker bind-address selection.
// Windows does not support UDS for the broker endpoint; configure
// `experimental.broker.bind_address` (TCP) instead.
func (c *agentConfig) brokerSocketAddr() (net.Addr, error) {
	return nil, errors.New("experimental.broker.socket_path is not supported on this platform; use experimental.broker.bind_address (TCP) instead")
}

// validateOS performs windows specific validations of the agent config
func (c *agentConfig) validateOS() error {
	if c.SocketPath != "" {
		return errors.New("invalid configuration: socket_path is not supported in this platform; please use named_pipe_name instead")
	}
	if c.AdminSocketPath != "" {
		return errors.New("invalid configuration: admin_socket_path is not supported in this platform; please use admin_named_pipe_name instead")
	}
	return nil
}

func prepareEndpoints(c *agent.Config) error {
	if err := enableSeDebugPrivilege(); err != nil {
		c.Log.WithError(err).Warn("Could not enable SeDebugPrivilege; workload attestation of processes running as more privileged users may fail")
	} else {
		c.Log.Info("Enabled SeDebugPrivilege")
	}
	return nil
}

func enableSeDebugPrivilege() error {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("failed to open process token: %w", err)
	}
	defer token.Close()

	var luid windows.LUID
	seDebug, err := windows.UTF16PtrFromString("SeDebugPrivilege")
	if err != nil {
		return fmt.Errorf("failed to encode privilege name: %w", err)
	}
	err = windows.LookupPrivilegeValue(nil, seDebug, &luid)
	if err != nil {
		return fmt.Errorf("failed to look up SeDebugPrivilege: %w", err)
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}

	result, _, err := procAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if result == 0 {
		return fmt.Errorf("AdjustTokenPrivileges failed: %w", err)
	}
	if errors.Is(err, windows.ERROR_NOT_ALL_ASSIGNED) {
		return errors.New("SeDebugPrivilege is not held by this token")
	}
	return nil
}
