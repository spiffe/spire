package catalog

import (
	"os/exec"
	"syscall"
)

func pluginCmd(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	// This is insurance that a plugin process does not outlive SPIRE on linux.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}
	return cmd
}
