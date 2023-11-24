package catalog

import (
	"os/exec"

	"golang.org/x/sys/unix"
)

func pluginCmd(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	// This is insurance that a plugin process does not outlive SPIRE on linux.
	cmd.SysProcAttr = &unix.SysProcAttr{
		Pdeathsig: unix.SIGKILL,
	}
	return cmd
}
