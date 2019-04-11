// +build !linux

package catalog

import (
	"os/exec"
)

func pluginCmd(name string, arg ...string) *exec.Cmd {
	return exec.Command(name, arg...)
}
