//go:build !windows
// +build !windows

package peertracker

import (
	"net"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const (
	childSource = "peertracker_test_child_posix.go"
)

func addr(t *testing.T) net.Addr {
	return &net.UnixAddr{
		Net:  "unix",
		Name: filepath.Join(t.TempDir(), "test.sock"),
	}
}

func listener(t *testing.T, log *logrus.Logger, addr net.Addr) *Listener {
	listener, err := (&ListenerFactory{Log: log}).ListenUnix(addr.Network(), addr.(*net.UnixAddr))
	require.NoError(t, err)

	return listener
}

func childExecCommand(t *testing.T, childPath string, addr net.Addr) *exec.Cmd {
	return exec.Command(childPath, "-socketPath", addr.(*net.UnixAddr).Name)
}

func (f *fakePeer) killGrandchild() {
	if f.grandchildPID == 0 {
		f.t.Fatal("no known grandchild")
	}

	err := syscall.Kill(f.grandchildPID, syscall.SIGKILL)
	if err != nil {
		f.t.Fatalf("unable to kill grandchild: %v", err)
	}

	f.grandchildPID = 0
}
