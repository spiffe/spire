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

type fakePeer struct {
	grandchildPID int
	conn          net.Conn
	t             *testing.T
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
	// #nosec G204 test code
	return exec.Command(childPath, "-socketPath", addr.(*net.UnixAddr).Name)
}

func dial(addr net.Addr) (net.Conn, error) {
	return net.Dial(addr.Network(), addr.String())
}
