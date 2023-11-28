//go:build !windows

package peertracker

import (
	"net"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
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

	err := unix.Kill(f.grandchildPID, unix.SIGKILL)
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

func childExecCommand(childPath string, addr net.Addr) *exec.Cmd {
	// #nosec G204 test code
	return exec.Command(childPath, "-socketPath", addr.(*net.UnixAddr).Name)
}

func dial(addr net.Addr) (net.Conn, error) {
	return net.Dial(addr.Network(), addr.String())
}
