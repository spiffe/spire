//go:build windows
// +build windows

package peertracker

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const (
	childSource = "peertracker_test_child_windows.go"
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

	process, err := os.FindProcess(f.grandchildPID)
	if err != nil {
		f.t.Fatalf("unable to find process: %v", err)
	}
	if err = process.Kill(); err != nil {
		f.t.Fatalf("unable to kill grandchild: %v", err)
	}

	// Wait for the process to exit, so we are sure that we can
	// cleanup the directory containing the executable
	if _, err := process.Wait(); err != nil {
		f.t.Fatalf("wait failed: %v", err)
	}
	f.grandchildPID = 0
}

func addr(t *testing.T) net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func listener(t *testing.T, log *logrus.Logger, addr net.Addr) *Listener {
	listener, err := (&ListenerFactory{Log: log}).ListenTCP(addr.Network(), addr.(*net.TCPAddr))
	require.NoError(t, err)

	return listener
}

func childExecCommand(t *testing.T, childPath string, addr net.Addr) *exec.Cmd {
	// #nosec G204 test code
	return exec.Command(childPath,
		"-tcpSocketPort",
		strconv.Itoa(addr.(*net.TCPAddr).Port),
		"-protocolInfoFile",
		filepath.Join(filepath.Dir(childPath), "wsaprotocolinfo"))
}
