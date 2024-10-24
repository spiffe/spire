//go:build windows

package peertracker

import (
	"net"
	"os"
	"os/exec"
	"testing"

	"github.com/Microsoft/go-winio"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/test/spiretest"
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
	// clean up the directory containing the executable
	if _, err := process.Wait(); err != nil {
		f.t.Fatalf("wait failed: %v", err)
	}
	f.grandchildPID = 0
}

func addr(*testing.T) net.Addr {
	return spiretest.GetRandNamedPipeAddr()
}

func listener(t *testing.T, log *logrus.Logger, addr net.Addr) *Listener {
	listener, err := (&ListenerFactory{Log: log}).ListenPipe(addr.String(), nil)
	require.NoError(t, err)

	return listener
}

func childExecCommand(childPath string, addr net.Addr) *exec.Cmd {
	// #nosec G204 test code
	return exec.Command(childPath, "-namedPipeName", addr.String())
}

func dial(addr net.Addr) (net.Conn, error) {
	return winio.DialPipe(addr.String(), nil)
}
