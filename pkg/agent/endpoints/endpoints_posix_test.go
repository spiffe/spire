//go:build !windows

package endpoints

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
)

func getTestAddr(t *testing.T) net.Addr {
	return &net.UnixAddr{
		Net:  "unix",
		Name: filepath.Join(spiretest.TempDir(t), "agent.sock"),
	}
}

func testRemoteCaller(context.Context, *testing.T, string) {
	// No testing for UDS endpoints
}
