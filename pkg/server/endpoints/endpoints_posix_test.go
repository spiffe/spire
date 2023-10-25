//go:build !windows

package endpoints

import (
	"net"
	"path/filepath"
	"testing"

	"context"
	"github.com/spiffe/spire/test/spiretest"
)

func getLocalAddr(t *testing.T) net.Addr {
	tempdir := spiretest.TempDir(t)
	return &net.UnixAddr{Net: "unix", Name: filepath.Join(tempdir, "sockets")}
}

func testRemoteCaller(context.Context, *testing.T, string) {
	// No testing for UDS endpoints
}
