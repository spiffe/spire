//go:build !windows

package endpoints

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
)

func getLocalAddr(t *testing.T) net.Addr {
	tempdir := spiretest.TempDir(t)
	return &net.UnixAddr{Net: "unix", Name: filepath.Join(tempdir, "sockets")}
}

func testRemoteCaller(context.Context, *testing.T, string) {
	// No testing for UDS endpoints
}
