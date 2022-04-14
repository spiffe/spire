//go:build windows
// +build windows

package endpoints

import (
	"net"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
)

func getTestAddr(t *testing.T) net.Addr {
	return spiretest.GetRandNamedPipeAddr()
}
