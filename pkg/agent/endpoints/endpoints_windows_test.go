//go:build windows

package endpoints

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func getTestAddr(*testing.T) net.Addr {
	return spiretest.GetRandNamedPipeAddr()
}

func testRemoteCaller(t *testing.T, target string) {
	hostName, err := os.Hostname()
	require.NoError(t, err)

	// Use the host name instead of "." in the target, as it would be a remote caller
	targetAsRemote := strings.ReplaceAll(target, "\\\\.\\", fmt.Sprintf("\\\\%s\\", hostName))
	_, err = util.NewGRPCClient(targetAsRemote)

	// Remote calls must be denied
	require.ErrorIs(t, err, windows.ERROR_ACCESS_DENIED)
}
