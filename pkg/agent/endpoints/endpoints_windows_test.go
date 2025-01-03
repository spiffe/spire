//go:build windows

package endpoints

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func getTestAddr(*testing.T) net.Addr {
	return spiretest.GetRandNamedPipeAddr()
}

func testRemoteCaller(t *testing.T, target string) {
	hostName, err := os.Hostname()
	require.NoError(t, err)

	// Use the host name instead of "." in the target, as it would be a remote caller
	targetAsRemote := strings.ReplaceAll(target, "\\\\.\\", fmt.Sprintf("\\\\%s\\", hostName))
	conn, err := util.NewGRPCClient(targetAsRemote)
	require.NoError(t, err)

	healthClient := grpc_health_v1.NewHealthClient(conn)
	_, err = healthClient.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})

	// Remote calls must be denied
	require.ErrorContains(t, err, windows.ERROR_ACCESS_DENIED.Error())
}
