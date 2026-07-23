package debug

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/mitchellh/cli"
	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/debug/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type debugTest struct {
	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer

	cmd cli.Command
}

func setupTest() *debugTest {
	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	cmd := newGetInfoCommand(&commoncli.Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	})

	return &debugTest{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		cmd:    cmd,
	}
}

func TestSynopsis(t *testing.T) {
	test := setupTest()
	require.Equal(t, "Prints debug information about the agent", test.cmd.Synopsis())
}

func TestHelp(t *testing.T) {
	test := setupTest()
	require.Empty(t, test.cmd.Help())
	require.Equal(t, usage, test.stderr.String())
}

func TestBadFlags(t *testing.T) {
	test := setupTest()

	code := test.cmd.Run([]string{"-badflag"})
	require.NotEqual(t, 0, code)
	require.Empty(t, test.stdout.String(), "stdout")
	require.Equal(t, "flag provided but not defined: -badflag\n"+usage, test.stderr.String(), "stderr")
}

func TestFailsOnUnavailable(t *testing.T) {
	test := setupTest()

	code := test.cmd.Run([]string{socketAddrArg, socketAddrUnavailable})
	require.NotEqual(t, 0, code)
	require.Empty(t, test.stdout.String(), "stdout")
	require.Contains(t, test.stderr.String(), "Error:")
}

func TestGetInfo(t *testing.T) {
	now := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	lastSync := now.Add(-30 * time.Second)

	fakeResp := &debugv1.GetInfoResponse{
		Uptime:                        42,
		LastSyncSuccess:               lastSync.Unix(),
		CachedX509SvidsCount:          3,
		CachedJwtSvidsCount:           1,
		CachedSvidstoreX509SvidsCount: 0,
		SvidChain: []*debugv1.GetInfoResponse_Cert{
			{
				Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/foo"},
				ExpiresAt: now.Add(24 * time.Hour).Unix(),
				Subject:   "CN=agent",
			},
		},
	}

	socketAddr := startGRPCSocketServer(t, func(srv *grpc.Server) {
		debugv1.RegisterDebugServer(srv, &fakeDebugServer{resp: fakeResp})
	})

	test := setupTest()
	code := test.cmd.Run([]string{socketAddrArg, socketAddr})
	require.Equal(t, 0, code, "exit code; stderr: %s", test.stderr.String())
	require.Empty(t, test.stderr.String(), "stderr")

	out := test.stdout.String()
	require.Contains(t, out, "Agent Debug Info:")
	require.Contains(t, out, "42s")
	require.Contains(t, out, "Cached X.509 SVIDs:")
	require.Contains(t, out, "3")
	require.Contains(t, out, "spiffe://example.org/spire/agent/foo")
}

func TestGetInfoJSON(t *testing.T) {
	fakeResp := &debugv1.GetInfoResponse{
		Uptime:               10,
		LastSyncSuccess:      1705320000,
		CachedX509SvidsCount: 2,
	}

	socketAddr := startGRPCSocketServer(t, func(srv *grpc.Server) {
		debugv1.RegisterDebugServer(srv, &fakeDebugServer{resp: fakeResp})
	})

	test := setupTest()
	code := test.cmd.Run([]string{socketAddrArg, socketAddr, "-output", "json"})
	require.Equal(t, 0, code, "exit code; stderr: %s", test.stderr.String())
	require.Empty(t, test.stderr.String(), "stderr")

	out := test.stdout.String()
	require.Contains(t, out, `"uptime"`)
	require.Contains(t, out, `"cached_x509_svids_count"`)
}

type fakeDebugServer struct {
	debugv1.UnimplementedDebugServer
	resp *debugv1.GetInfoResponse
}

func (s *fakeDebugServer) GetInfo(_ context.Context, _ *debugv1.GetInfoRequest) (*debugv1.GetInfoResponse, error) {
	return s.resp, nil
}
