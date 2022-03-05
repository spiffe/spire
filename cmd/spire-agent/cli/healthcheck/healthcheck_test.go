package healthcheck

import (
	"bytes"
	"context"
	"testing"

	"github.com/mitchellh/cli"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/health/grpc_health_v1"
)

type healthCheckTest struct {
	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer

	cmd cli.Command
}

func setupTest() *healthCheckTest {
	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	return &healthCheckTest{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		cmd: newHealthCheckCommand(&common_cli.Env{
			Stdin:  stdin,
			Stdout: stdout,
			Stderr: stderr,
		}),
	}
}

func TestSynopsis(t *testing.T) {
	test := setupTest()
	require.Equal(t, "Determines agent health status", test.cmd.Synopsis())
}

func withStatus(status grpc_health_v1.HealthCheckResponse_ServingStatus) healthServer {
	return healthServer{status: status}
}

type healthServer struct {
	grpc_health_v1.UnimplementedHealthServer
	status grpc_health_v1.HealthCheckResponse_ServingStatus
	err    error
}

func (s healthServer) Check(context.Context, *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &grpc_health_v1.HealthCheckResponse{
		Status: s.status,
	}, nil
}
