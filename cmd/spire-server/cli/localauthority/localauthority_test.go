package localauthority_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/mitchellh/cli"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var (
	availableFormats = []string{"pretty", "json"}
)

type localAuthorityTest struct {
	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	args   []string
	server *fakeLocalAuthorityServer
	client cli.Command
}

func (s *localAuthorityTest) afterTest(t *testing.T) {
	t.Logf("TEST:%s", t.Name())
	t.Logf("STDOUT:\n%s", s.stdout.String())
	t.Logf("STDIN:\n%s", s.stdin.String())
	t.Logf("STDERR:\n%s", s.stderr.String())
}

func setupTest(t *testing.T, newClient func(*commoncli.Env) cli.Command) *localAuthorityTest {
	server := &fakeLocalAuthorityServer{}

	addr := spiretest.StartGRPCServer(t, func(s *grpc.Server) {
		localauthorityv1.RegisterLocalAuthorityServer(s, server)
	})

	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	client := newClient(&commoncli.Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	})

	test := &localAuthorityTest{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		args:   []string{common.AddrArg, common.GetAddr(addr)},
		server: server,
		client: client,
	}

	t.Cleanup(func() {
		test.afterTest(t)
	})

	return test
}

type fakeLocalAuthorityServer struct {
	localauthorityv1.UnsafeLocalAuthorityServer

	activeJWT,
	preparedJWT,
	oldJWT,
	activeX509,
	preparedX509,
	oldX509,
	taintedX509,
	revokedX509,
	taintedJWT,
	revokedJWT *localauthorityv1.AuthorityState

	err error
}

func (s *fakeLocalAuthorityServer) GetJWTAuthorityState(context.Context, *localauthorityv1.GetJWTAuthorityStateRequest) (*localauthorityv1.GetJWTAuthorityStateResponse, error) {
	return &localauthorityv1.GetJWTAuthorityStateResponse{
		Active:   s.activeJWT,
		Prepared: s.preparedJWT,
		Old:      s.oldJWT,
	}, s.err
}

func (s *fakeLocalAuthorityServer) PrepareJWTAuthority(context.Context, *localauthorityv1.PrepareJWTAuthorityRequest) (*localauthorityv1.PrepareJWTAuthorityResponse, error) {
	return &localauthorityv1.PrepareJWTAuthorityResponse{
		PreparedAuthority: s.preparedJWT,
	}, s.err
}

func (s *fakeLocalAuthorityServer) ActivateJWTAuthority(context.Context, *localauthorityv1.ActivateJWTAuthorityRequest) (*localauthorityv1.ActivateJWTAuthorityResponse, error) {
	return &localauthorityv1.ActivateJWTAuthorityResponse{
		ActivatedAuthority: s.activeJWT,
	}, s.err
}

func (s *fakeLocalAuthorityServer) TaintJWTAuthority(context.Context, *localauthorityv1.TaintJWTAuthorityRequest) (*localauthorityv1.TaintJWTAuthorityResponse, error) {
	return &localauthorityv1.TaintJWTAuthorityResponse{
		TaintedAuthority: s.taintedJWT,
	}, s.err
}

func (s *fakeLocalAuthorityServer) RevokeJWTAuthority(context.Context, *localauthorityv1.RevokeJWTAuthorityRequest) (*localauthorityv1.RevokeJWTAuthorityResponse, error) {
	return &localauthorityv1.RevokeJWTAuthorityResponse{
		RevokedAuthority: s.revokedJWT,
	}, s.err
}

func (s *fakeLocalAuthorityServer) GetX509AuthorityState(context.Context, *localauthorityv1.GetX509AuthorityStateRequest) (*localauthorityv1.GetX509AuthorityStateResponse, error) {
	return &localauthorityv1.GetX509AuthorityStateResponse{
		Active:   s.activeX509,
		Prepared: s.preparedX509,
		Old:      s.oldX509,
	}, s.err
}

func (s *fakeLocalAuthorityServer) PrepareX509Authority(context.Context, *localauthorityv1.PrepareX509AuthorityRequest) (*localauthorityv1.PrepareX509AuthorityResponse, error) {
	return &localauthorityv1.PrepareX509AuthorityResponse{
		PreparedAuthority: s.preparedX509,
	}, s.err
}

func (s *fakeLocalAuthorityServer) ActivateX509Authority(context.Context, *localauthorityv1.ActivateX509AuthorityRequest) (*localauthorityv1.ActivateX509AuthorityResponse, error) {
	return &localauthorityv1.ActivateX509AuthorityResponse{
		ActivatedAuthority: s.activeX509,
	}, s.err
}

func (s *fakeLocalAuthorityServer) TaintX509Authority(context.Context, *localauthorityv1.TaintX509AuthorityRequest) (*localauthorityv1.TaintX509AuthorityResponse, error) {
	return &localauthorityv1.TaintX509AuthorityResponse{
		TaintedAuthority: s.taintedX509,
	}, s.err
}

func (s *fakeLocalAuthorityServer) TaintX509UpstreamAuthority(context.Context, *localauthorityv1.TaintX509UpstreamAuthorityRequest) (*localauthorityv1.TaintX509UpstreamAuthorityResponse, error) {
	return &localauthorityv1.TaintX509UpstreamAuthorityResponse{}, s.err
}

func (s *fakeLocalAuthorityServer) RevokeX509Authority(context.Context, *localauthorityv1.RevokeX509AuthorityRequest) (*localauthorityv1.RevokeX509AuthorityResponse, error) {
	return &localauthorityv1.RevokeX509AuthorityResponse{
		RevokedAuthority: s.revokedX509,
	}, s.err
}

func (s *fakeLocalAuthorityServer) RevokeX509UpstreamAuthority(context.Context, *localauthorityv1.RevokeX509UpstreamAuthorityRequest) (*localauthorityv1.RevokeX509UpstreamAuthorityResponse, error) {
	return &localauthorityv1.RevokeX509UpstreamAuthorityResponse{}, s.err
}

func requireOutputBasedOnFormat(t *testing.T, format, stdoutString string, expectedStdoutPretty, expectedStdoutJSON string) {
	switch format {
	case "pretty":
		require.Contains(t, stdoutString, expectedStdoutPretty)
	case "json":
		if expectedStdoutJSON != "" {
			require.JSONEq(t, expectedStdoutJSON, stdoutString)
		} else {
			require.Empty(t, stdoutString)
		}
	}
}
