package authoritycommontest

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
	AvailableFormats = []string{"pretty", "json"}
)

type localAuthorityTest struct {
	Stdin  *bytes.Buffer
	Stdout *bytes.Buffer
	Stderr *bytes.Buffer
	Args   []string
	Server *fakeLocalAuthorityServer
	Client cli.Command
}

func (s *localAuthorityTest) afterTest(t *testing.T) {
	t.Logf("TEST:%s", t.Name())
	t.Logf("STDOUT:\n%s", s.Stdout.String())
	t.Logf("STDIN:\n%s", s.Stdin.String())
	t.Logf("STDERR:\n%s", s.Stderr.String())
}

func SetupTest(t *testing.T, newClient func(*commoncli.Env) cli.Command) *localAuthorityTest {
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
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		Args:   []string{common.AddrArg, common.GetAddr(addr)},
		Server: server,
		Client: client,
	}

	t.Cleanup(func() {
		test.afterTest(t)
	})

	return test
}

type fakeLocalAuthorityServer struct {
	localauthorityv1.UnsafeLocalAuthorityServer

	ActiveJWT,
	PreparedJWT,
	OldJWT,
	ActiveX509,
	PreparedX509,
	OldX509,
	TaintedX509,
	RevokedX509,
	TaintedJWT,
	RevokedJWT *localauthorityv1.AuthorityState

	TaintedUpstreamAuthoritySubjectKeyId,
	RevokedUpstreamAuthoritySubjectKeyId string
	Err error
}

func (s *fakeLocalAuthorityServer) GetJWTAuthorityState(context.Context, *localauthorityv1.GetJWTAuthorityStateRequest) (*localauthorityv1.GetJWTAuthorityStateResponse, error) {
	return &localauthorityv1.GetJWTAuthorityStateResponse{
		Active:   s.ActiveJWT,
		Prepared: s.PreparedJWT,
		Old:      s.OldJWT,
	}, s.Err
}

func (s *fakeLocalAuthorityServer) PrepareJWTAuthority(context.Context, *localauthorityv1.PrepareJWTAuthorityRequest) (*localauthorityv1.PrepareJWTAuthorityResponse, error) {
	return &localauthorityv1.PrepareJWTAuthorityResponse{
		PreparedAuthority: s.PreparedJWT,
	}, s.Err
}

func (s *fakeLocalAuthorityServer) ActivateJWTAuthority(context.Context, *localauthorityv1.ActivateJWTAuthorityRequest) (*localauthorityv1.ActivateJWTAuthorityResponse, error) {
	return &localauthorityv1.ActivateJWTAuthorityResponse{
		ActivatedAuthority: s.ActiveJWT,
	}, s.Err
}

func (s *fakeLocalAuthorityServer) TaintJWTAuthority(context.Context, *localauthorityv1.TaintJWTAuthorityRequest) (*localauthorityv1.TaintJWTAuthorityResponse, error) {
	return &localauthorityv1.TaintJWTAuthorityResponse{
		TaintedAuthority: s.TaintedJWT,
	}, s.Err
}

func (s *fakeLocalAuthorityServer) RevokeJWTAuthority(context.Context, *localauthorityv1.RevokeJWTAuthorityRequest) (*localauthorityv1.RevokeJWTAuthorityResponse, error) {
	return &localauthorityv1.RevokeJWTAuthorityResponse{
		RevokedAuthority: s.RevokedJWT,
	}, s.Err
}

func (s *fakeLocalAuthorityServer) GetX509AuthorityState(context.Context, *localauthorityv1.GetX509AuthorityStateRequest) (*localauthorityv1.GetX509AuthorityStateResponse, error) {
	return &localauthorityv1.GetX509AuthorityStateResponse{
		Active:   s.ActiveX509,
		Prepared: s.PreparedX509,
		Old:      s.OldX509,
	}, s.Err
}

func (s *fakeLocalAuthorityServer) PrepareX509Authority(context.Context, *localauthorityv1.PrepareX509AuthorityRequest) (*localauthorityv1.PrepareX509AuthorityResponse, error) {
	return &localauthorityv1.PrepareX509AuthorityResponse{
		PreparedAuthority: s.PreparedX509,
	}, s.Err
}

func (s *fakeLocalAuthorityServer) ActivateX509Authority(context.Context, *localauthorityv1.ActivateX509AuthorityRequest) (*localauthorityv1.ActivateX509AuthorityResponse, error) {
	return &localauthorityv1.ActivateX509AuthorityResponse{
		ActivatedAuthority: s.ActiveX509,
	}, s.Err
}

func (s *fakeLocalAuthorityServer) TaintX509Authority(context.Context, *localauthorityv1.TaintX509AuthorityRequest) (*localauthorityv1.TaintX509AuthorityResponse, error) {
	return &localauthorityv1.TaintX509AuthorityResponse{
		TaintedAuthority: s.TaintedX509,
	}, s.Err
}

func (s *fakeLocalAuthorityServer) TaintX509UpstreamAuthority(context.Context, *localauthorityv1.TaintX509UpstreamAuthorityRequest) (*localauthorityv1.TaintX509UpstreamAuthorityResponse, error) {
	return &localauthorityv1.TaintX509UpstreamAuthorityResponse{
		UpstreamAuthoritySubjectKeyId: s.TaintedUpstreamAuthoritySubjectKeyId,
	}, s.Err
}

func (s *fakeLocalAuthorityServer) RevokeX509Authority(context.Context, *localauthorityv1.RevokeX509AuthorityRequest) (*localauthorityv1.RevokeX509AuthorityResponse, error) {
	return &localauthorityv1.RevokeX509AuthorityResponse{
		RevokedAuthority: s.RevokedX509,
	}, s.Err
}

func (s *fakeLocalAuthorityServer) RevokeX509UpstreamAuthority(context.Context, *localauthorityv1.RevokeX509UpstreamAuthorityRequest) (*localauthorityv1.RevokeX509UpstreamAuthorityResponse, error) {
	return &localauthorityv1.RevokeX509UpstreamAuthorityResponse{
		UpstreamAuthoritySubjectKeyId: s.RevokedUpstreamAuthoritySubjectKeyId,
	}, s.Err
}

func RequireOutputBasedOnFormat(t *testing.T, format, stdoutString string, expectedStdoutPretty, expectedStdoutJSON string) {
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
