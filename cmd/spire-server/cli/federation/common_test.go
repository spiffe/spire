package federation

import (
	"bytes"
	"context"
	"testing"

	"github.com/mitchellh/cli"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc"
)

type cmdTest struct {
	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer

	args   []string
	server *fakeServer

	client cli.Command
}

func (e *cmdTest) afterTest(t *testing.T) {
	t.Logf("TEST:%s", t.Name())
	t.Logf("STDOUT:\n%s", e.stdout.String())
	t.Logf("STDIN:\n%s", e.stdin.String())
	t.Logf("STDERR:\n%s", e.stderr.String())
}

type fakeServer struct {
	trustdomainv1.UnimplementedTrustDomainServer

	t   *testing.T
	err error

	expectCreateReq *trustdomainv1.BatchCreateFederationRelationshipRequest
	expectDeleteReq *trustdomainv1.BatchDeleteFederationRelationshipRequest
	expectListReq   *trustdomainv1.ListFederationRelationshipsRequest

	createResp *trustdomainv1.BatchCreateFederationRelationshipResponse
	deleteResp *trustdomainv1.BatchDeleteFederationRelationshipResponse
	listResp   *trustdomainv1.ListFederationRelationshipsResponse
}

func (f *fakeServer) BatchCreateFederationRelationship(ctx context.Context, req *trustdomainv1.BatchCreateFederationRelationshipRequest) (*trustdomainv1.BatchCreateFederationRelationshipResponse, error) {
	if f.err != nil {
		return nil, f.err
	}

	spiretest.AssertProtoEqual(f.t, f.expectCreateReq, req)
	return f.createResp, nil
}

func (f *fakeServer) BatchDeleteFederationRelationship(ctx context.Context, req *trustdomainv1.BatchDeleteFederationRelationshipRequest) (*trustdomainv1.BatchDeleteFederationRelationshipResponse, error) {
	if f.err != nil {
		return nil, f.err
	}

	spiretest.AssertProtoEqual(f.t, f.expectDeleteReq, req)
	return f.deleteResp, nil
}

func (f *fakeServer) ListFederationRelationships(ctx context.Context, req *trustdomainv1.ListFederationRelationshipsRequest) (*trustdomainv1.ListFederationRelationshipsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}

	spiretest.AssertProtoEqual(f.t, f.expectListReq, req)
	return f.listResp, nil
}

func setupTest(t *testing.T, newClient func(*common_cli.Env) cli.Command) *cmdTest {
	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	client := newClient(&common_cli.Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	})

	server := &fakeServer{t: t}
	socketPath := spiretest.StartGRPCSocketServerOnTempSocket(t, func(s *grpc.Server) {
		trustdomainv1.RegisterTrustDomainServer(s, server)
	})

	test := &cmdTest{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		args:   []string{"-socketPath", socketPath},
		server: server,
		client: client,
	}

	t.Cleanup(func() {
		test.afterTest(t)
	})

	return test
}
