package sshpop

import (
	"context"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/plugin/sshpop"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/fixture"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
)

func TestSSHPoP(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	p         nodeattestor.Plugin
	sshclient *sshpop.Client
	sshserver *sshpop.Server
}

func (s *Suite) SetupTest() {
	s.p = s.newPlugin()
	s.configure()
}

func (s *Suite) newPlugin() nodeattestor.Plugin {
	var p nodeattestor.Plugin
	s.LoadPlugin(BuiltIn(), &p)
	return p
}

func (s *Suite) configure() {
	require := s.Require()

	certificatePath := fixture.Join("nodeattestor", "sshpop", "agent_ssh_key-cert.pub")
	privateKeyPath := fixture.Join("nodeattestor", "sshpop", "agent_ssh_key")
	certAuthoritiesPath := fixture.Join("nodeattestor", "sshpop", "ssh_cert_authority.pub")

	clientConfig := fmt.Sprintf(`
		host_key_path = %q
		host_cert_path = %q`, privateKeyPath, certificatePath)

	resp, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: clientConfig,
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	require.NoError(err)
	require.Equal(resp, &plugin.ConfigureResponse{})

	sshclient, err := sshpop.NewClient("example.org", clientConfig)
	require.NoError(err)
	s.sshclient = sshclient

	certAuthority, err := ioutil.ReadFile(certAuthoritiesPath)
	require.NoError(err)
	sshserver, err := sshpop.NewServer("example.org", fmt.Sprintf(`cert_authorities = [%q]`, certAuthority))
	require.NoError(err)
	s.sshserver = sshserver
}

func (s *Suite) TestFetchAttestationDataSuccess() {
	require := s.Require()

	client := s.sshclient.NewHandshake()
	server := s.sshserver.NewHandshake()

	stream, done := s.fetchAttestationData()
	defer done()

	attesetationData, err := client.AttestationData()
	require.NoError(err)

	// first response has the spiffeid and attestation data
	resp, err := stream.Recv()
	require.NoError(err)
	require.NotNil(resp)
	require.Equal("sshpop", resp.AttestationData.Type)
	require.JSONEq(string(attesetationData), string(resp.AttestationData.Data))
	require.Nil(resp.Response)

	// send a challenge
	err = server.VerifyAttestationData(resp.AttestationData.Data)
	require.NoError(err)
	challenge, err := server.IssueChallenge()
	require.NoError(err)
	err = stream.Send(&nodeattestor.FetchAttestationDataRequest{
		Challenge: challenge,
	})
	require.NoError(err)

	// recv the response
	resp, err = stream.Recv()
	require.NoError(err)
	require.Nil(resp.AttestationData)
	require.NotEmpty(resp.Response)

	// verify signature
	err = server.VerifyChallengeResponse(resp.Response)
	require.NoError(err)
}

func (s *Suite) TestFetchAttestationDataFailure() {
	require := s.Require()

	challengeFails := func(challenge []byte, expected string) {
		stream, done := s.fetchAttestationData()
		defer done()

		resp, err := stream.Recv()
		require.NoError(err)
		require.NotNil(resp)

		require.NoError(stream.Send(&nodeattestor.FetchAttestationDataRequest{
			Challenge: challenge,
		}))

		resp, err = stream.Recv()
		s.RequireErrorContains(err, expected)
		require.Nil(resp)
	}

	// not configured
	stream, err := s.newPlugin().FetchAttestationData(context.Background())
	require.NoError(err)
	defer func() { s.NoError(stream.CloseSend()) }()
	resp, err := stream.Recv()
	s.RequireGRPCStatus(err, codes.Unknown, "sshpop: not configured")
	require.Nil(resp)

	// malformed challenge
	challengeFails(nil, "sshpop: failed to unmarshal challenge request")

	// empty challenge
	challengeFails([]byte("{}"), "sshpop: failed to combine nonces")
}

func (s *Suite) TestGetPluginInfo() {
	require := s.Require()

	resp, err := s.p.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	require.NoError(err)
	require.Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *Suite) fetchAttestationData() (nodeattestor.NodeAttestor_FetchAttestationDataClient, func()) {
	stream, err := s.p.FetchAttestationData(context.Background())
	s.Require().NoError(err)
	return stream, func() {
		s.Require().NoError(stream.CloseSend())
	}
}
