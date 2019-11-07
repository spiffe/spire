package sshpop

import (
	"context"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/spiffe/spire/pkg/common/plugin/sshpop"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"
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

	certAuthority, err := ioutil.ReadFile(certAuthoritiesPath)
	require.NoError(err)
	serverConfig := fmt.Sprintf(`cert_authorities = [%q]`, certAuthority)

	resp, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: serverConfig,
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	require.NoError(err)
	require.Equal(resp, &plugin.ConfigureResponse{})

	sshserver, err := sshpop.NewServer("example.org", serverConfig)
	require.NoError(err)
	s.sshserver = sshserver

	clientConfig := fmt.Sprintf(`
		host_key_path = %q
		host_cert_path = %q`, privateKeyPath, certificatePath)
	sshclient, err := sshpop.NewClient("example.org", clientConfig)
	require.NoError(err)
	s.sshclient = sshclient
}

func (s *Suite) TestAttestSuccess() {
	require := s.Require()

	client := s.sshclient.NewHandshake()

	stream, done := s.attest()
	defer done()

	// send down good attestation data
	attestationData, err := client.AttestationData()
	require.NoError(err)
	err = stream.Send(&nodeattestor.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: "sshpop",
			Data: attestationData,
		},
	})
	require.NoError(err)

	// receive and parse challenge
	resp, err := stream.Recv()
	require.NoError(err)
	require.Equal("", resp.AgentId)
	s.NotEmpty(resp.Challenge)

	// calculate and send the response
	challengeRes, err := client.RespondToChallenge(resp.Challenge)
	require.NoError(err)
	err = stream.Send(&nodeattestor.AttestRequest{
		Response: challengeRes,
	})
	require.NoError(err)

	// receive the attestation result
	resp, err = stream.Recv()
	require.NoError(err)
	require.Equal("spiffe://example.org/spire/agent/sshpop/21Aic_muK032oJMhLfU1_CMNcGmfAnvESeuH5zyFw_g", resp.AgentId)
	require.Nil(resp.Challenge)
	require.Len(resp.Selectors, 0)
}

func (s *Suite) TestAttestFailure() {
	require := s.Require()

	attestFails := func(attestationData *common.AttestationData, expected string) {
		stream, done := s.attest()
		defer done()

		require.NoError(stream.Send(&nodeattestor.AttestRequest{
			AttestationData: attestationData,
		}))

		resp, err := stream.Recv()
		s.errorContains(err, expected)
		require.Nil(resp)
	}

	challengeResponseFails := func(response string, expected string) {
		stream, done := s.attest()
		defer done()

		client := s.sshclient.NewHandshake()
		attestationData, err := client.AttestationData()
		require.NoError(err)
		err = stream.Send(&nodeattestor.AttestRequest{
			AttestationData: &common.AttestationData{
				Type: "sshpop",
				Data: attestationData,
			},
		})
		require.NoError(err)

		resp, err := stream.Recv()
		require.NoError(err)
		s.NotNil(resp)

		require.NoError(stream.Send(&nodeattestor.AttestRequest{
			Response: []byte(response),
		}))

		resp, err = stream.Recv()
		s.errorContains(err, expected)
		require.Nil(resp)
	}

	// not configured yet
	stream, err := s.newPlugin().Attest(context.Background())
	require.NoError(err)
	defer func() {
		require.NoError(stream.CloseSend())
	}()
	resp, err := stream.Recv()
	s.RequireGRPCStatus(err, codes.Unknown, "sshpop: not configured")
	require.Nil(resp)

	// unexpected data type
	attestFails(&common.AttestationData{Type: "foo"}, "sshpop: expected attestation type \"sshpop\" but got \"foo\"")

	// malformed challenge response
	challengeResponseFails("", "sshpop: failed to unmarshal challenge response")

	// invalid response
	challengeResponseFails("{}", "sshpop: failed to combine nonces")
}

func (s *Suite) TestGetPluginInfo() {
	require := s.Require()

	resp, err := s.p.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	require.NoError(err)
	require.Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *Suite) attest() (nodeattestor.NodeAttestor_AttestClient, func()) {
	stream, err := s.p.Attest(context.Background())
	s.Require().NoError(err)
	return stream, func() {
		s.Require().NoError(stream.CloseSend())
	}
}

func (s *Suite) errorContains(err error, substring string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), substring)
}
