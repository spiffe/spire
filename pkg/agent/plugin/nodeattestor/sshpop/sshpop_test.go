package sshpop

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/sshpop"
	"github.com/spiffe/spire/test/fixture"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
)

var (
	streamBuilder = nodeattestortest.ServerStream(sshpop.PluginName)
)

func TestSSHPoP(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	na        nodeattestor.NodeAttestor
	sshclient *sshpop.Client
	sshserver *sshpop.Server
}

func (s *Suite) SetupTest() {
	require := s.Require()

	certificatePath := fixture.Join("nodeattestor", "sshpop", "agent_ssh_key-cert.pub")
	privateKeyPath := fixture.Join("nodeattestor", "sshpop", "agent_ssh_key")
	certAuthoritiesPath := fixture.Join("nodeattestor", "sshpop", "ssh_cert_authority.pub")

	clientConfig := fmt.Sprintf(`
		host_key_path = %q
		host_cert_path = %q`, privateKeyPath, certificatePath)

	s.na = s.loadPlugin(plugintest.CoreConfig(catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}),
		plugintest.Configure(clientConfig),
	)

	sshclient, err := sshpop.NewClient("example.org", clientConfig)
	require.NoError(err)
	s.sshclient = sshclient

	certAuthority, err := os.ReadFile(certAuthoritiesPath)
	require.NoError(err)
	sshserver, err := sshpop.NewServer("example.org", fmt.Sprintf(`cert_authorities = [%q]`, certAuthority))
	require.NoError(err)
	s.sshserver = sshserver
}

func (s *Suite) loadPlugin(options ...plugintest.Option) nodeattestor.NodeAttestor {
	na := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), na, options...)
	return na
}

func (s *Suite) TestFetchAttestationDataSuccess() {
	require := s.Require()

	server := s.sshserver.NewHandshake()

	err := s.na.Attest(context.Background(),
		streamBuilder.Handle(func(payloadOrChallengeResponse []byte) (challenge []byte, err error) {
			// send challenge
			if err := server.VerifyAttestationData(payloadOrChallengeResponse); err != nil {
				return nil, err
			}
			return server.IssueChallenge()
		}).Handle(func(payloadOrChallengeResponse []byte) (challenge []byte, err error) {
			// verify signature
			if err := server.VerifyChallengeResponse(payloadOrChallengeResponse); err != nil {
				return nil, err
			}
			return nil, nil
		}).Build())
	require.NoError(err)
}

func (s *Suite) TestFetchAttestationDataFailure() {
	// not configured
	err := s.loadPlugin().Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatus(err, codes.FailedPrecondition, "nodeattestor(sshpop): not configured")

	// malformed challenge
	err = s.na.Attest(context.Background(), streamBuilder.IgnoreThenChallenge([]byte("malformed")).Build())
	s.RequireGRPCStatusContains(err, codes.Internal, "nodeattestor(sshpop): failed to unmarshal challenge request")

	// empty challenge
	err = s.na.Attest(context.Background(), streamBuilder.IgnoreThenChallenge([]byte("{}")).Build())
	s.RequireGRPCStatusContains(err, codes.Internal, "nodeattestor(sshpop): failed to combine nonces")
}
