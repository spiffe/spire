package sshpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/sshpop"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/test/fixture"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
)

func TestSSHPoP(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	attestor  nodeattestor.NodeAttestor
	sshclient *sshpop.Client
	sshserver *sshpop.Server
}

func (s *Suite) SetupTest() {
	s.attestor = s.loadPlugin(s.T())
}

func (s *Suite) loadPlugin(t *testing.T) nodeattestor.NodeAttestor {
	v1 := new(nodeattestor.V1)

	certificatePath := fixture.Join("nodeattestor", "sshpop", "agent_ssh_key-cert.pub")
	privateKeyPath := fixture.Join("nodeattestor", "sshpop", "agent_ssh_key")
	certAuthoritiesPath := fixture.Join("nodeattestor", "sshpop", "ssh_cert_authority.pub")

	certAuthority, err := os.ReadFile(certAuthoritiesPath)
	require.NoError(t, err)
	serverConfig := fmt.Sprintf(`cert_authorities = [%q]`, certAuthority)

	plugintest.Load(s.T(), BuiltIn(), v1,
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(serverConfig),
	)

	sshserver, err := sshpop.NewServer("example.org", serverConfig)
	require.NoError(t, err)
	s.sshserver = sshserver

	clientConfig := fmt.Sprintf(`
		host_key_path = %q
		host_cert_path = %q`, privateKeyPath, certificatePath)
	sshclient, err := sshpop.NewClient("example.org", clientConfig)
	require.NoError(t, err)
	s.sshclient = sshclient

	return v1
}

func (s *Suite) TestAttestSuccess() {
	client := s.sshclient.NewHandshake()

	// send down good attestation data
	attestationData, err := client.AttestationData()
	require.NoError(s.T(), err)

	result, err := s.attestor.Attest(context.Background(), attestationData, func(ctx context.Context, challenge []byte) ([]byte, error) {
		require.NotEmpty(s.T(), challenge)
		challengeRes, err := client.RespondToChallenge(challenge)
		require.NoError(s.T(), err)

		return challengeRes, nil
	})

	// receive the attestation result
	require.NoError(s.T(), err)
	require.Equal(s.T(), "spiffe://example.org/spire/agent/sshpop/21Aic_muK032oJMhLfU1_CMNcGmfAnvESeuH5zyFw_g", result.AgentID)
	require.Len(s.T(), result.Selectors, 0)
}

func (s *Suite) TestAttestFailure() {
	attestFails := func(t *testing.T, attestor nodeattestor.NodeAttestor, payload []byte, expectCode codes.Code, expectMessage string) {
		result, err := attestor.Attest(context.Background(), payload, expectNoChallenge)
		spiretest.RequireGRPCStatusContains(t, err, expectCode, expectMessage)
		require.Nil(nil, result)
	}

	challengeResponseFails := func(t *testing.T, attestor nodeattestor.NodeAttestor, response string, expectCode codes.Code, expectMessage string) {
		client := s.sshclient.NewHandshake()
		attestationData, err := client.AttestationData()
		require.NoError(t, err)

		doChallenge := func(ctx context.Context, challenge []byte) ([]byte, error) {
			require.NotEmpty(t, challenge)
			return []byte(response), nil
		}
		result, err := attestor.Attest(context.Background(), attestationData, doChallenge)
		spiretest.RequireGRPCStatusContains(t, err, expectCode, expectMessage)
		require.Nil(t, result)
	}

	s.T().Run("not configured", func(t *testing.T) {
		attestor := new(nodeattestor.V1)
		plugintest.Load(t, BuiltIn(), attestor)

		attestFails(t, attestor, []byte("payload"), codes.FailedPrecondition, "nodeattestor(sshpop): not configured")
	})

	s.T().Run("no attestation payload", func(t *testing.T) {
		attestor := new(nodeattestor.V1)
		plugintest.Load(t, BuiltIn(), attestor)

		attestFails(t, attestor, nil, codes.InvalidArgument, "payload cannot be empty")
	})

	s.T().Run("malformed payload", func(t *testing.T) {
		attestor := s.loadPlugin(t)
		attestFails(t, attestor, []byte("payload"), codes.Internal, "nodeattestor(sshpop): failed to unmarshal data")
	})

	s.T().Run("malformed challenge response", func(t *testing.T) {
		attestor := s.loadPlugin(t)
		challengeResponseFails(t, attestor, "", codes.Internal, "nodeattestor(sshpop): failed to unmarshal challenge response")
	})

	s.T().Run("invalid response", func(t *testing.T) {
		attestor := s.loadPlugin(t)
		challengeResponseFails(t, attestor, "{}", codes.Internal, "failed to combine nonces")
	})
}

func expectNoChallenge(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("challenge is not expected")
}

func (s *Suite) TestVerifyClientIP() {
	const sourceAddr = "10.0.0.5"

	// The fixture certificates carry no source-address critical option, so mint
	// a certificate that does and trust it for the duration of this test.
	dir := s.T().TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(s.T(), err)
	caSigner, err := ssh.NewSignerFromSigner(caKey)
	require.NoError(s.T(), err)

	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(s.T(), err)
	hostSigner, err := ssh.NewSignerFromSigner(hostKey)
	require.NoError(s.T(), err)

	cert := &ssh.Certificate{
		Key:             hostSigner.PublicKey(),
		CertType:        ssh.HostCert,
		ValidPrincipals: []string{"node.example.org"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	cert.CriticalOptions = map[string]string{"source-address": sourceAddr}
	require.NoError(s.T(), cert.SignCert(rand.Reader, caSigner))

	hostKeyDER, err := x509.MarshalECPrivateKey(hostKey)
	require.NoError(s.T(), err)
	hostKeyPath := filepath.Join(dir, "host_key")
	require.NoError(s.T(), os.WriteFile(hostKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: hostKeyDER}), 0600))
	hostCertPath := filepath.Join(dir, "host_key-cert.pub")
	require.NoError(s.T(), os.WriteFile(hostCertPath, ssh.MarshalAuthorizedKey(cert), 0600))

	certAuthority := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(caSigner.PublicKey())))
	serverConfig := fmt.Sprintf("cert_authorities = [%q]\nverify_client_ip = true", certAuthority)
	clientConfig := fmt.Sprintf("host_key_path = %q\nhost_cert_path = %q", hostKeyPath, hostCertPath)

	newAttestor := func(t *testing.T) (nodeattestor.NodeAttestor, *sshpop.Client) {
		v1 := new(nodeattestor.V1)
		plugintest.Load(t, BuiltIn(), v1,
			plugintest.CoreConfig(catalog.CoreConfig{
				TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
			}),
			plugintest.Configure(serverConfig),
		)
		client, err := sshpop.NewClient("example.org", clientConfig)
		require.NoError(t, err)
		return v1, client
	}

	attest := func(t *testing.T, ctx context.Context) error {
		attestor, client := newAttestor(t)
		handshake := client.NewHandshake()
		attestationData, err := handshake.AttestationData()
		require.NoError(t, err)
		_, err = attestor.Attest(ctx, attestationData, func(_ context.Context, challenge []byte) ([]byte, error) {
			return handshake.RespondToChallenge(challenge)
		})
		return err
	}

	contextWithPeer := func(ip string) context.Context {
		return peer.NewContext(context.Background(), &peer.Peer{
			Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 12345},
		})
	}

	s.T().Run("client IP matches source-address", func(t *testing.T) {
		require.NoError(t, attest(t, contextWithPeer(sourceAddr)))
	})

	s.T().Run("client IP does not match source-address", func(t *testing.T) {
		err := attest(t, contextWithPeer("10.0.0.6"))
		spiretest.RequireGRPCStatusContains(t, err, codes.PermissionDenied, "client IP verification failed")
	})

	s.T().Run("client IP not available", func(t *testing.T) {
		err := attest(t, context.Background())
		spiretest.RequireGRPCStatusContains(t, err, codes.Internal, "client IP not available for verification")
	})
}
