package tailscale

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	commonutil "github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	spirecommon "github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcpeer "google.golang.org/grpc/peer"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

const (
	testNodeID   = "n1234567890"
	testHostname = "mynode"
	testOS       = "linux"
	testUser     = "user@example.com"
	testPeerAddr = "100.64.0.5:12345"
)

var (
	testAddresses = []netip.Prefix{
		netip.MustParsePrefix("100.64.0.5/32"),
		netip.MustParsePrefix("fd7a:115c:a1e0::5/128"),
	}
	testTags = []string{"tag:server", "tag:production"}
)

func TestTailscaleAttestor(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	agentStore *fakeagentstore.AgentStore
}

func (s *Suite) SetupTest() {
	s.agentStore = fakeagentstore.New()
}

// ctxWithPeer returns a context with gRPC peer info set to the given address.
// The V1 wrapper extracts this and forwards it as metadata to the plugin.
func ctxWithPeer(addr string) context.Context {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", addr)
	return grpcpeer.NewContext(context.Background(), &grpcpeer.Peer{Addr: tcpAddr})
}

func (s *Suite) TestErrorWhenNotConfigured() {
	attestor := new(nodeattestor.V1)
	plugintest.Load(s.T(), builtin(New()), attestor,
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
	)

	result, err := attestor.Attest(ctxWithPeer(testPeerAddr), []byte("{}"), expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.FailedPrecondition, "not configured")
	s.Require().Nil(result)
}

func (s *Suite) TestErrorOnMissingPayload() {
	attestor := s.loadPlugin(s.defaultConfig(), s.defaultFakeClient())
	result, err := attestor.Attest(ctxWithPeer(testPeerAddr), nil, expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.InvalidArgument, "payload cannot be empty")
	s.Require().Nil(result)
}

func (s *Suite) TestErrorOnNoPeerAddress() {
	// Attest with no peer info in context — the V1 wrapper won't set the metadata
	attestor := s.loadPlugin(s.defaultConfig(), s.defaultFakeClient())
	result, err := attestor.Attest(context.Background(), []byte("{}"), expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.Internal, "peer address not found")
	s.Require().Nil(result)
}

func (s *Suite) TestErrorOnNonTailscaleIP() {
	attestor := s.loadPlugin(s.defaultConfig(), s.defaultFakeClient())
	result, err := attestor.Attest(ctxWithPeer("192.168.1.1:12345"), []byte("{}"), expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.PermissionDenied, "not a Tailscale IP")
	s.Require().Nil(result)
}

func (s *Suite) TestErrorOnWhoisFailure() {
	fakeClient := &fakeWhoisClient{
		err: fmt.Errorf("connection refused"),
	}
	attestor := s.loadPlugin(s.defaultConfig(), fakeClient)
	result, err := attestor.Attest(ctxWithPeer(testPeerAddr), []byte("{}"), expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.Internal, "failed to query tailscaled whois")
	s.Require().Nil(result)
}

func (s *Suite) TestErrorOnDeviceNotAuthorized() {
	resp := s.defaultWhoIsResponse()
	resp.Node.MachineAuthorized = false
	fakeClient := &fakeWhoisClient{response: resp}
	attestor := s.loadPlugin(s.defaultConfig(), fakeClient)
	result, err := attestor.Attest(ctxWithPeer(testPeerAddr), []byte("{}"), expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.PermissionDenied, "not authorized")
	s.Require().Nil(result)
}

func (s *Suite) TestErrorOnAttestedBefore() {
	fakeClient := &fakeWhoisClient{response: s.defaultWhoIsResponse()}
	attestor := s.loadPlugin(s.defaultConfig(), fakeClient)

	agentID := fmt.Sprintf("spiffe://example.org/spire/agent/tailscale/%s", testNodeID)
	s.agentStore.SetAgentInfo(&agentstorev1.AgentInfo{
		AgentId: agentID,
	})

	result, err := attestor.Attest(ctxWithPeer(testPeerAddr), []byte("{}"), expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.PermissionDenied, "attestation data has already been used to attest an agent")
	s.Require().Nil(result)
}

func (s *Suite) TestAttestSuccess() {
	fakeClient := &fakeWhoisClient{response: s.defaultWhoIsResponse()}
	attestor := s.loadPlugin(s.defaultConfig(), fakeClient)

	result, err := attestor.Attest(ctxWithPeer(testPeerAddr), []byte("{}"), expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(result)

	expectedAgentID := fmt.Sprintf("spiffe://example.org/spire/agent/tailscale/%s", testNodeID)
	s.Require().Equal(expectedAgentID, result.AgentID)
	s.Require().True(result.CanReattest)

	expectedSelectors := []*spirecommon.Selector{
		{Type: "tailscale", Value: "hostname:mynode"},
		{Type: "tailscale", Value: "tag:server"},
		{Type: "tailscale", Value: "tag:production"},
		{Type: "tailscale", Value: "os:linux"},
		{Type: "tailscale", Value: "address:100.64.0.5"},
		{Type: "tailscale", Value: "address:fd7a:115c:a1e0::5"},
		{Type: "tailscale", Value: "user:user@example.com"},
		{Type: "tailscale", Value: "authorized:true"},
		{Type: "tailscale", Value: "node_id:" + testNodeID},
	}
	commonutil.SortSelectors(expectedSelectors)
	commonutil.SortSelectors(result.Selectors)
	spiretest.AssertProtoListEqual(s.T(), expectedSelectors, result.Selectors)
}

func (s *Suite) TestAttestSuccessIPv6() {
	resp := s.defaultWhoIsResponse()
	fakeClient := &fakeWhoisClient{response: resp}
	attestor := s.loadPlugin(s.defaultConfig(), fakeClient)

	result, err := attestor.Attest(ctxWithPeer("[fd7a:115c:a1e0::5]:12345"), []byte("{}"), expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(result)
	s.Require().Equal(fmt.Sprintf("spiffe://example.org/spire/agent/tailscale/%s", testNodeID), result.AgentID)
}

func (s *Suite) TestAttestSuccessWithCustomTemplate() {
	config := `agent_path_template = "/{{ .Hostname }}"`
	fakeClient := &fakeWhoisClient{response: s.defaultWhoIsResponse()}
	attestor := s.loadPlugin(config, fakeClient)

	result, err := attestor.Attest(ctxWithPeer(testPeerAddr), []byte("{}"), expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(result)
	s.Require().Equal("spiffe://example.org/spire/agent/mynode", result.AgentID)
}

func (s *Suite) TestAttestSuccessMinimalSelectors() {
	resp := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			StableID:          tailcfg.StableNodeID(testNodeID),
			Hostinfo:          (&tailcfg.Hostinfo{Hostname: testHostname}).View(),
			MachineAuthorized: true,
		},
	}
	fakeClient := &fakeWhoisClient{response: resp}
	attestor := s.loadPlugin(s.defaultConfig(), fakeClient)

	result, err := attestor.Attest(ctxWithPeer(testPeerAddr), []byte("{}"), expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(result)

	expectedSelectors := []*spirecommon.Selector{
		{Type: "tailscale", Value: "hostname:mynode"},
		{Type: "tailscale", Value: "authorized:true"},
		{Type: "tailscale", Value: "node_id:" + testNodeID},
	}
	commonutil.SortSelectors(expectedSelectors)
	commonutil.SortSelectors(result.Selectors)
	spiretest.AssertProtoListEqual(s.T(), expectedSelectors, result.Selectors)
}

func (s *Suite) TestConfigure() {
	doConfig := func(t *testing.T, coreConfig catalog.CoreConfig, config string) error {
		var err error
		plugintest.Load(t, BuiltIn(), nil,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(config),
		)
		return err
	}

	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}

	s.T().Run("malformed HCL", func(t *testing.T) {
		err := doConfig(t, coreConfig, "bad juju")
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "unable to decode configuration")
	})

	s.T().Run("bad agent_path_template", func(t *testing.T) {
		err := doConfig(t, coreConfig, `agent_path_template = "/{{ .NodeID "`)
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "failed to parse agent path template")
	})

	s.T().Run("success with defaults", func(t *testing.T) {
		err := doConfig(t, coreConfig, "")
		require.NoError(t, err)
	})

	s.T().Run("success with socket_path", func(t *testing.T) {
		err := doConfig(t, coreConfig, `socket_path = "/var/run/tailscale/tailscaled.sock"`)
		require.NoError(t, err)
	})
}

func (s *Suite) TestIsTailscaleIP() {
	tests := []struct {
		addr     string
		expected bool
	}{
		{"100.64.0.1:1234", true},
		{"100.127.255.255:1234", true},
		{"100.64.0.1", true},
		{"fd7a:115c:a1e0::1", true},
		{"[fd7a:115c:a1e0::1]:1234", true},
		{"192.168.1.1:1234", false},
		{"10.0.0.1:1234", false},
		{"not-an-ip", false},
	}
	for _, tt := range tests {
		s.T().Run(tt.addr, func(t *testing.T) {
			require.Equal(t, tt.expected, isTailscaleIP(tt.addr))
		})
	}
}

// Helpers

func (s *Suite) defaultConfig() string {
	return ""
}

func (s *Suite) defaultWhoIsResponse() *apitype.WhoIsResponse {
	return &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			StableID: tailcfg.StableNodeID(testNodeID),
			Hostinfo: (&tailcfg.Hostinfo{
				Hostname: testHostname,
				OS:       testOS,
			}).View(),
			Tags:              testTags,
			Addresses:         testAddresses,
			MachineAuthorized: true,
		},
		UserProfile: &tailcfg.UserProfile{
			LoginName: testUser,
		},
	}
}

func (s *Suite) defaultFakeClient() *fakeWhoisClient {
	return &fakeWhoisClient{response: s.defaultWhoIsResponse()}
}

func (s *Suite) loadPlugin(config string, client whoisClient) nodeattestor.NodeAttestor {
	p := New()
	if client != nil {
		p.hooks.newClient = func(_ string) whoisClient {
			return client
		}
	}

	v1 := new(nodeattestor.V1)
	plugintest.Load(s.T(), builtin(p), v1,
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
		plugintest.Configure(config),
	)
	return v1
}

// fakeWhoisClient is a test double for the tailscaled local API.
type fakeWhoisClient struct {
	response *apitype.WhoIsResponse
	err      error
}

func (f *fakeWhoisClient) WhoIs(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.response, nil
}

func expectNoChallenge(_ context.Context, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("challenge is not expected")
}
