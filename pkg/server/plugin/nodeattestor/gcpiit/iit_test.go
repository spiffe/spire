package gcpiit

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/gcp"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/compute/v1"
	"google.golang.org/grpc/codes"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	testProject      = "test-project"
	testZone         = "test-zone"
	testInstanceID   = "test-instance-id"
	testInstanceName = "test-instance-name"
	testAgentID      = "spiffe://example.org/spire/agent/gcp_iit/test-project/test-instance-id"
	testSAFile       = "test_sa.json"
)

var (
	testKey = testkey.MustRSA2048()
)

func TestIITAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(IITAttestorSuite))
}

type IITAttestorSuite struct {
	spiretest.Suite

	agentStore *fakeagentstore.AgentStore
	attestor   nodeattestor.NodeAttestor

	client *fakeComputeEngineClient
}

func (s *IITAttestorSuite) SetupTest() {
	s.agentStore = fakeagentstore.New()
	s.client = newFakeComputeEngineClient()
	s.attestor = s.loadPlugin()
}

func (s *IITAttestorSuite) TestErrorWhenNotConfigured() {
	attestor := new(nodeattestor.V1)
	plugintest.Load(s.T(), builtin(s.newPlugin()), attestor,
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
	)
	s.attestor = attestor

	payload := s.signDefaultToken()
	s.requireAttestError(s.T(), payload, codes.FailedPrecondition, "nodeattestor(gcp_iit): not configured")
}

func (s *IITAttestorSuite) TestErrorOnMissingPayload() {
	s.requireAttestError(s.T(), nil, codes.InvalidArgument, "payload cannot be empty")
}

func (s *IITAttestorSuite) TestErrorOnMissingKid() {
	payload := s.signToken(testKey, "", buildDefaultClaims())
	s.requireAttestError(s.T(), payload, codes.InvalidArgument, "nodeattestor(gcp_iit): failed to validate the identity token signature: square/go-jose: unsupported key type/format")
}

func (s *IITAttestorSuite) TestErrorOnInvalidClaims() {
	claims := buildDefaultClaims()
	claims.Expiry = jwt.NewNumericDate(time.Now().Add(-time.Hour))

	payload := s.signToken(testKey, "kid", claims)
	s.requireAttestError(s.T(), payload, codes.PermissionDenied, "nodeattestor(gcp_iit): failed to validate the identity token claims: square/go-jose/jwt: validation failed, token is expired (exp)")
}

func (s *IITAttestorSuite) TestErrorOnInvalidAudience() {
	claims := buildClaims(testProject, "invalid")

	payload := s.signToken(testKey, "kid", claims)
	s.requireAttestError(s.T(), payload, codes.PermissionDenied, `nodeattestor(gcp_iit): failed to validate the identity token claims: square/go-jose/jwt: validation failed, invalid audience claim (aud)`)
}

func (s *IITAttestorSuite) TestErrorOnAttestedBefore() {
	payload := s.signDefaultToken()

	s.agentStore.SetAgentInfo(&agentstorev1.AgentInfo{
		AgentId: testAgentID,
	})

	s.requireAttestError(s.T(), payload, codes.PermissionDenied, "nodeattestor(gcp_iit): attestation data has already been used to attest an agent")
}

func (s *IITAttestorSuite) TestErrorOnProjectIdMismatch() {
	claims := buildClaims("project-whatever", tokenAudience)
	payload := s.signToken(testKey, "kid", claims)

	s.requireAttestError(s.T(), payload, codes.PermissionDenied, `nodeattestor(gcp_iit): identity token project ID "project-whatever" is not in the allow list`)
}

func (s *IITAttestorSuite) TestErrorOnInvalidSignature() {
	alternativeKey := testkey.MustRSA2048()

	payload := s.signToken(alternativeKey, "kid", buildDefaultClaims())

	s.requireAttestError(s.T(), payload, codes.InvalidArgument, "nodeattestor(gcp_iit): failed to validate the identity token signature: square/go-jose: error in cryptographic primitive")
}

func (s *IITAttestorSuite) TestErrorOnInvalidPayload() {
	s.requireAttestError(s.T(), []byte("secret"), codes.InvalidArgument, "nodeattestor(gcp_iit): unable to parse the identity token: square/go-jose: compact JWS format must have three parts")
}

func (s *IITAttestorSuite) TestErrorOnServiceAccountFileMismatch() {
	// mismatch SA file
	s.client.setInstance(&compute.Instance{})

	s.attestor = s.loadPluginWithConfig(`
projectid_allow_list = ["test-project"]
use_instance_metadata = true
service_account_file = "error_sa.json"
`)

	s.requireAttestError(s.T(), s.signDefaultToken(), codes.Internal, `nodeattestor(gcp_iit): failed to fetch instance metadata: expected sa file "test_sa.json", got "error_sa.json"`)
}

func (s *IITAttestorSuite) TestAttestSuccess() {
	payload := s.signDefaultToken()

	result, err := s.attestor.Attest(context.Background(), payload, expectNoChallenge)
	s.Require().NoError(err)

	s.Require().Equal(testAgentID, result.AgentID)
	s.RequireProtoListEqual([]*common.Selector{
		{Type: "gcp_iit", Value: "project-id:test-project"},
		{Type: "gcp_iit", Value: "zone:test-zone"},
		{Type: "gcp_iit", Value: "instance-name:test-instance-name"},
	}, result.Selectors)
}

func (s *IITAttestorSuite) TestAttestSuccessWithInstanceMetadata() {
	s.attestor = s.loadPluginForInstanceMetadata(&compute.Instance{
		Tags: &compute.Tags{
			Items: []string{"tag-1", "tag-2"},
		},
		ServiceAccounts: []*compute.ServiceAccount{
			{Email: "service-account-1"},
			{Email: "service-account-2"},
		},
		Labels: map[string]string{
			"allowed":          "ALLOWED",
			"allowed-no-value": "",
			"disallowed":       "disallowed",
		},
		Metadata: &compute.Metadata{
			Items: []*compute.MetadataItems{
				{
					Key:   "allowed",
					Value: stringPtr("ALLOWED"),
				},
				{
					Key: "allowed-no-value",
				},
				{
					Key:   "disallowed",
					Value: stringPtr("DISALLOWED"),
				},
			},
		},
	})

	expectSelectors := []*common.Selector{
		{Type: "gcp_iit", Value: "project-id:" + testProject},
		{Type: "gcp_iit", Value: "zone:" + testZone},
		{Type: "gcp_iit", Value: "instance-name:" + testInstanceName},
		{Type: "gcp_iit", Value: "tag:tag-1"},
		{Type: "gcp_iit", Value: "tag:tag-2"},
		{Type: "gcp_iit", Value: "sa:service-account-1"},
		{Type: "gcp_iit", Value: "sa:service-account-2"},
		{Type: "gcp_iit", Value: "metadata:allowed:ALLOWED"},
		{Type: "gcp_iit", Value: "metadata:allowed-no-value:"},
		{Type: "gcp_iit", Value: "label:allowed:ALLOWED"},
		{Type: "gcp_iit", Value: "label:allowed-no-value:"},
	}

	result, err := s.attestor.Attest(context.Background(), s.signDefaultToken(), expectNoChallenge)
	s.Require().NoError(err)

	util.SortSelectors(expectSelectors)
	util.SortSelectors(result.Selectors)

	s.RequireProtoListEqual(expectSelectors, result.Selectors)
	s.Require().Equal(testAgentID, result.AgentID)
}

func (s *IITAttestorSuite) TestAttestFailsIfInstanceMetadataValueExceedsLimit() {
	s.attestor = s.loadPluginForInstanceMetadata(&compute.Instance{
		Metadata: &compute.Metadata{
			Items: []*compute.MetadataItems{
				{
					Key:   "allowed",
					Value: stringPtr("ALLOWED BUT TOO LONG"),
				},
			},
		},
	})
	s.requireAttestError(s.T(), s.signDefaultToken(), codes.Internal, `nodeattestor(gcp_iit): metadata "allowed" exceeded value limit (20 > 10)`)
}

func (s *IITAttestorSuite) TestAttestSuccessWithEmptyInstanceMetadata() {
	s.attestor = s.loadPluginForInstanceMetadata(&compute.Instance{})

	result, err := s.attestor.Attest(context.Background(), s.signDefaultToken(), expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(result)

	s.Require().Equal(testAgentID, result.AgentID)
	s.RequireProtoListEqual([]*common.Selector{
		{Type: "gcp_iit", Value: "project-id:" + testProject},
		{Type: "gcp_iit", Value: "zone:" + testZone},
		{Type: "gcp_iit", Value: "instance-name:" + testInstanceName},
	}, result.Selectors)
}

func (s *IITAttestorSuite) TestAttestFailureDueToMissingInstanceMetadata() {
	s.attestor = s.loadPluginForInstanceMetadata(nil)

	s.requireAttestError(s.T(), s.signDefaultToken(), codes.Internal, "nodeattestor(gcp_iit): failed to fetch instance metadata: no instance found")
}

func (s *IITAttestorSuite) TestAttestSuccessWithCustomSPIFFEIDTemplate() {
	attestor := s.loadPluginWithConfig(`
projectid_allow_list = ["test-project"]
agent_path_template = "/{{ .InstanceID }}"
`)

	expectSVID := "spiffe://example.org/spire/agent/test-instance-id"

	payload := s.signDefaultToken()
	result, err := attestor.Attest(context.Background(), payload, expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(result)
	s.Require().Equal(expectSVID, result.AgentID)
}

func (s *IITAttestorSuite) TestConfigure() {
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

	s.T().Run("malformed", func(t *testing.T) {
		err := doConfig(t, coreConfig, "trust_domain")
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "unable to decode configuration")
	})

	s.T().Run("missing trust domain", func(t *testing.T) {
		err := doConfig(t, catalog.CoreConfig{}, `
projectid_allow_list = ["bar"]
		`)
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "trust_domain is required")
	})

	s.T().Run("missing projectID allow list", func(t *testing.T) {
		err := doConfig(t, coreConfig, "")
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "projectid_allow_list is required")
	})

	s.T().Run("bad SVID template", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
projectid_allow_list = ["test-project"]
agent_path_template = "/{{ .InstanceID "
`)
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "failed to parse agent path template")
	})

	s.T().Run("success", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
projectid_allow_list = ["bar"]
		`)
		require.NoError(t, err)
	})
}

func (s *IITAttestorSuite) TestFailToRecvStream() {
	_, err := validateAttestationAndExtractIdentityMetadata(&recvFailStream{}, nil)
	s.Require().EqualError(err, "failed to recv from stream")
}

func (s *IITAttestorSuite) loadPlugin() nodeattestor.NodeAttestor {
	return s.loadPluginWithConfig(`
projectid_allow_list = ["test-project"]
	`)
}

func (s *IITAttestorSuite) loadPluginWithConfig(config string) nodeattestor.NodeAttestor {
	p := s.newPlugin()

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

func (s *IITAttestorSuite) newPlugin() *IITAttestorPlugin {
	p := New()
	p.jwksRetriever = testKeyRetriever{}
	p.client = s.client
	return p
}

func (s *IITAttestorSuite) signToken(key crypto.Signer, kid string, claims any) []byte {
	return signToken(s.T(), key, kid, claims)
}

func (s *IITAttestorSuite) signDefaultToken() []byte {
	return s.signToken(testKey, "kid", buildDefaultClaims())
}

func (s *IITAttestorSuite) requireAttestError(t *testing.T, payload []byte, expectCode codes.Code, expectMsg string) {
	result, err := s.attestor.Attest(context.Background(), payload, expectNoChallenge)
	spiretest.RequireGRPCStatusContains(t, err, expectCode, expectMsg)
	require.Nil(t, result)
}

func (s *IITAttestorSuite) loadPluginForInstanceMetadata(instance *compute.Instance) nodeattestor.NodeAttestor {
	s.client.setInstance(instance)
	return s.loadPluginWithConfig(`
projectid_allow_list = ["test-project"]
use_instance_metadata = true
allowed_label_keys = ["allowed", "allowed-no-value"]
allowed_metadata_keys = ["allowed", "allowed-no-value"]
max_metadata_value_size = 10
service_account_file = "test_sa.json"
`)
}

// Test helpers

type recvFailStream struct {
	nodeattestorv1.NodeAttestor_AttestServer
}

func (r *recvFailStream) Recv() (*nodeattestorv1.AttestRequest, error) {
	return nil, errors.New("failed to recv from stream")
}

type testKeyRetriever struct{}

func (testKeyRetriever) retrieveJWKS(context.Context) (*jose.JSONWebKeySet, error) {
	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID: "kid",
				Key:   testKey.Public(),
			},
		},
	}, nil
}

func buildClaims(projectID string, audience string) gcp.IdentityToken {
	return gcp.IdentityToken{
		Google: gcp.Google{
			ComputeEngine: gcp.ComputeEngine{
				ProjectID:    projectID,
				InstanceID:   testInstanceID,
				InstanceName: testInstanceName,
				Zone:         testZone,
			},
		},
		Claims: jwt.Claims{
			Audience: []string{audience},
		},
	}
}

func buildDefaultClaims() gcp.IdentityToken {
	return buildClaims("test-project", tokenAudience)
}

type fakeComputeEngineClient struct {
	mu       sync.Mutex
	instance *compute.Instance
}

func newFakeComputeEngineClient() *fakeComputeEngineClient {
	return &fakeComputeEngineClient{}
}

func (c *fakeComputeEngineClient) setInstance(instance *compute.Instance) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.instance = instance
}

func (c *fakeComputeEngineClient) fetchInstanceMetadata(_ context.Context, projectID, zone, instanceName string, serviceAccountFile string) (*compute.Instance, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case projectID != testProject:
		return nil, fmt.Errorf("expected project %q; got %q", testProject, projectID)
	case zone != testZone:
		return nil, fmt.Errorf("expected zone %q; got %q", testZone, zone)
	case instanceName != testInstanceName:
		return nil, fmt.Errorf("expected instance name %q; got %q", testInstanceName, instanceName)
	case c.instance == nil:
		return nil, errors.New("no instance found")
	case serviceAccountFile != testSAFile:
		return nil, fmt.Errorf("expected sa file %q, got %q", testSAFile, serviceAccountFile)
	default:
		return c.instance, nil
	}
}

func stringPtr(s string) *string {
	return &s
}

func expectNoChallenge(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("challenge is not expected")
}

func signToken(t *testing.T, key crypto.Signer, kid string, claims any) []byte {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key: &jose.JSONWebKey{
			Key:   cryptosigner.Opaque(key),
			KeyID: kid,
		},
	}, nil)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return []byte(token)
}
