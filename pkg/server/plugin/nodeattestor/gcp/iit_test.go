package gcp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/plugin/gcp"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	agentstorev0 "github.com/spiffe/spire/proto/spire/hostservice/server/agentstore/v0"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/compute/v1"
	"google.golang.org/grpc/codes"
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
	testKey, _ = pemutil.ParseRSAPrivateKey([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBzAIBAAJhAMnVzWSZn20CtcFaWh1Uuoh7NObRt9z84h8zzuIVSNkeJV6Dei0v
8FGp3ZilrU3MDM6WsuFTUVo21qBTOTnYKuEI0bk7pTgZk9CN6aF0iZbzyrvsU6hy
b09dN0PFBc5A2QIDAQABAmEAqSpioQvFPKfF0M46s1S9lwC1ATULRtRJbd+NaZ5v
VVLX/VRzRYZlhPy7d2J9U7ROFjSM+Fng8S1knrHAK0ka/ZfYOl1ZLoMexpBovebM
mGcsCHrHz4eBN8B1Y+8JRhkBAjEA7fTLjbz3M7za1nGODqWsoBv33yJHGh9GIaf9
umpx3qpFZCVsqHgCvmalAu+IXAz5AjEA2SPTRcddrGVsDnSOYot3eCArVOIxgI+r
H9A4cjS4cp4W4nBZhb+08/IYtDfYdirhAjAtl8LMtJE045GWlwld+xZ5UwKKSVoQ
Qj/AwRxXdH++5ycGijkoil4UNzyUtGqPIJkCMQC5g9ola8ekWqKPVxWvK+jOQO3E
f9w7MoPJkmQnbtOHWXnDzKkvlDJNmTFyB6RwkQECMQDp+GR2I305amG9isTzm7UU
8pJxbXLymDwR4A7x5vwH6x2gLBgpat21QAR14W4dYEg=
-----END RSA PRIVATE KEY-----`))

	// Alternative key
	alternativeKeyPEM, _ = pemutil.ParseRSAPrivateKey([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBywIBAAJhAKC4t/KjGW7qAuK89ZQGasYlI1octSwElSGioJag1w7s/d2EXjtY
4FDYOYa8bKB3wC6rIzPDKUR783fZ3gJmvdI8TLlnj25wyPApVkRXC3ZQxYj5/hcG
aQuNWr6zrY8C8QIDAQABAmB95nViQtWHhxTfnPobDLPTp//7dQWPB7/y6zw1AqW0
8X0ka66Net+tNNRLcYr+YQ8Sv4suvGVo3NXBNU+jJVys2s+kB2vvfh5w/mpaEyM1
C3UGsX8WWcRvxkxQhwR5VmECMQDWAufI9k7mfo8kjPcFcxKZbwiklTn0p6IVNXIf
cA7f210xizyPm2NDUvs1v+f6Yw0CMQDAQT1zR4qlTm4tufG0+IlfPaP9FxvTl+ox
dxnOm4DzNx14+seX6Mont4ucrrFnNnUCMQC3u8zVGqnId3VbMu7MreuU8N+htUAJ
jHW58aWl2eXbSJCs/VYkEIra/P4ROk3mCG0CMQC3mpaRDXW/QRO/36CR7/lhV4DR
J8yPWrlx3AhtY9zWaYBgFT+gN9U38PYIAF2z8DECMHNJ/MNm0Keasv9K3sfrCpL6
bpR/VgtruOOSiOvJJ9xOAKCSsyeVpZdHrWlY7fkCKg==
-----END RSA PRIVATE KEY-----`))
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
	plugintest.Load(s.T(), BuiltIn(), attestor,
		plugintest.HostServices(agentstorev0.AgentStoreServiceServer(s.agentStore)),
	)
	s.attestor = attestor
	s.requireAttestError(s.T(), []byte("payload"), codes.FailedPrecondition, "nodeattestor(gcp_iit): not configured")
}

func (s *IITAttestorSuite) TestErrorOnMissingPayload() {
	s.requireAttestError(s.T(), nil, codes.InvalidArgument, "payload cannot be empty")
}

func (s *IITAttestorSuite) TestErrorOnMissingKid() {
	token := buildToken()
	token.Header["kid"] = nil

	payload := s.signToken(token)
	s.requireAttestError(s.T(), payload, codes.InvalidArgument, "nodeattestor(gcp_iit): unable to parse/validate the identity token: identity token missing kid header")
}

func (s *IITAttestorSuite) TestErrorOnInvalidClaims() {
	claims := buildDefaultClaims()
	claims["exp"] = 1
	token := buildTokenWithClaims(claims)

	payload := s.signToken(token)
	s.requireAttestError(s.T(), payload, codes.InvalidArgument, "nodeattestor(gcp_iit): unable to parse/validate the identity token: token is expired")
}

func (s *IITAttestorSuite) TestErrorOnInvalidAudience() {
	claims := buildClaims(testProject, "invalid")
	token := buildTokenWithClaims(claims)

	payload := s.signToken(token)
	s.requireAttestError(s.T(), payload, codes.PermissionDenied, `nodeattestor(gcp_iit): unexpected identity token audience "invalid"`)
}

func (s *IITAttestorSuite) TestErrorOnAttestedBefore() {
	token := buildToken()
	payload := s.signToken(token)

	s.agentStore.SetAgentInfo(&agentstorev0.AgentInfo{
		AgentId: testAgentID,
	})

	s.requireAttestError(s.T(), payload, codes.PermissionDenied, "nodeattestor(gcp_iit): IIT has already been used to attest an agent")
}

func (s *IITAttestorSuite) TestErrorOnProjectIdMismatch() {
	claims := buildClaims("project-whatever", tokenAudience)
	token := buildTokenWithClaims(claims)
	payload := s.signToken(token)

	s.requireAttestError(s.T(), payload, codes.PermissionDenied, `nodeattestor(gcp_iit): identity token project ID "project-whatever" is not in the allow list`)
}

func (s *IITAttestorSuite) TestErrorOnInvalidAlgorithm() {
	token := buildToken()

	tokenString, err := token.SignedString(alternativeKeyPEM)
	s.Require().NoError(err)

	payload := []byte(tokenString)

	s.requireAttestError(s.T(), payload, codes.InvalidArgument, "nodeattestor(gcp_iit): unable to parse/validate the identity token: crypto/rsa: verification error")
}

func (s *IITAttestorSuite) TestErrorOnInvalidPayload() {
	s.requireAttestError(s.T(), []byte("secret"), codes.InvalidArgument, "nodeattestor(gcp_iit): unable to parse/validate the identity token: token contains an invalid number of segments")
}

func (s *IITAttestorSuite) TestErrorOnBadSVIDTemplate() {
	var err error
	plugintest.Load(s.T(), BuiltIn(), nil,
		plugintest.CaptureConfigureError(&err),
		plugintest.HostServices(agentstorev0.AgentStoreServiceServer(s.agentStore)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`
projectid_allow_list = ["test-project"]
agent_path_template = "{{ .InstanceID "
`),
	)

	s.AssertGRPCStatusContains(err, codes.InvalidArgument, "failed to parse agent path template")
}

func (s *IITAttestorSuite) TestErrorOnServiceAccountFileMismatch() {
	// mismatch SA file
	s.client.setInstance(&compute.Instance{})

	s.attestor = s.loadPluginWithConfig(`
projectid_allow_list = ["test-project"]
use_instance_metadata = true
service_account_file = "error_sa.json"
`)

	s.requireAttestError(s.T(), s.signToken(buildToken()), codes.Internal, `nodeattestor(gcp_iit): failed to fetch instance metadata: expected sa file "test_sa.json", got "error_sa.json"`)
}

func (s *IITAttestorSuite) TestAttestSuccess() {
	token := buildToken()
	payload := s.signToken(token)

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

	result, err := s.attestor.Attest(context.Background(), s.signToken(buildToken()), expectNoChallenge)
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
	s.requireAttestError(s.T(), s.signToken(buildToken()), codes.Internal, `nodeattestor(gcp_iit): metadata "allowed" exceeded value limit (20 > 10)`)
}

func (s *IITAttestorSuite) TestAttestSuccessWithEmptyInstanceMetadata() {
	s.attestor = s.loadPluginForInstanceMetadata(&compute.Instance{})

	result, err := s.attestor.Attest(context.Background(), s.signToken(buildToken()), expectNoChallenge)
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

	s.requireAttestError(s.T(), s.signToken(buildToken()), codes.Internal, "nodeattestor(gcp_iit): failed to fetch instance metadata: no instance found")
}

func (s *IITAttestorSuite) TestAttestSuccessWithCustomSPIFFEIDTemplate() {
	attestor := s.loadPluginWithConfig(`
projectid_allow_list = ["test-project"]
agent_path_template = "{{ .InstanceID }}"
`)

	token := buildToken()
	expectSVID := "spiffe://example.org/spire/agent/test-instance-id"

	payload := s.signToken(token)
	result, err := attestor.Attest(context.Background(), payload, expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(result)
	s.Require().Equal(expectSVID, result.AgentID)
}

func (s *IITAttestorSuite) TestConfigure() {
	doConfig := func(coreConfig catalog.CoreConfig, config string) error {
		var err error
		plugintest.Load(s.T(), BuiltIn(), nil,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev0.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(config),
		)
		return err
	}

	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}

	s.T().Run("malformed", func(t *testing.T) {
		err := doConfig(coreConfig, "trust_domain")
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "unable to decode configuration")
	})

	s.T().Run("missing trust domain", func(t *testing.T) {
		err := doConfig(catalog.CoreConfig{}, `
projectid_allow_list = ["bar"]
		`)
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "trust_domain is required")
	})

	s.T().Run("missing projectID allow list", func(t *testing.T) {
		err := doConfig(coreConfig, "")
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "projectid_allow_list is required")
	})

	s.T().Run("success", func(t *testing.T) {
		err := doConfig(coreConfig, `
projectid_allow_list = ["bar"]
		`)
		require.NoError(t, err)
	})
}

func (s *IITAttestorSuite) TestFailToRecvStream() {
	_, err := validateAttestationAndExtractIdentityMetadata(&recvFailStream{}, testKeyRetriever{})
	s.Require().EqualError(err, "failed to recv from stream")
}

func (s *IITAttestorSuite) loadPlugin() nodeattestor.NodeAttestor {
	return s.loadPluginWithConfig(`
projectid_allow_list = ["test-project"]
	`)
}

func (s *IITAttestorSuite) loadPluginWithConfig(config string) nodeattestor.NodeAttestor {
	p := New()
	p.tokenKeyRetriever = testKeyRetriever{}
	p.client = s.client

	v1 := new(nodeattestor.V1)
	plugintest.Load(s.T(), builtin(p), v1,
		plugintest.HostServices(agentstorev0.AgentStoreServiceServer(s.agentStore)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.HostServices(agentstorev0.AgentStoreServiceServer(s.agentStore)),
		plugintest.Configure(config),
	)

	return v1
}

func (s *IITAttestorSuite) signToken(token *jwt.Token) []byte {
	signedToken, err := token.SignedString(testKey)
	s.Require().NoError(err)
	return []byte(signedToken)
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

func (testKeyRetriever) retrieveKey(token *jwt.Token) (interface{}, error) {
	if token.Header["kid"] == nil {
		return nil, errors.New("identity token missing kid header")
	}
	return &testKey.PublicKey, nil
}

func buildClaims(projectID string, audience string) jwt.MapClaims {
	return jwt.MapClaims{
		"google": &gcp.Google{
			ComputeEngine: gcp.ComputeEngine{
				ProjectID:    projectID,
				InstanceID:   testInstanceID,
				InstanceName: testInstanceName,
				Zone:         testZone,
			},
		},
		"aud": audience,
	}
}

func buildDefaultClaims() jwt.MapClaims {
	return buildClaims("test-project", tokenAudience)
}

func buildToken() *jwt.Token {
	return buildTokenWithClaims(buildDefaultClaims())
}

func buildTokenWithClaims(claims jwt.Claims) *jwt.Token {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "123"
	return token
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

func (c *fakeComputeEngineClient) fetchInstanceMetadata(ctx context.Context, projectID, zone, instanceName string, serviceAccountFile string) (*compute.Instance, error) {
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

func expectNoChallenge(ctx context.Context, challenge []byte) ([]byte, error) {
	return nil, errors.New("challenge is not expected")
}
