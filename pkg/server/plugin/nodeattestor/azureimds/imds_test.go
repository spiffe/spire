package azureimds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testVMID           = "550e8400-e29b-41d4-a716-446655440000"
	testSubscriptionID = "SUBSCRIPTIONID"
	testTenantID       = "TENANTID"
	testTenantDomain   = "example.com"
	testVMSSName       = "myvmss"
)

var (
	testVMSelectors = []string{
		"resource-group:RESOURCEGROUP",
		"subscription-id:SUBSCRIPTIONID",
		"vm-location:westus",
		"vm-name:VIRTUALMACHINE",
	}
)

func TestIMDSAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(IMDSAttestorSuite))
}

type IMDSAttestorSuite struct {
	spiretest.Suite

	attestor                nodeattestor.NodeAttestor
	agentStore              *fakeagentstore.AgentStore
	api                     *fakeAPIClient
	sharedNonce             string // Captures the latest challenge nonce for assertions
	lastValidatedDoc        *azure.AttestedDocument
	lastValidatedDocContent *azure.AttestedDocumentContent
}

func (s *IMDSAttestorSuite) SetupTest() {
	s.agentStore = fakeagentstore.New()
	s.api = newFakeAPIClient(s.T())
	s.sharedNonce = ""
	s.lastValidatedDoc = nil
	s.lastValidatedDocContent = nil
	s.attestor = s.loadPlugin()
}

func (s *IMDSAttestorSuite) TestAttestFailsWhenNotConfigured() {
	attestor := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), attestor,
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
	)
	s.attestor = attestor
	s.requireAttestError(s.T(), []byte("payload"), codes.FailedPrecondition, "nodeattestor(azure_imds): not configured")
}

func (s *IMDSAttestorSuite) TestAttestFailsWithMalformedPayload() {
	// The malformed payload needs to be in the challenge response, not the initial payload
	malformedChallengeHandler := makeChallengeHandlerWithNonceCapture(&s.sharedNonce, func(ctx context.Context, challenge []byte) ([]byte, error) {
		return []byte("{invalid json"), nil
	})
	attestor := s.loadPluginWithChallengeHandler(malformedChallengeHandler, nil)
	payload := []byte("initial")
	result, err := attestor.Attest(context.Background(), payload, malformedChallengeHandler)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.InvalidArgument, "nodeattestor(azure_imds): failed to unmarshal data payload")
	require.Nil(s.T(), result)
}

func (s *IMDSAttestorSuite) TestAttestFailsWithDocumentValidationError() {
	attestor := s.loadPluginWithDocValidation(func(ctx context.Context, doc *azure.AttestedDocument) (*azure.AttestedDocumentContent, error) {
		return nil, errors.New("document validation failed")
	})

	payload := []byte("initial")
	s.requireAttestErrorWithAttestor(s.T(), attestor, payload, codes.InvalidArgument, "nodeattestor(azure_imds): failed to validate attested document")
}

func (s *IMDSAttestorSuite) TestAttestFailsWithMissingVMID() {
	attestor := s.loadPluginWithDocValidation(func(ctx context.Context, doc *azure.AttestedDocument) (*azure.AttestedDocumentContent, error) {
		return &azure.AttestedDocumentContent{
			VMID:           "",
			SubscriptionID: testSubscriptionID,
			Nonce:          "nonce",
		}, nil
	})

	payload := []byte("initial")
	s.requireAttestErrorWithAttestor(s.T(), attestor, payload, codes.InvalidArgument, "nodeattestor(azure_imds): missing VM ID in attested document")
}

func (s *IMDSAttestorSuite) TestAttestFailsWithInvalidVMID() {
	attestor := s.loadPluginWithDocValidation(func(ctx context.Context, doc *azure.AttestedDocument) (*azure.AttestedDocumentContent, error) {
		return &azure.AttestedDocumentContent{
			VMID:           "not-a-uuid",
			SubscriptionID: testSubscriptionID,
			Nonce:          "nonce",
		}, nil
	})

	payload := []byte("initial")
	s.requireAttestErrorWithAttestor(s.T(), attestor, payload, codes.InvalidArgument, "nodeattestor(azure_imds): invalid VM ID")
}

func (s *IMDSAttestorSuite) TestAttestFailsWithMissingSubscriptionID() {
	attestor := s.loadPluginWithDocValidation(func(ctx context.Context, doc *azure.AttestedDocument) (*azure.AttestedDocumentContent, error) {
		return &azure.AttestedDocumentContent{
			VMID:           testVMID,
			SubscriptionID: "",
			Nonce:          "nonce",
		}, nil
	})

	payload := []byte("initial")
	s.requireAttestErrorWithAttestor(s.T(), attestor, payload, codes.InvalidArgument, "nodeattestor(azure_imds): missing subscription ID in attested document")
}

func (s *IMDSAttestorSuite) TestAttestFailsWithNonceMismatch() {
	// Create a challenge handler that embeds the wrong nonce in the attested document
	badChallengeHandler := func(ctx context.Context, challenge []byte) ([]byte, error) {
		nonce := string(challenge)
		return makeAttestPayloadWithNonce(testVMID, testSubscriptionID, nonce+"-mismatch", testTenantDomain, nil), nil
	}
	challengeHandler := makeChallengeHandlerWithNonceCapture(&s.sharedNonce, badChallengeHandler)
	attestor := s.loadPluginWithChallengeHandler(challengeHandler, nil)

	payload := []byte("initial") // Initial payload doesn't matter, challenge will be sent
	s.lastValidatedDocContent = nil
	result, err := attestor.Attest(context.Background(), payload, challengeHandler)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.InvalidArgument, "nodeattestor(azure_imds): nonce mismatch")
	require.Nil(s.T(), result)
	s.Require().NotNil(s.lastValidatedDocContent, "expected attested document to be parsed before nonce mismatch")
	s.Require().Equal(s.sharedNonce+"-mismatch", s.lastValidatedDocContent.Nonce)
}

func (s *IMDSAttestorSuite) TestAttestFailsWithUnauthorizedTenant() {
	// Use a challenge handler that sets unauthorized tenant in metadata
	unauthorizedChallengeHandler := makeChallengeHandlerWithNonceCapture(&s.sharedNonce, func(ctx context.Context, challenge []byte) ([]byte, error) {
		nonce := string(challenge)
		return makeAttestPayloadWithNonce(testVMID, testSubscriptionID, nonce, "unauthorized.com", nil), nil
	})

	// Create an attestor with the unauthorized challenge handler
	attestorUnauthorized := s.loadPluginWithChallengeHandler(
		unauthorizedChallengeHandler,
		nil,
		plugintest.Configure(`
			tenants = {
				"example.com" = {}
			}
		`),
	)

	payload := []byte("initial")
	s.lastValidatedDocContent = nil
	result, err := attestorUnauthorized.Attest(context.Background(), payload, unauthorizedChallengeHandler)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.PermissionDenied, "nodeattestor(azure_imds): tenant \"unauthorized.com\" is not authorized")
	require.Nil(s.T(), result)
	s.Require().NotNil(s.lastValidatedDocContent, "expected attested document to be validated before tenant authorization failure")
	s.Require().Equal(s.sharedNonce, s.lastValidatedDocContent.Nonce)
}

func (s *IMDSAttestorSuite) TestAttestFailsWhenAttestedBefore() {
	agentID := fmt.Sprintf("spiffe://example.org/spire/agent/azure_imds/%s/%s/%s", testTenantID, testSubscriptionID, testVMID)
	s.agentStore.SetAgentInfo(&agentstorev1.AgentInfo{
		AgentId: agentID,
	})

	payload := []byte("initial")
	s.requireAttestError(s.T(), payload, codes.PermissionDenied, "nodeattestor(azure_imds): attestation data has already been used to attest an agent")
}

func (s *IMDSAttestorSuite) TestAttestFailsWhenVMNotFound() {
	payload := []byte("initial")
	s.requireAttestError(s.T(), payload, codes.Unknown, "not found")
}

func (s *IMDSAttestorSuite) TestAttestFailsWithDisallowedSubscription() {
	s.attestor = s.loadPluginWithConfig(`
		tenants = {
			"example.com" = {
				restrict_to_subscriptions = ["another-subscription"]
			}
		}
	`)

	payload := []byte("initial")
	s.requireAttestError(s.T(), payload, codes.PermissionDenied, `nodeattestor(azure_imds): subscription "SUBSCRIPTIONID" is not authorized`)
}

func (s *IMDSAttestorSuite) TestAttestSuccessWithRegularVM() {
	s.setVirtualMachine(&VirtualMachine{
		Name:          "VIRTUALMACHINE",
		Location:      "westus",
		ResourceGroup: "RESOURCEGROUP",
	})

	agentID := fmt.Sprintf("spiffe://example.org/spire/agent/azure_imds/%s/%s/%s", testTenantID, testSubscriptionID, testVMID)

	selectorValues := slices.Clone(testVMSelectors)
	sort.Strings(selectorValues)

	var expected []*common.Selector
	for _, selectorValue := range selectorValues {
		expected = append(expected, &common.Selector{
			Type:  "azure_imds",
			Value: selectorValue,
		})
	}

	payload := []byte("initial")
	s.requireAttestSuccess(payload, agentID, expected)
}

func (s *IMDSAttestorSuite) TestAttestSuccessWithVMSS() {
	s.setVMSSInstance(&VirtualMachine{
		Name:          "VIRTUALMACHINE",
		Location:      "westus",
		ResourceGroup: "RESOURCEGROUP",
	})

	agentID := fmt.Sprintf("spiffe://example.org/spire/agent/azure_imds/%s/%s/%s", testTenantID, testSubscriptionID, testVMID)

	selectorValues := slices.Clone(testVMSelectors)
	selectorValues = append(selectorValues, fmt.Sprintf("vmss-name:%s", testVMSSName))
	sort.Strings(selectorValues)

	var expected []*common.Selector
	for _, selectorValue := range selectorValues {
		expected = append(expected, &common.Selector{
			Type:  "azure_imds",
			Value: selectorValue,
		})
	}

	// Create challenge handler that includes VMSS name in metadata
	vmssChallengeHandler := makeChallengeHandlerWithNonceCapture(&s.sharedNonce, func(ctx context.Context, challenge []byte) ([]byte, error) {
		nonce := string(challenge)
		vmssName := testVMSSName
		return makeAttestPayloadWithNonce(testVMID, testSubscriptionID, nonce, testTenantDomain, &vmssName), nil
	})

	attestor := s.loadPluginWithChallengeHandler(vmssChallengeHandler, nil)

	payload := []byte("initial")
	resp, err := attestor.Attest(context.Background(), payload, vmssChallengeHandler)
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Equal(agentID, resp.AgentID)
	s.RequireProtoListEqual(expected, resp.Selectors)
}

func (s *IMDSAttestorSuite) TestAttestSuccessWithRestrictedSubscription() {
	s.setVirtualMachine(&VirtualMachine{
		Name:          "VIRTUALMACHINE",
		Location:      "westus",
		ResourceGroup: "RESOURCEGROUP",
	})

	s.attestor = s.loadPluginWithConfig(`
		tenants = {
			"example.com" = {
				restrict_to_subscriptions = ["` + testSubscriptionID + `"]
			}
		}
	`)

	agentID := fmt.Sprintf("spiffe://example.org/spire/agent/azure_imds/%s/%s/%s", testTenantID, testSubscriptionID, testVMID)

	selectorValues := slices.Clone(testVMSelectors)
	sort.Strings(selectorValues)

	var expected []*common.Selector
	for _, selectorValue := range selectorValues {
		expected = append(expected, &common.Selector{
			Type:  "azure_imds",
			Value: selectorValue,
		})
	}

	payload := []byte("initial")
	s.requireAttestSuccess(payload, agentID, expected)
}

func (s *IMDSAttestorSuite) TestAttestFailsWhenVMSSInstanceNotFound() {
	vmssChallengeHandler := makeChallengeHandlerWithNonceCapture(&s.sharedNonce, func(ctx context.Context, challenge []byte) ([]byte, error) {
		nonce := string(challenge)
		vmssName := testVMSSName
		return makeAttestPayloadWithNonce(testVMID, testSubscriptionID, nonce, testTenantDomain, &vmssName), nil
	})
	attestor := s.loadPluginWithChallengeHandler(vmssChallengeHandler, nil)

	payload := []byte("initial")
	result, err := attestor.Attest(context.Background(), payload, vmssChallengeHandler)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.Unknown, "not found")
	require.Nil(s.T(), result)
}

func (s *IMDSAttestorSuite) TestAttestSuccessWithCustomAgentPathTemplate() {
	s.setVirtualMachine(&VirtualMachine{
		Name:          "VIRTUALMACHINE",
		Location:      "westus",
		ResourceGroup: "RESOURCEGROUP",
	})

	attestorWithCustomTemplate := s.loadPluginWithConfig(`
		tenants = {
			"example.com" = {}
		}
		agent_path_template = "/{{ .PluginName }}/{{ .TenantID }}"
	`)

	selectorValues := slices.Clone(testVMSelectors)
	sort.Strings(selectorValues)

	var expected []*common.Selector
	for _, selectorValue := range selectorValues {
		expected = append(expected, &common.Selector{
			Type:  "azure_imds",
			Value: selectorValue,
		})
	}

	payload := []byte("initial")
	challengeHandler := makeChallengeHandlerWithNonceCapture(&s.sharedNonce, expectChallengeResponse)
	resp, err := attestorWithCustomTemplate.Attest(context.Background(), payload, challengeHandler)
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Equal(fmt.Sprintf("spiffe://example.org/spire/agent/azure_imds/%s", testTenantID), resp.AgentID)
	s.RequireProtoListEqual(expected, resp.Selectors)
}

func (s *IMDSAttestorSuite) TestAttestIncludesOnlyAllowedTags() {
	s.setVirtualMachine(&VirtualMachine{
		Name:          "VIRTUALMACHINE",
		Location:      "westus",
		ResourceGroup: "RESOURCEGROUP",
		Tags: map[string]any{
			"env":   "prod",
			"team":  "alpha",
			"extra": "ignore",
		},
	})

	s.attestor = s.loadPluginWithConfig(`
		tenants = {
			"example.com" = {
				allowed_vm_tags = ["env", "team"]
			}
		}
	`)

	agentID := fmt.Sprintf("spiffe://example.org/spire/agent/azure_imds/%s/%s/%s", testTenantID, testSubscriptionID, testVMID)

	selectorValues := slices.Clone(testVMSelectors)
	selectorValues = append(selectorValues,
		"vm-tag:env:prod",
		"vm-tag:team:alpha",
	)
	sort.Strings(selectorValues)

	var expected []*common.Selector
	for _, selectorValue := range selectorValues {
		expected = append(expected, &common.Selector{
			Type:  "azure_imds",
			Value: selectorValue,
		})
	}

	payload := []byte("initial")
	s.requireAttestSuccess(payload, agentID, expected)
}

func (s *IMDSAttestorSuite) TestConfigure() {
	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}

	s.T().Run("malformed configuration", func(t *testing.T) {
		attestor := s.newTestAttestor()

		v1 := new(nodeattestor.V1)
		var err error
		plugintest.Load(t, builtin(attestor), v1,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure("blah"),
		)
		spiretest.RequireErrorContains(t, err, "unable to decode configuration")
	})

	s.T().Run("missing tenants", func(t *testing.T) {
		attestor := s.newTestAttestor()

		v1 := new(nodeattestor.V1)
		var err error
		plugintest.Load(t, builtin(attestor), v1,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(""),
		)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "configuration must have at least one tenant")
	})

	s.T().Run("both secret_auth and token_auth specified", func(t *testing.T) {
		attestor := s.newTestAttestor()

		v1 := new(nodeattestor.V1)
		var err error
		plugintest.Load(t, builtin(attestor), v1,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(`
				tenants = {
					"example.com" = {
						secret_auth = {
							app_id = "APPID"
							app_secret = "SECRET"
						}
						token_auth = {
							app_id = "APPID"
							token_path = "/path/to/token"
						}
					}
				}
			`),
		)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, `misconfigured tenant`)
	})

	s.T().Run("token auth missing token_path", func(t *testing.T) {
		attestor := s.newTestAttestor()

		v1 := new(nodeattestor.V1)
		var err error
		plugintest.Load(t, builtin(attestor), v1,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(`
				tenants = {
					"example.com" = {
						token_auth = {
							app_id = "APPID"
						}
					}
				}
			`),
		)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, `missing token file path`)
	})

	s.T().Run("token auth missing app_id", func(t *testing.T) {
		attestor := s.newTestAttestor()

		v1 := new(nodeattestor.V1)
		var err error
		plugintest.Load(t, builtin(attestor), v1,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(`
				tenants = {
					"example.com" = {
						token_auth = {
							token_path = "/path/to/token"
						}
					}
				}
			`),
		)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, `missing app id`)
	})

	s.T().Run("secret auth missing app_id", func(t *testing.T) {
		attestor := s.newTestAttestor()

		v1 := new(nodeattestor.V1)
		var err error
		plugintest.Load(t, builtin(attestor), v1,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(`
				tenants = {
					"example.com" = {
						secret_auth = {
							app_secret = "SECRET"
						}
					}
				}
			`),
		)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, `missing app id`)
	})

	s.T().Run("secret auth missing app_secret", func(t *testing.T) {
		attestor := s.newTestAttestor()

		v1 := new(nodeattestor.V1)
		var err error
		plugintest.Load(t, builtin(attestor), v1,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(`
				tenants = {
					"example.com" = {
						secret_auth = {
							app_id = "APPID"
						}
					}
				}
			`),
		)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, `missing app id`)
	})

	s.T().Run("success with default credential", func(t *testing.T) {
		attestor := s.newTestAttestor()

		v1 := new(nodeattestor.V1)
		var err error
		plugintest.Load(t, builtin(attestor), v1,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(`
				tenants = {
					"example.com" = {}
				}
			`),
		)
		require.NoError(t, err)
	})

	s.T().Run("success with secret auth", func(t *testing.T) {
		attestor := s.newTestAttestor()

		v1 := new(nodeattestor.V1)
		var err error
		plugintest.Load(t, builtin(attestor), v1,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(`
				tenants = {
					"example.com" = {
						secret_auth = {
							app_id = "APPID"
							app_secret = "SECRET"
						}
					}
				}
			`),
		)
		require.NoError(t, err)
	})

	s.T().Run("success with token auth", func(t *testing.T) {
		attestor := s.newTestAttestor()

		v1 := new(nodeattestor.V1)
		var err error
		plugintest.Load(t, builtin(attestor), v1,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(`
				tenants = {
					"example.com" = {
						token_auth = {
							app_id = "APPID"
							token_path = "/path/to/token"
						}
					}
				}
			`),
		)
		require.NoError(t, err)
	})

	s.T().Run("success with multiple tenants", func(t *testing.T) {
		attestor := s.newTestAttestor()
		attestor.hooks.lookupTenantID = func(domain string) (string, error) {
			if domain == "example.com" {
				return testTenantID, nil
			}
			return "TENANTID2", nil
		}

		v1 := new(nodeattestor.V1)
		var err error
		plugintest.Load(t, builtin(attestor), v1,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(`
				tenants = {
					"example.com" = {}
					"example2.com" = {}
				}
			`),
		)
		require.NoError(t, err)
	})
}

func (s *IMDSAttestorSuite) TestValidate() {
	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}

	s.T().Run("invalid configuration", func(t *testing.T) {
		attestor := s.newTestAttestor()

		// Load with valid config first
		plugintest.Load(t, builtin(attestor), nil,
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(`
				tenants = {
					"example.com" = {}
				}
			`),
			plugintest.CaptureLoadError(nil),
		)

		// Then test Validate with invalid config
		resp, err := attestor.Validate(context.Background(), &configv1.ValidateRequest{
			HclConfiguration: "blah",
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.Valid)
		require.NotEmpty(t, resp.Notes)
	})

	s.T().Run("valid configuration", func(t *testing.T) {
		attestor := s.newTestAttestor()

		plugintest.Load(t, builtin(attestor), nil,
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(`
				tenants = {
					"example.com" = {}
				}
			`),
			plugintest.CaptureLoadError(nil),
		)

		resp, err := attestor.Validate(context.Background(), &configv1.ValidateRequest{
			CoreConfiguration: &configv1.CoreConfiguration{
				TrustDomain: "example.org",
			},
			HclConfiguration: `
				tenants = {
					"example.com" = {}
				}
			`,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.Valid)
	})
}

func (s *IMDSAttestorSuite) requireAttestSuccess(payload []byte, expectID string, expectSelectors []*common.Selector) {
	s.lastValidatedDoc = nil
	s.lastValidatedDocContent = nil
	challengeHandler := makeChallengeHandlerWithNonceCapture(&s.sharedNonce, expectChallengeResponse)
	resp, err := s.attestor.Attest(context.Background(), payload, challengeHandler)
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Equal(expectID, resp.AgentID)
	s.RequireProtoListEqual(expectSelectors, resp.Selectors)
	s.Require().NotNil(s.lastValidatedDoc, "expected attested document to be validated")
	s.Require().NotNil(s.lastValidatedDocContent, "expected attested document content to be captured")
	s.Require().Equal(testVMID, s.lastValidatedDocContent.VMID)
	s.Require().Equal(testSubscriptionID, s.lastValidatedDocContent.SubscriptionID)
	s.Require().Equal(s.sharedNonce, s.lastValidatedDocContent.Nonce)
}

func (s *IMDSAttestorSuite) requireAttestError(t *testing.T, payload []byte, expectCode codes.Code, expectMsg string) {
	s.requireAttestErrorWithAttestor(t, s.attestor, payload, expectCode, expectMsg)
}

func (s *IMDSAttestorSuite) requireAttestErrorWithAttestor(t *testing.T, attestor nodeattestor.NodeAttestor, payload []byte, expectCode codes.Code, expectMsg string) {
	s.lastValidatedDoc = nil
	s.lastValidatedDocContent = nil
	challengeHandler := makeChallengeHandlerWithNonceCapture(&s.sharedNonce, expectChallengeResponse)
	result, err := attestor.Attest(context.Background(), payload, challengeHandler)
	spiretest.RequireGRPCStatusContains(t, err, expectCode, expectMsg)
	require.Nil(t, result)
}

func (s *IMDSAttestorSuite) loadPlugin(options ...plugintest.Option) nodeattestor.NodeAttestor {
	return s.loadPluginWithConfig(`
		tenants = {
			"example.com" = {}
		}
	`, options...)
}

func (s *IMDSAttestorSuite) loadPluginWithConfig(config string, options ...plugintest.Option) nodeattestor.NodeAttestor {
	challengeHandler := makeChallengeHandlerWithNonceCapture(&s.sharedNonce, expectChallengeResponse)
	return s.loadPluginWithChallengeHandler(challengeHandler, nil, append([]plugintest.Option{
		plugintest.Configure(config),
	}, options...)...)
}

func (s *IMDSAttestorSuite) loadPluginWithChallengeHandler(
	challengeFn func(context.Context, []byte) ([]byte, error),
	docValidationFn func(context.Context, *azure.AttestedDocument) (*azure.AttestedDocumentContent, error),
	options ...plugintest.Option,
) nodeattestor.NodeAttestor {
	attestor := s.newTestAttestor()
	attestor.hooks.lookupTenantID = func(domain string) (string, error) {
		if domain == "example.com" {
			return testTenantID, nil
		}
		return domain, nil
	}
	attestor.hooks.validateAttestedDoc = func(ctx context.Context, doc *azure.AttestedDocument) (*azure.AttestedDocumentContent, error) {
		s.lastValidatedDoc = doc
		var (
			content *azure.AttestedDocumentContent
			err     error
		)
		if docValidationFn != nil {
			content, err = docValidationFn(ctx, doc)
		} else {
			content, err = s.parseTestDocument(doc)
		}
		if err != nil {
			return nil, err
		}
		s.lastValidatedDocContent = content
		return content, nil
	}
	_ = challengeFn // challengeFn is used by individual tests, not stored here

	v1 := new(nodeattestor.V1)
	plugintest.Load(s.T(), builtin(attestor), v1, append([]plugintest.Option{
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`
			tenants = {
				"example.com" = {}
			}
		`),
	}, options...)...)
	return v1
}

func (s *IMDSAttestorSuite) loadPluginWithDocValidation(validateFunc func(context.Context, *azure.AttestedDocument) (*azure.AttestedDocumentContent, error)) nodeattestor.NodeAttestor {
	challengeHandler := makeChallengeHandlerWithNonceCapture(&s.sharedNonce, expectChallengeResponse)
	docValidation := func(ctx context.Context, doc *azure.AttestedDocument) (*azure.AttestedDocumentContent, error) {
		content, err := validateFunc(ctx, doc)
		if err != nil {
			return nil, err
		}
		if content != nil && s.sharedNonce != "" {
			content.Nonce = s.sharedNonce
		}
		return content, nil
	}
	return s.loadPluginWithChallengeHandler(challengeHandler, docValidation)
}

func (s *IMDSAttestorSuite) setVirtualMachine(vm *VirtualMachine) {
	s.api.SetVirtualMachine(testVMID, testSubscriptionID, vm)
}

func (s *IMDSAttestorSuite) setVMSSInstance(vm *VirtualMachine) {
	s.api.SetVMSSInstance(testVMID, testSubscriptionID, testVMSSName, vm)
}

func (s *IMDSAttestorSuite) newTestAttestor() *IMDSAttestorPlugin {
	attestor := New()
	attestor.hooks.lookupTenantID = func(string) (string, error) { return testTenantID, nil }
	attestor.hooks.newClient = func(azcore.TokenCredential) (apiClient, error) { return s.api, nil }
	attestor.hooks.fetchCredential = func(string) (azcore.TokenCredential, error) { return &fakeAzureCredential{}, nil }
	return attestor
}

func (s *IMDSAttestorSuite) parseTestDocument(doc *azure.AttestedDocument) (*azure.AttestedDocumentContent, error) {
	content := new(testAttestedDocument)
	if err := json.Unmarshal([]byte(doc.Signature), content); err != nil {
		return nil, fmt.Errorf("failed to unmarshal test document: %w", err)
	}
	return &azure.AttestedDocumentContent{
		VMID:           content.VMID,
		SubscriptionID: content.SubscriptionID,
		Nonce:          content.Nonce,
	}, nil
}

type fakeAPIClient struct {
	t testing.TB

	virtualMachines map[string]*VirtualMachine
	vmssInstances   map[string]*VirtualMachine
}

func newFakeAPIClient(t testing.TB) *fakeAPIClient {
	return &fakeAPIClient{
		t:               t,
		virtualMachines: make(map[string]*VirtualMachine),
		vmssInstances:   make(map[string]*VirtualMachine),
	}
}

func (c *fakeAPIClient) SetVirtualMachine(vmID, subscriptionID string, vm *VirtualMachine) {
	key := fmt.Sprintf("%s:%s", vmID, subscriptionID)
	c.virtualMachines[key] = vm
}

func (c *fakeAPIClient) GetVirtualMachine(_ context.Context, vmID string, subscriptionID *string) (*VirtualMachine, error) {
	var key string
	if subscriptionID != nil {
		key = fmt.Sprintf("%s:%s", vmID, *subscriptionID)
	} else {
		key = fmt.Sprintf("%s:", vmID)
	}
	vm := c.virtualMachines[key]
	if vm == nil {
		return nil, errors.New("not found")
	}
	return vm, nil
}

func (c *fakeAPIClient) SetVMSSInstance(vmID, subscriptionID, vmssName string, vm *VirtualMachine) {
	key := fmt.Sprintf("%s:%s:%s", vmID, subscriptionID, vmssName)
	c.vmssInstances[key] = vm
}

func (c *fakeAPIClient) GetVMSSInstance(_ context.Context, vmID, subscriptionID, vmssName string) (*VirtualMachine, error) {
	key := fmt.Sprintf("%s:%s:%s", vmID, subscriptionID, vmssName)
	vm := c.vmssInstances[key]
	if vm == nil {
		return nil, errors.New("not found")
	}
	return vm, nil
}

type fakeAzureCredential struct{}

func (f *fakeAzureCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

type testAttestedDocument struct {
	VMID           string `json:"vm_id"`
	SubscriptionID string `json:"subscription_id"`
	Nonce          string `json:"nonce"`
}

func makeAttestPayloadWithNonce(vmID, subscriptionID, nonce, agentDomain string, vmssName *string) []byte { //nolint: unparam
	docBytes, _ := json.Marshal(testAttestedDocument{
		VMID:           vmID,
		SubscriptionID: subscriptionID,
		Nonce:          nonce,
	})
	payload := azure.IMDSAttestationPayload{
		Document: azure.AttestedDocument{
			Encoding:  "test-json",
			Signature: string(docBytes),
		},
		Metadata: azure.AgentUntrustedMetadata{
			AgentDomain: agentDomain,
			VMSSName:    vmssName,
		},
	}
	data, _ := json.Marshal(payload)
	return data
}

// expectChallengeResponse handles the challenge/response flow for IMDS attestation
// It captures the nonce from the challenge and returns a proper attestation payload
func expectChallengeResponse(ctx context.Context, challenge []byte) ([]byte, error) {
	nonce := string(challenge)
	// Create attestation payload with the nonce embedded
	return makeAttestPayloadWithNonce(testVMID, testSubscriptionID, nonce, testTenantDomain, nil), nil
}

// makeChallengeHandlerWithNonceCapture creates a challenge handler that captures the nonce
// and stores it in the provided storage pointer, then calls the underlying handler
func makeChallengeHandlerWithNonceCapture(
	storage *string,
	underlying func(context.Context, []byte) ([]byte, error),
) func(context.Context, []byte) ([]byte, error) {
	return func(ctx context.Context, challenge []byte) ([]byte, error) {
		if storage != nil {
			*storage = string(challenge)
		}
		if underlying != nil {
			return underlying(ctx, challenge)
		}
		return expectChallengeResponse(ctx, challenge)
	}
}
