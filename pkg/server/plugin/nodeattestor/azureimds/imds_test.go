package azureimds

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/jwtutil"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testKeyID    = "KEYID"
	resourceID   = "https://example.org/app/"
	vmResourceID = "/subscriptions/SUBSCRIPTIONID/resourceGroups/RESOURCEGROUP/providers/Microsoft.Compute/virtualMachines/VIRTUALMACHINE"
)

var (
	niResourceID        = "/subscriptions/SUBSCRIPTIONID/resourceGroups/RESOURCEGROUP/providers/Microsoft.Network/networkInterfaces/NETWORKINTERFACE"
	nsgResourceID       = "/subscriptions/SUBSCRIPTIONID/resourceGroups/NSGRESOURCEGROUP/providers/Microsoft.Network/networkSecurityGroups/NETWORKSECURITYGROUP"
	subnetResourceID    = "/subscriptions/SUBSCRIPTIONID/resourceGroups/NETRESOURCEGROUP/providers/Microsoft.Network/virtualNetworks/VIRTUALNETWORK/subnets/SUBNET"
	malformedResourceID = "MALFORMEDRESOURCEID"
	vmSelectors         = []string{
		"subscription-id:SUBSCRIPTIONID",
		"vm-name:RESOURCEGROUP:VIRTUALMACHINE",
	}
	niSelectors = []string{
		"network-security-group:NSGRESOURCEGROUP:NETWORKSECURITYGROUP",
		"virtual-network:NETRESOURCEGROUP:VIRTUALNETWORK",
		"virtual-network-subnet:NETRESOURCEGROUP:VIRTUALNETWORK:SUBNET",
	}
	instanceMetadata = &azure.InstanceMetadata{Compute: azure.ComputeMetadata{SubscriptionID: "SUBSCRIPTIONID"}}
	testToken        = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"
)

func TestMSIAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(MSIAttestorSuite))
}

type MSIAttestorSuite struct {
	spiretest.Suite

	attestor   nodeattestor.NodeAttestor
	key        *rsa.PrivateKey
	jwks       *jose.JSONWebKeySet
	now        time.Time
	agentStore *fakeagentstore.AgentStore
	api        *fakeAPIClient
}

func (s *MSIAttestorSuite) SetupSuite() {
	s.key = testkey.NewRSA2048(s.T())
}

func (s *MSIAttestorSuite) SetupTest() {
	s.jwks = &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:   s.key.Public(),
				KeyID: testKeyID,
			},
		},
	}
	s.now = time.Now()
	s.agentStore = fakeagentstore.New()
	s.api = newFakeAPIClient(s.T())
	s.attestor = s.loadPlugin()
}

func (s *MSIAttestorSuite) TestAttestFailsWhenNotConfigured() {
	attestor := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), attestor,
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
	)
	s.attestor = attestor
	s.requireAttestError(s.T(), []byte("payload"), codes.FailedPrecondition, "nodeattestor(azure_msi): not configured")
}

func (s *MSIAttestorSuite) TestAttestFailsWithNoAttestationDataPayload() {
	s.requireAttestError(s.T(), nil, codes.InvalidArgument, "payload cannot be empty")
}

func (s *MSIAttestorSuite) TestAttestFailsWithMalformedAttestationDataPayload() {
	s.requireAttestError(s.T(), []byte("{"), codes.InvalidArgument, "nodeattestor(azure_msi): failed to unmarshal data payload")
}

func (s *MSIAttestorSuite) TestAttestFailsWithNoToken() {
	s.requireAttestError(s.T(), makeAttestPayload(""),
		codes.InvalidArgument,
		"nodeattestor(azure_msi): missing token from attestation data")
}

func (s *MSIAttestorSuite) TestAttestFailsWithMalformedToken() {
	s.requireAttestError(s.T(), makeAttestPayload("blah"),
		codes.InvalidArgument,
		"nodeattestor(azure_msi): unable to parse token")
}

func (s *MSIAttestorSuite) TestAttestFailsIfTokenKeyIDMissing() {
	s.requireAttestError(s.T(), s.signAttestPayload("", "", "", ""),
		codes.InvalidArgument,
		"nodeattestor(azure_msi): token missing key id")
}

func (s *MSIAttestorSuite) TestAttestFailsIfTokenKeyIDNotFound() {
	s.jwks.Keys = nil
	s.requireAttestError(s.T(), s.signAttestPayload("KEYID", "", "", ""),
		codes.InvalidArgument,
		`nodeattestor(azure_msi): key id "KEYID" not found`)
}

func (s *MSIAttestorSuite) TestAttestFailsWithBadSignature() {
	// sign a token and replace the signature
	token := s.signToken("KEYID", "", "", "")
	parts := strings.Split(token, ".")
	s.Require().Len(parts, 3)
	parts[2] = "aaaa"
	token = strings.Join(parts, ".")

	s.requireAttestError(s.T(), makeAttestPayload(token),
		codes.InvalidArgument,
		"unable to verify token")
}

func (s *MSIAttestorSuite) TestAttestFailsWithAlgorithmMismatch() {
	// sign a token with a different key algorithm than that of the key in
	// the key set.
	key := testkey.MustEC256()
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			"kid": "KEYID",
		},
	})
	s.Require().NoError(err)

	token, err := jwt.Signed(signer).Serialize()
	s.Require().NoError(err)

	s.requireAttestError(s.T(), makeAttestPayload(token),
		codes.InvalidArgument,
		"unable to verify token")
}

func (s *MSIAttestorSuite) TestAttestFailsClaimValidation() {
	s.T().Run("missing tenant id claim", func(t *testing.T) {
		s.requireAttestError(t, s.signAttestPayload("KEYID", resourceID, "", "PRINCIPALID"),
			codes.Internal,
			"nodeattestor(azure_msi): token missing tenant ID claim")
	})

	s.T().Run("unauthorized tenant id claim", func(t *testing.T) {
		s.requireAttestError(t, s.signAttestPayload("KEYID", resourceID, "BADTENANTID", "PRINCIPALID"),
			codes.PermissionDenied,
			`nodeattestor(azure_msi): tenant "BADTENANTID" is not authorized`)
	})

	s.T().Run("no audience", func(t *testing.T) {
		s.requireAttestError(t, s.signAttestPayload("KEYID", "", "TENANTID", "PRINCIPALID"),
			codes.Internal,
			"nodeattestor(azure_msi): unable to validate token claims: go-jose/go-jose/jwt: validation failed, invalid audience claim (aud)")
	})

	s.T().Run("wrong audience", func(t *testing.T) {
		s.requireAttestError(t, s.signAttestPayload("KEYID", "FOO", "TENANTID", "PRINCIPALID"),
			codes.Internal,
			"nodeattestor(azure_msi): unable to validate token claims: go-jose/go-jose/jwt: validation failed, invalid audience claim (aud)")
	})

	s.T().Run(" missing principal id (sub) claim", func(t *testing.T) {
		s.requireAttestError(t, s.signAttestPayload("KEYID", resourceID, "TENANTID", ""),
			codes.Internal,
			"nodeattestor(azure_msi): token missing subject claim")
	})
}

func (s *MSIAttestorSuite) TestAttestTokenExpiration() {
	token := s.signAttestPayload("KEYID", resourceID, "TENANTID", "PRINCIPALID")

	// within 5m leeway (token expires at 1m + 5m leeway = 6m)
	s.adjustTime(6 * time.Minute)
	_, err := s.attestor.Attest(context.Background(), token, expectNoChallenge)
	s.Require().NotNil(err)

	// just after 5m leeway
	s.adjustTime(time.Second)
	s.requireAttestError(s.T(), token, codes.Internal, "nodeattestor(azure_msi): unable to validate token claims: go-jose/go-jose/jwt: validation failed, token is expired (exp)")
}

func (s *MSIAttestorSuite) TestAttestSuccessWithDefaultResourceID() {
	s.setVirtualMachine(&VirtualMachine{
		Properties: &VirtualMachineProperties{},
	})

	// Success with default resource ID (via TENANTID2)
	s.requireAttestSuccess(
		s.signAttestPayload("KEYID", azure.DefaultMSIResourceID, "TENANTID2", "PRINCIPALID"),
		"spiffe://example.org/spire/agent/azure_msi/TENANTID2/PRINCIPALID",
		vmSelectors)
}

func (s *MSIAttestorSuite) TestAttestSuccessWithCustomResourceID() {
	s.setVirtualMachine(&VirtualMachine{
		Properties: &VirtualMachineProperties{},
	})

	// Success with custom resource ID (via TENANTID)
	s.requireAttestSuccess(
		s.signAttestPayload("KEYID", resourceID, "TENANTID", "PRINCIPALID"),
		"spiffe://example.org/spire/agent/azure_msi/TENANTID/PRINCIPALID",
		vmSelectors)
}

func (s *MSIAttestorSuite) TestAttestSuccessWithCustomSPIFFEIDTemplate() {
	s.setVirtualMachine(&VirtualMachine{
		Properties: &VirtualMachineProperties{},
	})

	payload := s.signAttestPayload("KEYID", resourceID, "TENANTID", "PRINCIPALID")

	selectorValues := slices.Clone(vmSelectors)
	sort.Strings(selectorValues)

	var expected []*common.Selector
	for _, selectorValue := range selectorValues {
		expected = append(expected, &common.Selector{
			Type:  "azure_msi",
			Value: selectorValue,
		})
	}

	attestorWithCustomAgentTemplate := s.loadPluginWithConfig(
		`
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
			}
			"TENANTID2" = { }
		}
		agent_path_template = "/{{ .PluginName }}/{{ .TenantID }}"
	`)
	resp, err := attestorWithCustomAgentTemplate.Attest(context.Background(), payload, expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Equal("spiffe://example.org/spire/agent/azure_msi/TENANTID", resp.AgentID)
	s.RequireProtoListEqual(expected, resp.Selectors)
}

func (s *MSIAttestorSuite) TestAttestFailsWithNoClientCredentials() {
	s.attestor = s.loadPlugin(plugintest.Configure(`
		tenants = {
			"TENANTID" = {}
		}`))

	s.requireAttestError(
		s.T(),
		s.signAttestPayload("KEYID", azure.DefaultMSIResourceID, "TENANTID", "PRINCIPALID"),
		codes.Internal,
		`nodeattestor(azure_msi): unable to get resource for principal "PRINCIPALID": not found`)
}

func (s *MSIAttestorSuite) TestAttestResolutionWithVariousSelectorCombos() {
	payload := s.signAttestPayload("KEYID", resourceID, "TENANTID", "PRINCIPALID")
	agentID := "spiffe://example.org/spire/agent/azure_msi/TENANTID/PRINCIPALID"

	vm := &VirtualMachine{
		Properties: &VirtualMachineProperties{},
	}
	s.setVirtualMachine(vm)

	// no network profile
	s.requireAttestSuccess(payload, agentID, vmSelectors)

	// network profile with no interfaces
	vm.Properties.NetworkProfile = &armcompute.NetworkProfile{}
	s.requireAttestSuccess(payload, agentID, vmSelectors)

	// network profile with empty interface
	vm.Properties.NetworkProfile.NetworkInterfaces = []*armcompute.NetworkInterfaceReference{{}}
	s.requireAttestSuccess(payload, agentID, vmSelectors)

	// network profile with interface with malformed ID
	vm.Properties.NetworkProfile.NetworkInterfaces = []*armcompute.NetworkInterfaceReference{{ID: &malformedResourceID}}
	s.requireAttestError(s.T(), payload,
		codes.Internal,
		`nodeattestor(azure_msi): malformed network interface ID "MALFORMEDRESOURCEID"`)

	// network profile with interface with no interface info
	vm.Properties.NetworkProfile.NetworkInterfaces = []*armcompute.NetworkInterfaceReference{
		{
			ID: &niResourceID,
		},
	}
	s.requireAttestError(s.T(), payload,
		codes.Internal,
		`nodeattestor(azure_msi): unable to get network interface "RESOURCEGROUP:NETWORKINTERFACE"`)

	// network interface with no security group or ip config
	ni := &NetworkInterface{
		Properties: &NetworkInterfacePropertiesFormat{},
	}
	s.setNetworkInterface(ni)
	s.requireAttestSuccess(payload, agentID, vmSelectors)

	// network interface with malformed security group
	ni.Properties.NetworkSecurityGroup = &armnetwork.SecurityGroup{ID: &malformedResourceID}
	s.requireAttestError(s.T(), payload,
		codes.Internal,
		`nodeattestor(azure_msi): malformed network security group ID "MALFORMEDRESOURCEID"`)
	ni.Properties.NetworkSecurityGroup = nil

	// network interface with no ip configuration
	ni.Properties.IPConfigurations = []*NetworkInterfaceIPConfiguration{}
	s.requireAttestSuccess(payload, agentID, vmSelectors)

	// network interface with empty ip configuration
	ni.Properties.IPConfigurations = []*NetworkInterfaceIPConfiguration{{}}
	s.requireAttestSuccess(payload, agentID, vmSelectors)

	// network interface with empty ip configuration properties
	props := new(NetworkInterfaceIPConfigurationPropertiesFormat)
	ni.Properties.IPConfigurations = []*NetworkInterfaceIPConfiguration{{Properties: props}}
	s.requireAttestSuccess(payload, agentID, vmSelectors)

	// network interface with subnet with no ID
	props.Subnet = &armnetwork.Subnet{}
	s.requireAttestSuccess(payload, agentID, vmSelectors)

	// network interface with subnet with malformed ID
	props.Subnet.ID = &malformedResourceID
	s.requireAttestError(s.T(), payload,
		codes.Internal,
		`nodeattestor(azure_msi): malformed virtual network subnet ID "MALFORMEDRESOURCEID"`)

	// network interface with good subnet and security group
	ni.Properties.NetworkSecurityGroup = &armnetwork.SecurityGroup{ID: &nsgResourceID}
	props.Subnet.ID = &subnetResourceID
	s.requireAttestSuccess(payload, agentID, vmSelectors, niSelectors)
}

func (s *MSIAttestorSuite) TestAzureAssertionFunc() {
	goodToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"

	for _, tt := range []struct {
		name          string
		tokenPath     string
		tokenContent  string
		readErr       bool
		expectErr     bool
		expectedToken string
	}{
		{
			name:          "success",
			tokenPath:     "token_path",
			tokenContent:  goodToken,
			expectErr:     false,
			expectedToken: goodToken,
		},
		{
			name:      "read failed",
			tokenPath: "failed_read",
			readErr:   true,
			expectErr: true,
		},
		{
			name:         "bad token",
			tokenPath:    "bad_token_path",
			tokenContent: "bad",
			expectErr:    true,
		},
	} {

		s.T().Run(tt.name, func(t *testing.T) {
			fakeReadFile := func(name string) ([]byte, error) {
				if tt.readErr {
					return nil, errors.New("read failed")
				}
				return []byte(tt.tokenContent), nil
			}

			assertor := getAzureAssertionFunc(tt.tokenPath, fakeReadFile)
			token, err := assertor(context.Background())

			if tt.expectErr {
				require.Error(t, err)
				require.Empty(t, token)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedToken, token)
		})
	}
}

func (s *MSIAttestorSuite) TestAllowedTags() {
	tagSelectors := []string{
		"tag:tag1:value1",
		"tag:tag2:value2",
	}
	testCases := []struct {
		name                   string
		allowedVMTags          string
		expectedSelectorValues []string
		expectedSelectorLen    int
	}{
		{
			name:                   "tags are filtered",
			allowedVMTags:          `["tag1", "tag2"]`,
			expectedSelectorValues: append(slices.Clone(tagSelectors), vmSelectors...),
			expectedSelectorLen:    len(tagSelectors) + len(vmSelectors),
		},
		{
			name:                   "no tags",
			allowedVMTags:          `[]`,
			expectedSelectorValues: vmSelectors,
			expectedSelectorLen:    len(vmSelectors),
		},
		{
			name:                   "one tag",
			allowedVMTags:          `["tag1"]`,
			expectedSelectorValues: append(slices.Clone(vmSelectors), "tag:tag1:value1"),
			expectedSelectorLen:    len(vmSelectors) + 1,
		},
	}

	for _, tc := range testCases {
		s.setVirtualMachine(&VirtualMachine{
			Tags: map[string]*string{
				"tag1": toPointer("value1"),
				"tag2": toPointer("value2"),
				"tag3": toPointer("value3"),
			},
			Properties: &VirtualMachineProperties{},
		})

		payload := s.signAttestPayload("KEYID", resourceID, "TENANTID", "PRINCIPALID")
		s.T().Run(tc.name, func(t *testing.T) {
			s.Suite.T().Helper()
			config := fmt.Sprintf(`
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
				allowed_vm_tags = %s
			}
		}
		`, tc.allowedVMTags)
			p := s.loadPluginWithConfig(config)

			resp, err := p.Attest(context.Background(), payload, expectNoChallenge)
			s.Require().NoError(err)
			s.Require().NotNil(resp)
			s.Require().Equal("spiffe://example.org/spire/agent/azure_msi/TENANTID/PRINCIPALID", resp.AgentID)

			s.Require().Len(resp.Selectors, tc.expectedSelectorLen)
			sort.Strings(tc.expectedSelectorValues)
			var expected []*common.Selector
			for _, selectorValue := range tc.expectedSelectorValues {
				expected = append(expected, &common.Selector{
					Type:  "azure_msi",
					Value: selectorValue,
				})
			}
			s.RequireProtoListEqual(expected, resp.Selectors)
		})
	}
}

func (s *MSIAttestorSuite) TestAttestFailsWhenCannotResolveVirtualMachineResource() {
	s.api.SetVirtualMachineResourceID("PRINCIPALID", "")

	s.requireAttestError(s.T(), s.signAttestPayload("KEYID", resourceID, "TENANTID", "PRINCIPALID"),
		codes.Internal,
		"nodeattestor(azure_msi): unable to get resource for principal \"PRINCIPALID\": not found")
}

func (s *MSIAttestorSuite) TestAttestFailsWithMalformedResourceID() {
	s.api.SetVirtualMachineResourceID("PRINCIPALID", malformedResourceID)

	s.requireAttestError(s.T(), s.signAttestPayload("KEYID", resourceID, "TENANTID", "PRINCIPALID"),
		codes.Internal,
		`nodeattestor(azure_msi): malformed virtual machine ID "MALFORMEDRESOURCEID"`)
}

func (s *MSIAttestorSuite) TestAttestFailsWithNoVirtualMachineInfo() {
	s.api.SetVirtualMachineResourceID("PRINCIPALID", vmResourceID)

	s.requireAttestError(s.T(), s.signAttestPayload("KEYID", resourceID, "TENANTID", "PRINCIPALID"),
		codes.Internal,
		`nodeattestor(azure_msi): unable to get virtual machine "RESOURCEGROUP:VIRTUALMACHINE"`)
}

func (s *MSIAttestorSuite) TestAttestFailsWhenAttestedBefore() {
	agentID := "spiffe://example.org/spire/agent/azure_msi/TENANTID/PRINCIPALID"
	s.agentStore.SetAgentInfo(&agentstorev1.AgentInfo{
		AgentId: agentID,
	})
	s.requireAttestError(s.T(), s.signAttestPayload("KEYID", resourceID, "TENANTID", "PRINCIPALID"),
		codes.PermissionDenied,
		"nodeattestor(azure_msi): attestation data has already been used to attest an agent")
}

func (s *MSIAttestorSuite) TestConfigure() {
	var clients []string
	var logEntries []*logrus.Entry

	type testOpts struct {
		fetchCredential func(string) (azcore.TokenCredential, error)
	}

	doConfig := func(t *testing.T, coreConfig catalog.CoreConfig, config string, opt *testOpts) error {
		// reset the clients list and log entries
		clients = nil
		logEntries = nil

		if opt == nil {
			opt = new(testOpts)
		}

		attestor := New()
		attestor.hooks.now = func() time.Time { return s.now }
		attestor.hooks.fetchInstanceMetadata = func(azure.HTTPClient) (*azure.InstanceMetadata, error) {
			return instanceMetadata, nil
		}
		attestor.hooks.fetchCredential = func(tenantID string) (azcore.TokenCredential, error) {
			if opt.fetchCredential != nil {
				return opt.fetchCredential(tenantID)
			}
			return &fakeAzureCredential{}, nil
		}
		attestor.hooks.newClient = func(credential azcore.TokenCredential) (apiClient, error) {
			clients = append(clients, subscriptionID)
			return s.api, nil
		}
		log, hook := test.NewNullLogger()
		var err error
		plugintest.Load(t, builtin(attestor), nil,
			plugintest.Log(log),
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(config),
		)
		logEntries = hook.AllEntries()
		return err
	}

	_ = logEntries // silence unused warning, future tests asserting on logs will use this

	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}

	s.T().Run("malformed configuration", func(t *testing.T) {
		err := doConfig(t, coreConfig, "blah", nil)
		spiretest.RequireErrorContains(t, err, "unable to decode configuration")
	})

	s.T().Run("missing trust domain", func(t *testing.T) {
		err := doConfig(t, catalog.CoreConfig{}, "", nil)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "server core configuration must contain trust_domain")
	})

	s.T().Run("missing tenants", func(t *testing.T) {
		err := doConfig(t, coreConfig, "", nil)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "configuration must have at least one tenant")
	})

	s.T().Run("success with neither MSI nor app creds", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
			}
		}
		`, nil)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"SUBSCRIPTIONID"}, clients)
	})

	s.T().Run("success with MSI", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
			}
		}
		`, nil)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"SUBSCRIPTIONID"}, clients)
	})

	s.T().Run("success with app creds", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
				subscription_id = "TENANTSUBSCRIPTIONID"
				app_id = "APPID"
				app_secret = "APPSECRET"
			}
		}
		`, nil)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"TENANTSUBSCRIPTIONID"}, clients)
	})

	s.T().Run("success with app creds mixed with msi", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
				subscription_id = "TENANTSUBSCRIPTIONID"
				app_id = "APPID"
				app_secret = "APPSECRET"
			}
			"TENANTID2" = {	}
		}
		`, nil)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"TENANTSUBSCRIPTIONID", "SUBSCRIPTIONID"}, clients)
	})

	s.T().Run("failure with tenant missing subscription id", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
				app_id = "APPID"
				app_secret = "APPSECRET"

			}
		}
		`, nil)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, `misconfigured tenant "TENANTID": missing subscription id`)
	})

	s.T().Run("failure with tenant missing app id", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
				subscription_id = "TENANTSUBSCRIPTIONID"
				app_secret = "APPSECRET"

			}
		}
		`, nil)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, `misconfigured tenant "TENANTID": missing app id`)
	})

	s.T().Run("failure with tenant missing app secret", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
				subscription_id = "TENANTSUBSCRIPTIONID"
				app_id = "APPID"

			}
		}
		`, nil)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, `misconfigured tenant "TENANTID": missing app secret`)
	})

	s.T().Run("success with default credential", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
			}
		}
		`, nil)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"SUBSCRIPTIONID"}, clients)
	})

	s.T().Run("error when default credential fetch fails", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
			}
		}
		`,
			&testOpts{
				fetchCredential: func(string) (azcore.TokenCredential, error) {
					return nil, errors.New("some error")
				},
			},
		)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, `unable to fetch client credential: some error`)
	})

	s.T().Run("success with federation token", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		tenants = {
			"TENANTID" = {
				subscription_id = "TENANTSUBSCRIPTIONID"
				app_id = "APPID"
				token_path = "/path/to/token"
			}
		}
		`, nil)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"TENANTSUBSCRIPTIONID"}, clients)
	})

	s.T().Run("failure with federation token", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		tenants = {
			"TENANTID" = {
				token_path = "/path/to/token"
			}
		}
		`, nil)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, `misconfigured tenant "TENANTID": missing subscription id`)
	})
}

func (s *MSIAttestorSuite) adjustTime(d time.Duration) {
	s.now = s.now.Add(d)
}

func (s *MSIAttestorSuite) newSigner(keyID string) jose.Signer {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key: jose.JSONWebKey{
			Key:   s.key,
			KeyID: keyID,
		},
	}, nil)
	s.Require().NoError(err)
	return signer
}

func (s *MSIAttestorSuite) signToken(keyID, audience, tenantID, principalID string) string {
	builder := jwt.Signed(s.newSigner(keyID))

	// build up standard claims
	claims := jwt.Claims{
		Subject:   principalID,
		NotBefore: jwt.NewNumericDate(s.now),
		Expiry:    jwt.NewNumericDate(s.now.Add(time.Minute)),
	}
	if audience != "" {
		claims.Audience = []string{audience}
	}
	builder = builder.Claims(claims)

	// add the tenant id claim
	if tenantID != "" {
		builder = builder.Claims(map[string]any{
			"tid": tenantID,
		})
	}

	token, err := builder.Serialize()
	s.Require().NoError(err)
	return token
}

func (s *MSIAttestorSuite) signAttestPayload(keyID, audience, tenantID, principalID string) []byte {
	return makeAttestPayload(s.signToken(keyID, audience, tenantID, principalID))
}

func (s *MSIAttestorSuite) loadPlugin(options ...plugintest.Option) nodeattestor.NodeAttestor {
	return s.loadPluginWithConfig(`
		tenants = {
			"TENANTID" = {
				resource_id = "https://example.org/app/"
			}
			"TENANTID2" = { }
		}
	`, options...)
}

func (s *MSIAttestorSuite) loadPluginWithConfig(config string, options ...plugintest.Option) nodeattestor.NodeAttestor {
	attestor := New()
	attestor.hooks.now = func() time.Time {
		return s.now
	}
	attestor.hooks.keySetProvider = jwtutil.KeySetProviderFunc(func(ctx context.Context) (*jose.JSONWebKeySet, error) {
		return s.jwks, nil
	})
	attestor.hooks.newClient = func(string, azcore.TokenCredential) (apiClient, error) {
		return s.api, nil
	}
	attestor.hooks.fetchInstanceMetadata = func(azure.HTTPClient) (*azure.InstanceMetadata, error) {
		return instanceMetadata, nil
	}
	attestor.hooks.fetchCredential = func(_ string) (azcore.TokenCredential, error) {
		return &fakeAzureCredential{}, nil
	}

	v1 := new(nodeattestor.V1)
	plugintest.Load(s.T(), builtin(attestor), v1, append([]plugintest.Option{
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(config),
	}, options...)...)
	return v1
}

func (s *MSIAttestorSuite) requireAttestSuccess(payload []byte, expectID string, expectSelectorValues ...[]string) {
	var selectorValues []string
	for _, values := range expectSelectorValues {
		selectorValues = append(selectorValues, values...)
	}
	sort.Strings(selectorValues)

	var expected []*common.Selector
	for _, selectorValue := range selectorValues {
		expected = append(expected, &common.Selector{
			Type:  "azure_msi",
			Value: selectorValue,
		})
	}

	resp, err := s.attestor.Attest(context.Background(), payload, expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Equal(expectID, resp.AgentID)
	s.RequireProtoListEqual(expected, resp.Selectors)
}

func (s *MSIAttestorSuite) requireAttestError(t *testing.T, payload []byte, expectCode codes.Code, expectMsg string) {
	result, err := s.attestor.Attest(context.Background(), payload, expectNoChallenge)
	spiretest.RequireGRPCStatusContains(t, err, expectCode, expectMsg)
	require.Nil(t, result)
}

func (s *MSIAttestorSuite) setVirtualMachine(vm *VirtualMachine) {

	s.api.SetVirtualMachine("RESOURCEGROUP", "VIRTUALMACHINE", vm)
}

func (s *MSIAttestorSuite) setNetworkInterface(ni *NetworkInterface) {
	s.api.SetNetworkInterface("RESOURCEGROUP", "NETWORKINTERFACE", ni)
}

type fakeAPIClient struct {
	t testing.TB

	virtualMachines   map[string]*VirtualMachine
	networkInterfaces map[string]*NetworkInterface
}

func newFakeAPIClient(t testing.TB) *fakeAPIClient {
	return &fakeAPIClient{
		t:                 t,
		virtualMachines:   make(map[string]*VirtualMachine),
		networkInterfaces: make(map[string]*NetworkInterface),
	}
}

func (c *fakeAPIClient) GetVMSSInstance(_ context.Context, subscriptionID, vmId, ssName string) (*VMSSInfo, error) {
	//TODO: Implement
	return nil, nil
}

func (c *fakeAPIClient) SetVirtualMachine(resourceGroup string, vmId string, vm *VirtualMachine) {
	c.virtualMachines[vmId] = vm
}

func (c *fakeAPIClient) GetVirtualMachine(_ context.Context, vmId string, subscriptionId *string) (*VirtualMachine, error) {
	vm := c.virtualMachines[vmId]
	if vm == nil {
		return nil, errors.New("not found")
	}
	return vm, nil
}

func (c *fakeAPIClient) SetNetworkInterface(resourceGroup string, name string, ni *NetworkInterface) {
	c.networkInterfaces[name] = ni
}

func (c *fakeAPIClient) GetNetworkInterface(_ context.Context, resourceGroup string, name string) (*NetworkInterface, error) {
	ni := c.networkInterfaces[name]
	if ni == nil {
		return nil, errors.New("not found")
	}
	return ni, nil
}

type fakeAzureCredential struct{}

func (f *fakeAzureCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

func makeAttestPayload(token string) []byte {
	return fmt.Appendf(nil, `{"token": %q}`, token)
}

func expectNoChallenge(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("challenge is not expected")
}

func toPointer[T any](v T) *T {
	return &v
}
