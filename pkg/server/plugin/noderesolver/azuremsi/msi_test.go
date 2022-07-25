package azuremsi

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
)

const (
	azureAgentID = "spiffe://example.org/spire/agent/azure_msi/TENANT/PRINCIPAL"
	vmResourceID = "/subscriptions/SUBSCRIPTIONID/resourceGroups/RESOURCEGROUP/providers/Microsoft.Compute/virtualMachines/VIRTUALMACHINE"
)

var (
	trustDomain = spiffeid.RequireTrustDomainFromString("example.org")

	// these are vars because the address is needed
	niResourceID        = "/subscriptions/SUBSCRIPTIONID/resourceGroups/RESOURCEGROUP/providers/Microsoft.Network/networkInterfaces/NETWORKINTERFACE"
	nsgResourceID       = "/subscriptions/SUBSCRIPTIONID/resourceGroups/NSGRESOURCEGROUP/providers/Microsoft.Network/networkSecurityGroups/NETWORKSECURITYGROUP"
	subnetResourceID    = "/subscriptions/SUBSCRIPTIONID/resourceGroups/NETRESOURCEGROUP/providers/Microsoft.Network/virtualNetworks/VIRTUALNETWORK/subnets/SUBNET"
	malformedResourceID = "MALFORMEDRESOURCEID"

	// these are expected selectors
	vmSelectors = []string{
		"subscription-id:SUBSCRIPTION",
		"vm-name:RESOURCEGROUP:VIRTUALMACHINE",
	}
	niSelectors = []string{
		"network-security-group:NSGRESOURCEGROUP:NETWORKSECURITYGROUP",
		"virtual-network:NETRESOURCEGROUP:VIRTUALNETWORK",
		"virtual-network-subnet:NETRESOURCEGROUP:VIRTUALNETWORK:SUBNET",
	}
)

type fakeAzureCredential struct{}

func (f *fakeAzureCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

func TestMSIResolver(t *testing.T) {
	spiretest.Run(t, new(MSIResolverSuite))
}

type MSIResolverSuite struct {
	spiretest.Suite

	api *fakeAPIClient
}

func (s *MSIResolverSuite) SetupTest() {
	// set up the API with an initial view of the virtual machine
	s.api = newFakeAPIClient(s.T())
}

func (s *MSIResolverSuite) TestResolveWithIDFromAnotherTrustDomain() {
	nr := s.loadPluginWithTenant()
	s.assertResolveFailure(nr, "spiffe://otherdomain.test/whatever",
		codes.InvalidArgument,
		`noderesolver(azure_msi): invalid agent ID: SPIFFE ID "spiffe://otherdomain.test/whatever" is not a member of trust domain "example.org"`)
}

func (s *MSIResolverSuite) TestResolveWithNonAzureAgentID() {
	nr := s.loadPluginWithTenant()
	// agent ID's that aren't recognized by the resolver are simply ignored
	selectors, err := nr.Resolve(context.Background(), "spiffe://example.org/spire/agent/whatever")
	s.Require().NoError(err)
	s.Require().Empty(selectors)
}

func (s *MSIResolverSuite) TestResolveWithUnrecognizedTenant() {
	nr := s.loadPluginWithTenant()
	s.assertResolveFailure(nr, "spiffe://example.org/spire/agent/azure_msi/SOMEOTHERTENANT/PRINCIPAL",
		codes.InvalidArgument,
		`noderesolver(azure_msi): not configured for tenant "SOMEOTHERTENANT"`)
}

func (s *MSIResolverSuite) TestResolveWithNoVirtualMachineResource() {
	s.api.SetVirtualMachineResourceID("PRINCIPAL", "")

	nr := s.loadPluginWithTenant()
	s.assertResolveFailure(nr, azureAgentID,
		codes.Internal,
		`noderesolver(azure_msi): unable to get resource for principal "PRINCIPAL": not found`)
}

func (s *MSIResolverSuite) TestResolveWithMalformedResourceID() {
	s.api.SetVirtualMachineResourceID("PRINCIPAL", malformedResourceID)

	nr := s.loadPluginWithTenant()
	s.assertResolveFailure(nr, azureAgentID,
		codes.Internal,
		`noderesolver(azure_msi): malformed virtual machine ID "MALFORMEDRESOURCEID"`)
}

func (s *MSIResolverSuite) TestResolveWithNoVirtualMachineInfo() {
	s.api.SetVirtualMachineResourceID("PRINCIPAL", vmResourceID)

	nr := s.loadPluginWithTenant()
	s.assertResolveFailure(nr, azureAgentID,
		codes.Internal,
		`noderesolver(azure_msi): unable to get virtual machine "RESOURCEGROUP:VIRTUALMACHINE"`)
}

func (s *MSIResolverSuite) TestResolveVirtualMachine() {
	nr := s.loadPluginWithTenant()

	vm := &armcompute.VirtualMachine{
		Properties: &armcompute.VirtualMachineProperties{},
	}
	s.setVirtualMachine(vm)

	// no network profile
	s.assertResolveSuccess(nr, vmSelectors)

	// network profile with no interfaces
	vm.Properties.NetworkProfile = &armcompute.NetworkProfile{}
	s.assertResolveSuccess(nr, vmSelectors)

	// network profile with empty interface
	vm.Properties.NetworkProfile.NetworkInterfaces = []*armcompute.NetworkInterfaceReference{{}}
	s.assertResolveSuccess(nr, vmSelectors)

	// network profile with interface with malformed ID
	vm.Properties.NetworkProfile.NetworkInterfaces = []*armcompute.NetworkInterfaceReference{{ID: &malformedResourceID}}
	s.assertResolveFailure(nr, azureAgentID,
		codes.Internal,
		`noderesolver(azure_msi): malformed network interface ID "MALFORMEDRESOURCEID"`)

	// network profile with interface with no interface info
	vm.Properties.NetworkProfile.NetworkInterfaces = []*armcompute.NetworkInterfaceReference{
		{
			ID: &niResourceID,
		},
	}
	s.assertResolveFailure(nr, azureAgentID,
		codes.Internal,
		`noderesolver(azure_msi): unable to get network interface "RESOURCEGROUP:NETWORKINTERFACE"`)

	// network interface with no security group or ip config
	ni := &armnetwork.Interface{
		Properties: &armnetwork.InterfacePropertiesFormat{},
	}
	s.setNetworkInterface(ni)
	s.assertResolveSuccess(nr, vmSelectors)

	// network interface with malformed security group
	ni.Properties.NetworkSecurityGroup = &armnetwork.SecurityGroup{ID: &malformedResourceID}
	s.assertResolveFailure(nr, azureAgentID,
		codes.Internal,
		`noderesolver(azure_msi): malformed network security group ID "MALFORMEDRESOURCEID"`)
	ni.Properties.NetworkSecurityGroup = nil

	// network interface with no ip configuration
	ni.Properties.IPConfigurations = []*armnetwork.InterfaceIPConfiguration{}
	s.assertResolveSuccess(nr, vmSelectors)

	// network interface with empty ip configuration
	ni.Properties.IPConfigurations = []*armnetwork.InterfaceIPConfiguration{{}}
	s.assertResolveSuccess(nr, vmSelectors)

	// network interface with empty ip configuration properties
	props := new(armnetwork.InterfaceIPConfigurationPropertiesFormat)
	ni.Properties.IPConfigurations = []*armnetwork.InterfaceIPConfiguration{{Properties: props}}
	s.assertResolveSuccess(nr, vmSelectors)

	// network interface with subnet with no ID
	props.Subnet = &armnetwork.Subnet{}
	s.assertResolveSuccess(nr, vmSelectors)

	// network interface with subnet with malformed ID
	props.Subnet.ID = &malformedResourceID
	s.assertResolveFailure(nr, azureAgentID,
		codes.Internal,
		`noderesolver(azure_msi): malformed virtual network subnet ID "MALFORMEDRESOURCEID"`)

	// network interface with good subnet and security group
	ni.Properties.NetworkSecurityGroup = &armnetwork.SecurityGroup{ID: &nsgResourceID}
	props.Subnet.ID = &subnetResourceID
	s.assertResolveSuccess(nr, vmSelectors, niSelectors)
}

func (s *MSIResolverSuite) TestConfigure() {
	var err error

	coreConfig := catalog.CoreConfig{
		TrustDomain: trustDomain,
	}

	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.Configure("blah"),
	)
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "unable to decode configuration")

	// missing trust domain in core configuration
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{}),
		plugintest.Configure(""),
	)
	s.RequireGRPCStatus(err, codes.InvalidArgument, "trust domain is missing")

	// no tenants (not using MSI)
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(""),
	)
	s.RequireGRPCStatus(err, codes.InvalidArgument, "configuration must have at least one tenant when not using MSI")

	// tenant missing subscription id
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(`tenants = {
			TENANT = {
				app_id = "APPID"
				app_secret = "APPSECRET"
			}
		}`),
	)
	s.RequireGRPCStatus(err, codes.InvalidArgument, `misconfigured tenant "TENANT": missing subscription id`)

	// tenant missing app id
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(`tenants = {
			TENANT = {
				subscription_id = "SUBSCRIPTION"
				app_secret = "APPSECRET"
			}
		}`),
	)
	s.RequireGRPCStatus(err, codes.InvalidArgument, `misconfigured tenant "TENANT": missing app id`)

	// tenant missing app secret
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(`tenants = {
			TENANT = {
				subscription_id = "SUBSCRIPTION"
				app_id = "APPID"
			}
		}`),
	)
	s.RequireGRPCStatus(err, codes.InvalidArgument, `misconfigured tenant "TENANT": missing app secret`)

	// both MSI and tenant
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(`
			use_msi = true
			tenants = {
				TENANT = {}
			}
		`),
	)
	s.RequireGRPCStatus(err, codes.InvalidArgument, "configuration cannot have tenants when using MSI")

	// MSI only
	s.loadPlugin(
		plugintest.CoreConfig(coreConfig),
		plugintest.Configure(`use_msi = true`),
	)
}

func (s *MSIResolverSuite) loadPluginWithTenant() noderesolver.NodeResolver {
	return s.loadPlugin(
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: trustDomain,
		}),
		plugintest.Configure(`
		tenants = {
			TENANT = {
				subscription_id = "SUBSCRIPTION"
				app_id = "APPID"
				app_secret = "APPSECRET"
			}
		}`))
}

func (s *MSIResolverSuite) loadPlugin(options ...plugintest.Option) noderesolver.NodeResolver {
	resolver := New()
	resolver.hooks.newClient = func(string, azcore.TokenCredential) (apiClient, error) {
		return s.api, nil
	}
	resolver.hooks.fetchInstanceMetadata = func(context.Context, azure.HTTPClient) (*azure.InstanceMetadata, error) {
		return &azure.InstanceMetadata{
			Compute: azure.ComputeMetadata{
				SubscriptionID: "SUBSCRIPTION",
			},
		}, nil
	}

	resolver.hooks.msiCredential = func() (azcore.TokenCredential, error) {
		return &fakeAzureCredential{}, nil
	}

	nr := new(noderesolver.V1)
	plugintest.Load(s.T(), builtin(resolver), nr, options...)
	return nr
}

func (s *MSIResolverSuite) assertResolveSuccess(nr noderesolver.NodeResolver, selectorValueSets ...[]string) {
	var selectorValues []string
	for _, values := range selectorValueSets {
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

	actual, err := nr.Resolve(context.Background(), azureAgentID)
	s.Require().NoError(err)
	s.RequireProtoListEqual(expected, actual)
}

func (s *MSIResolverSuite) assertResolveFailure(nr noderesolver.NodeResolver, agentID string, code codes.Code, containsMsg string) {
	selectors, err := nr.Resolve(context.Background(), agentID)
	s.RequireGRPCStatusContains(err, code, containsMsg)
	s.Require().Empty(selectors)
}

func (s *MSIResolverSuite) setVirtualMachine(vm *armcompute.VirtualMachine) {
	s.api.SetVirtualMachineResourceID("PRINCIPAL", vmResourceID)
	s.api.SetVirtualMachine("RESOURCEGROUP", "VIRTUALMACHINE", vm)
}

func (s *MSIResolverSuite) setNetworkInterface(ni *armnetwork.Interface) {
	s.api.SetNetworkInterface("RESOURCEGROUP", "NETWORKINTERFACE", ni)
}

type fakeAPIClient struct {
	t testing.TB

	vmResourceIDs     map[string]string
	virtualMachines   map[string]*armcompute.VirtualMachine
	networkInterfaces map[string]*armnetwork.Interface
}

func newFakeAPIClient(t testing.TB) *fakeAPIClient {
	return &fakeAPIClient{
		t:                 t,
		vmResourceIDs:     make(map[string]string),
		virtualMachines:   make(map[string]*armcompute.VirtualMachine),
		networkInterfaces: make(map[string]*armnetwork.Interface),
	}
}

func (c *fakeAPIClient) SubscriptionID() string {
	return "SUBSCRIPTION"
}

func (c *fakeAPIClient) SetVirtualMachineResourceID(principalID, resourceID string) {
	c.vmResourceIDs[principalID] = resourceID
}

func (c *fakeAPIClient) GetVirtualMachineResourceID(ctx context.Context, principalID string) (string, error) {
	id := c.vmResourceIDs[principalID]
	if id == "" {
		return "", errors.New("not found")
	}
	return id, nil
}

func (c *fakeAPIClient) SetVirtualMachine(resourceGroup string, name string, vm *armcompute.VirtualMachine) {
	c.virtualMachines[resourceGroupName(resourceGroup, name)] = vm
}

func (c *fakeAPIClient) GetVirtualMachine(ctx context.Context, resourceGroup string, name string) (*armcompute.VirtualMachine, error) {
	vm := c.virtualMachines[resourceGroupName(resourceGroup, name)]
	if vm == nil {
		return nil, errors.New("not found")
	}
	return vm, nil
}

func (c *fakeAPIClient) SetNetworkInterface(resourceGroup string, name string, ni *armnetwork.Interface) {
	c.networkInterfaces[resourceGroupName(resourceGroup, name)] = ni
}

func (c *fakeAPIClient) GetNetworkInterface(ctx context.Context, resourceGroup string, name string) (*armnetwork.Interface, error) {
	ni := c.networkInterfaces[resourceGroupName(resourceGroup, name)]
	if ni == nil {
		return nil, errors.New("not found")
	}
	return ni, nil
}
