package azure

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/go-autorest/autorest"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/noderesolver"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
)

const (
	azureAgentID = "spiffe://example.org/spire/agent/azure_msi/TENANT/PRINCIPAL"
	vmResourceID = "/subscriptions/SUBSCRIPTIONID/resourceGroups/RESOURCEGROUP/providers/Microsoft.Compute/virtualMachines/VIRTUALMACHINE"
)

var (
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

func TestMSIResolver(t *testing.T) {
	spiretest.Run(t, new(MSIResolverSuite))
}

type MSIResolverSuite struct {
	spiretest.Suite

	api *fakeAPIClient

	resolver noderesolver.Plugin
}

func (s *MSIResolverSuite) SetupTest() {
	// set up the API with an initial view of the virtual machine
	s.api = newFakeAPIClient(s.T())

	resolver := New()
	resolver.hooks.newClient = func(string, autorest.Authorizer) apiClient {
		return s.api
	}
	resolver.hooks.fetchInstanceMetadata = func(context.Context, azure.HTTPClient) (*azure.InstanceMetadata, error) {
		return &azure.InstanceMetadata{
			Compute: azure.ComputeMetadata{
				SubscriptionID: "SUBSCRIPTION",
			},
		}, nil
	}
	s.LoadPlugin(builtin(resolver), &s.resolver)
	s.configureResolverWithTenant()
}

func (s *MSIResolverSuite) TestResolveWithEmptyRequest() {
	resp, err := s.resolver.Resolve(context.Background(), &noderesolver.ResolveRequest{})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Empty(resp.Map)
}

func (s *MSIResolverSuite) TestResolveWithNonAgentID() {
	s.assertResolveFailure("spiffe://example.org/spire/server/whatever",
		`azure-msi: "spiffe://example.org/spire/server/whatever" is not a valid agent SPIFFE ID`)
}

func (s *MSIResolverSuite) TestResolveWithNonAzureAgentID() {
	// agent ID's that aren't recognized by the resolver are simply ignored
	resp, err := s.resolver.Resolve(context.Background(), &noderesolver.ResolveRequest{
		BaseSpiffeIdList: []string{"spiffe://example.org/spire/agent/whatever"},
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Empty(resp.Map)
}

func (s *MSIResolverSuite) TestResolveWithUnrecognizedTenant() {
	s.assertResolveFailure("spiffe://example.org/spire/agent/azure_msi/SOMEOTHERTENANT/PRINCIPAL",
		`azure-msi: not configured for tenant "SOMEOTHERTENANT"`)
}

func (s *MSIResolverSuite) TestResolveWithNoVirtualMachineResource() {
	s.api.SetVirtualMachineResourceID("PRINCIPAL", "")
	s.assertResolveFailure(azureAgentID,
		`azure-msi: unable to get resource for principal "PRINCIPAL": not found`)
}

func (s *MSIResolverSuite) TestResolveWithMalformedResourceID() {
	s.api.SetVirtualMachineResourceID("PRINCIPAL", malformedResourceID)
	s.assertResolveFailure(azureAgentID,
		`azure-msi: malformed virtual machine ID "MALFORMEDRESOURCEID"`)
}

func (s *MSIResolverSuite) TestResolveWithNoVirtualMachineInfo() {
	s.api.SetVirtualMachineResourceID("PRINCIPAL", vmResourceID)
	s.assertResolveFailure(azureAgentID,
		`azure-msi: unable to get virtual machine "RESOURCEGROUP:VIRTUALMACHINE"`)
}

func (s *MSIResolverSuite) TestResolveVirtualMachine() {
	vm := &compute.VirtualMachine{
		VirtualMachineProperties: &compute.VirtualMachineProperties{},
	}
	s.setVirtualMachine(vm)

	// no network profile
	s.assertResolveSuccess(vmSelectors)

	// network profile with no interfaces
	vm.NetworkProfile = &compute.NetworkProfile{}
	s.assertResolveSuccess(vmSelectors)

	// network profile with empty interface
	vm.NetworkProfile.NetworkInterfaces = &[]compute.NetworkInterfaceReference{{}}
	s.assertResolveSuccess(vmSelectors)

	// network profile with interface with malformed ID
	vm.NetworkProfile.NetworkInterfaces = &[]compute.NetworkInterfaceReference{{ID: &malformedResourceID}}
	s.assertResolveFailure(azureAgentID,
		`azure-msi: malformed network interface ID "MALFORMEDRESOURCEID"`)

	// network profile with interface with no interface info
	vm.NetworkProfile.NetworkInterfaces = &[]compute.NetworkInterfaceReference{{ID: &niResourceID}}
	s.assertResolveFailure(azureAgentID,
		`azure-msi: unable to get network interface "RESOURCEGROUP:NETWORKINTERFACE"`)

	// network interface with no security group or ip config
	ni := &network.Interface{
		InterfacePropertiesFormat: &network.InterfacePropertiesFormat{},
	}
	s.setNetworkInterface(ni)
	s.assertResolveSuccess(vmSelectors)

	// network interface with malformed security group
	ni.NetworkSecurityGroup = &network.SecurityGroup{ID: &malformedResourceID}
	s.assertResolveFailure(azureAgentID,
		`azure-msi: malformed network security group ID "MALFORMEDRESOURCEID"`)
	ni.NetworkSecurityGroup = nil

	// network interface with no ip configuration
	ni.IPConfigurations = &[]network.InterfaceIPConfiguration{}
	s.assertResolveSuccess(vmSelectors)

	// network interface with empty ip configuration
	ni.IPConfigurations = &[]network.InterfaceIPConfiguration{{}}
	s.assertResolveSuccess(vmSelectors)

	// network interface with empty ip configuration properties
	props := new(network.InterfaceIPConfigurationPropertiesFormat)
	ni.IPConfigurations = &[]network.InterfaceIPConfiguration{{InterfaceIPConfigurationPropertiesFormat: props}}
	s.assertResolveSuccess(vmSelectors)

	// network interface with subnet with no ID
	props.Subnet = &network.Subnet{}
	s.assertResolveSuccess(vmSelectors)

	// network interface with subnet with malformed ID
	props.Subnet.ID = &malformedResourceID
	s.assertResolveFailure(azureAgentID,
		`azure-msi: malformed virtual network subnet ID "MALFORMEDRESOURCEID"`)

	// network interface with good subnet and security group
	ni.NetworkSecurityGroup = &network.SecurityGroup{ID: &nsgResourceID}
	props.Subnet.ID = &subnetResourceID
	s.assertResolveSuccess(vmSelectors, niSelectors)
}

func (s *MSIResolverSuite) TestConfigure() {
	resp, err := s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: "blah",
	})
	s.RequireErrorContains(err, "azure-msi: unable to decode configuration")
	s.Require().Nil(resp)

	// no tenants (not using MSI)
	resp, err = s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.RequireGRPCStatus(err, codes.Unknown, "azure-msi: configuration must have at least one tenant when not using MSI")
	s.Require().Nil(resp)

	// tenant missing subscription id
	resp, err = s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `tenants = {
			TENANT = {
				app_id = "APPID"
				app_secret = "APPSECRET"
			}
		}`})
	s.RequireGRPCStatus(err, codes.Unknown, `azure-msi: misconfigured tenant "TENANT": missing subscription id`)
	s.Require().Nil(resp)

	// tenant missing app id
	resp, err = s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `tenants = {
			TENANT = {
				subscription_id = "SUBSCRIPTION"
				app_secret = "APPSECRET"
			}
		}`})
	s.RequireGRPCStatus(err, codes.Unknown, `azure-msi: misconfigured tenant "TENANT": missing app id`)
	s.Require().Nil(resp)

	// tenant missing app secret
	resp, err = s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `tenants = {
			TENANT = {
				subscription_id = "SUBSCRIPTION"
				app_id = "APPID"
			}
		}`})
	s.RequireGRPCStatus(err, codes.Unknown, `azure-msi: misconfigured tenant "TENANT": missing app secret`)
	s.Require().Nil(resp)

	// success with tenant configuration
	s.configureResolverWithTenant()

	// both MSI and tenant
	resp, err = s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		use_msi = true
		tenants = {
			TENANT = {}
		}`})
	s.RequireGRPCStatus(err, codes.Unknown, "azure-msi: configuration cannot have tenants when using MSI")
	s.Require().Nil(resp)

	// success using MSI configuration
	s.configureResolverWithMSI()
}

func (s *MSIResolverSuite) TestGetPluginInfo() {
	resp, err := s.resolver.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *MSIResolverSuite) configureResolverWithTenant() {
	resp, err := s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `tenants = {
			TENANT = {
				subscription_id = "SUBSCRIPTION"
				app_id = "APPID"
				app_secret = "APPSECRET"
			}
		}`})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})
}

func (s *MSIResolverSuite) configureResolverWithMSI() {
	resp, err := s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `use_msi = true`,
	})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})
}

func (s *MSIResolverSuite) assertResolveSuccess(selectorValueSets ...[]string) {
	var selectorValues []string
	for _, values := range selectorValueSets {
		selectorValues = append(selectorValues, values...)
	}
	sort.Strings(selectorValues)

	selectors := &common.Selectors{}
	for _, selectorValue := range selectorValues {
		selectors.Entries = append(selectors.Entries, &common.Selector{
			Type:  "azure_msi",
			Value: selectorValue,
		})
	}

	expected := &noderesolver.ResolveResponse{
		Map: map[string]*common.Selectors{
			azureAgentID: selectors,
		},
	}

	actual, err := s.doResolve(azureAgentID)
	s.Require().NoError(err)
	s.Require().Equal(expected, actual)
}

func (s *MSIResolverSuite) assertResolveFailure(spiffeID, containsErr string) {
	resp, err := s.doResolve(spiffeID)
	s.RequireErrorContains(err, containsErr)
	s.Require().Nil(resp)
}

func (s *MSIResolverSuite) doResolve(spiffeID string) (*noderesolver.ResolveResponse, error) {
	return s.resolver.Resolve(context.Background(), &noderesolver.ResolveRequest{
		BaseSpiffeIdList: []string{spiffeID},
	})
}

func (s *MSIResolverSuite) setVirtualMachine(vm *compute.VirtualMachine) {
	s.api.SetVirtualMachineResourceID("PRINCIPAL", vmResourceID)
	s.api.SetVirtualMachine("RESOURCEGROUP", "VIRTUALMACHINE", vm)
}

func (s *MSIResolverSuite) setNetworkInterface(ni *network.Interface) {
	s.api.SetNetworkInterface("RESOURCEGROUP", "NETWORKINTERFACE", ni)
}

type fakeAPIClient struct {
	t testing.TB

	vmResourceIDs     map[string]string
	virtualMachines   map[string]*compute.VirtualMachine
	networkInterfaces map[string]*network.Interface
}

func newFakeAPIClient(t testing.TB) *fakeAPIClient {
	return &fakeAPIClient{
		t:                 t,
		vmResourceIDs:     make(map[string]string),
		virtualMachines:   make(map[string]*compute.VirtualMachine),
		networkInterfaces: make(map[string]*network.Interface),
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

func (c *fakeAPIClient) SetVirtualMachine(resourceGroup string, name string, vm *compute.VirtualMachine) {
	c.virtualMachines[resourceGroupName(resourceGroup, name)] = vm
}

func (c *fakeAPIClient) GetVirtualMachine(ctx context.Context, resourceGroup string, name string) (*compute.VirtualMachine, error) {
	vm := c.virtualMachines[resourceGroupName(resourceGroup, name)]
	if vm == nil {
		return nil, errors.New("not found")
	}
	return vm, nil
}

func (c *fakeAPIClient) SetNetworkInterface(resourceGroup string, name string, ni *network.Interface) {
	c.networkInterfaces[resourceGroupName(resourceGroup, name)] = ni
}

func (c *fakeAPIClient) GetNetworkInterface(ctx context.Context, resourceGroup string, name string) (*network.Interface, error) {
	ni := c.networkInterfaces[resourceGroupName(resourceGroup, name)]
	if ni == nil {
		return nil, errors.New("not found")
	}
	return ni, nil
}
