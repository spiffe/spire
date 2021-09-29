package azure

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	noderesolverv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/noderesolver/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

const (
	pluginName = "azure_msi"
)

var (
	reAgentIDPath            = regexp.MustCompile(`^/spire/agent/azure_msi/([^/]+)/([^/]+)`)
	reVirtualMachineID       = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Compute/virtualMachines/([^/]+)$`)
	reNetworkSecurityGroupID = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/networkSecurityGroups/([^/]+)$`)
	reNetworkInterfaceID     = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/networkInterfaces/([^/]+)$`)
	reVirtualNetworkSubnetID = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/virtualNetworks/([^/]+)/subnets/([^/]+)$`)
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *MSIResolverPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		noderesolverv1.NodeResolverPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type TenantConfig struct {
	SubscriptionID string `hcl:"subscription_id" json:"subscription_id"`
	AppID          string `hcl:"app_id" json:"app_id"`
	AppSecret      string `hcl:"app_secret" json:"app_secret"`
}

type MSIResolverConfig struct {
	UseMSI  bool                    `hcl:"use_msi" json:"use_msi"`
	Tenants map[string]TenantConfig `hcl:"tenants" json:"tenants"`
}

type MSIResolverPlugin struct {
	noderesolverv1.UnsafeNodeResolverServer
	configv1.UnsafeConfigServer

	log           hclog.Logger
	mu            sync.RWMutex
	msiClient     apiClient
	tenantClients map[string]apiClient

	hooks struct {
		newClient             func(string, autorest.Authorizer) apiClient
		fetchInstanceMetadata func(context.Context, azure.HTTPClient) (*azure.InstanceMetadata, error)
		msiAuthorizer         func() (autorest.Authorizer, error)
	}
}

func New() *MSIResolverPlugin {
	p := &MSIResolverPlugin{}
	p.hooks.newClient = newAzureClient
	p.hooks.fetchInstanceMetadata = azure.FetchInstanceMetadata
	p.hooks.msiAuthorizer = func() (autorest.Authorizer, error) {
		return auth.NewMSIConfig().Authorizer()
	}

	return p
}

func (p *MSIResolverPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *MSIResolverPlugin) Resolve(ctx context.Context, req *noderesolverv1.ResolveRequest) (*noderesolverv1.ResolveResponse, error) {
	selectorValues, err := p.resolve(ctx, req.AgentId)
	if err != nil {
		return nil, err
	}

	return &noderesolverv1.ResolveResponse{
		SelectorValues: selectorValues,
	}, nil
}

func (p *MSIResolverPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(MSIResolverConfig)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	var msiClient apiClient
	var tenantClients map[string]apiClient

	if config.UseMSI {
		if len(config.Tenants) > 0 {
			return nil, status.Error(codes.InvalidArgument, "configuration cannot have tenants when using MSI")
		}
		instanceMetadata, err := p.hooks.fetchInstanceMetadata(ctx, http.DefaultClient)
		if err != nil {
			return nil, err
		}
		authorizer, err := p.hooks.msiAuthorizer()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to get MSI authorizer: %v", err)
		}
		msiClient = p.hooks.newClient(instanceMetadata.Compute.SubscriptionID, authorizer)
	} else {
		if len(config.Tenants) == 0 {
			return nil, status.Error(codes.InvalidArgument, "configuration must have at least one tenant when not using MSI")
		}
		tenantClients = make(map[string]apiClient)
		for tenantID, tenant := range config.Tenants {
			if tenant.SubscriptionID == "" {
				return nil, status.Errorf(codes.InvalidArgument, "misconfigured tenant %q: missing subscription id", tenantID)
			}
			if tenant.AppID == "" {
				return nil, status.Errorf(codes.InvalidArgument, "misconfigured tenant %q: missing app id", tenantID)
			}
			if tenant.AppSecret == "" {
				return nil, status.Errorf(codes.InvalidArgument, "misconfigured tenant %q: missing app secret", tenantID)
			}
			authorizer, err := auth.NewClientCredentialsConfig(tenant.AppID, tenant.AppSecret, tenantID).Authorizer()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "unable to get tenant authorizer: %v", err)
			}
			tenantClients[tenantID] = p.hooks.newClient(tenant.SubscriptionID, authorizer)
		}
	}

	p.setClients(msiClient, tenantClients)
	return &configv1.ConfigureResponse{}, nil
}

func (p *MSIResolverPlugin) getClient(tenantID string) (apiClient, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	switch {
	case p.msiClient != nil:
		return p.msiClient, nil
	case p.tenantClients != nil:
		client, ok := p.tenantClients[tenantID]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "not configured for tenant %q", tenantID)
		}
		return client, nil
	default:
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
}

func (p *MSIResolverPlugin) setClients(msiClient apiClient, tenantClients map[string]apiClient) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.msiClient = msiClient
	p.tenantClients = tenantClients
}

func (p *MSIResolverPlugin) resolve(ctx context.Context, agentID string) ([]string, error) {
	// parse out the tenant ID and principal ID from the token
	u, err := idutil.ParseSpiffeID(agentID, idutil.AllowAnyTrustDomainAgent())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid agent ID: %v", err)
	}

	tenantID, principalID, err := parseAgentIDPath(u.Path)
	if err != nil {
		p.log.Warn("Unrecognized agent ID", telemetry.SPIFFEID, agentID)
		return nil, nil
	}

	client, err := p.getClient(tenantID)
	if err != nil {
		return nil, err
	}

	// Retrieve the resource belonging to the principal id.
	vmResourceID, err := client.GetVirtualMachineResourceID(ctx, principalID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get resource for principal %q: %v", principalID, err)
	}

	// parse out the resource group and vm name from the resource ID
	vmResourceGroup, vmName, err := parseVirtualMachineID(vmResourceID)
	if err != nil {
		return nil, err
	}

	// build up a unique map of selectors. this is easier than deduping
	// individual selectors (e.g. the virtual network for each interface)
	selectorMap := map[string]bool{
		selectorValue("subscription-id", client.SubscriptionID()): true,
		selectorValue("vm-name", vmResourceGroup, vmName):         true,
	}
	addSelectors := func(values []string) {
		for _, value := range values {
			selectorMap[value] = true
		}
	}

	// pull the VM information and gather selectors
	vm, err := client.GetVirtualMachine(ctx, vmResourceGroup, vmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get virtual machine %q: %v", resourceGroupName(vmResourceGroup, vmName), err)
	}
	if vm.NetworkProfile != nil {
		networkProfileSelectors, err := getNetworkProfileSelectors(ctx, client, vm.NetworkProfile)
		if err != nil {
			return nil, err
		}
		addSelectors(networkProfileSelectors)
	}

	// sort and return selectors
	selectorValues := make([]string, 0, len(selectorMap))
	for selectorValue := range selectorMap {
		selectorValues = append(selectorValues, selectorValue)
	}
	sort.Strings(selectorValues)

	return selectorValues, nil
}

func getNetworkProfileSelectors(ctx context.Context, client apiClient, networkProfile *compute.NetworkProfile) ([]string, error) {
	if networkProfile.NetworkInterfaces == nil {
		return nil, nil
	}

	var selectors []string
	for _, interfaceRef := range *networkProfile.NetworkInterfaces {
		if interfaceRef.ID == nil {
			continue
		}
		niResourceGroup, niName, err := parseNetworkInterfaceID(*interfaceRef.ID)
		if err != nil {
			return nil, err
		}
		networkInterface, err := client.GetNetworkInterface(ctx, niResourceGroup, niName)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to get network interface %q: %v", resourceGroupName(niResourceGroup, niName), err)
		}

		networkInterfaceSelectors, err := getNetworkInterfaceSelectors(networkInterface)
		if err != nil {
			return nil, err
		}

		selectors = append(selectors, networkInterfaceSelectors...)
	}

	return selectors, nil
}

func getNetworkInterfaceSelectors(networkInterface *network.Interface) ([]string, error) {
	var selectors []string
	if nsg := networkInterface.NetworkSecurityGroup; nsg != nil && nsg.ID != nil {
		nsgResourceGroup, nsgName, err := parseNetworkSecurityGroupID(*nsg.ID)
		if err != nil {
			return nil, err
		}
		selectors = append(selectors, selectorValue("network-security-group", nsgResourceGroup, nsgName))
	}

	if ipcs := networkInterface.IPConfigurations; ipcs != nil {
		for _, ipc := range *ipcs {
			if props := ipc.InterfaceIPConfigurationPropertiesFormat; props != nil {
				if subnet := props.Subnet; subnet != nil && subnet.ID != nil {
					subResourceGroup, subVirtualNetwork, subName, err := parseVirtualNetworkSubnetID(*subnet.ID)
					if err != nil {
						return nil, err
					}
					selectors = append(selectors, selectorValue("virtual-network", subResourceGroup, subVirtualNetwork))
					selectors = append(selectors, selectorValue("virtual-network-subnet", subResourceGroup, subVirtualNetwork, subName))
				}
			}
		}
	}

	return selectors, nil
}

func parseAgentIDPath(path string) (tenantID, principalID string, err error) {
	m := reAgentIDPath.FindStringSubmatch(path)
	if m == nil {
		return "", "", status.Errorf(codes.InvalidArgument, "malformed agent ID path %q", path)
	}
	return m[1], m[2], nil
}

func parseVirtualMachineID(id string) (resourceGroup, name string, err error) {
	m := reVirtualMachineID.FindStringSubmatch(id)
	if m == nil {
		return "", "", status.Errorf(codes.Internal, "malformed virtual machine ID %q", id)
	}
	return m[1], m[2], nil
}

func parseNetworkSecurityGroupID(id string) (resourceGroup, name string, err error) {
	m := reNetworkSecurityGroupID.FindStringSubmatch(id)
	if m == nil {
		return "", "", status.Errorf(codes.Internal, "malformed network security group ID %q", id)
	}
	return m[1], m[2], nil
}

func parseNetworkInterfaceID(id string) (resourceGroup, name string, err error) {
	m := reNetworkInterfaceID.FindStringSubmatch(id)
	if m == nil {
		return "", "", status.Errorf(codes.Internal, "malformed network interface ID %q", id)
	}
	return m[1], m[2], nil
}

func parseVirtualNetworkSubnetID(id string) (resourceGroup, networkName, subnetName string, err error) {
	m := reVirtualNetworkSubnetID.FindStringSubmatch(id)
	if m == nil {
		return "", "", "", status.Errorf(codes.Internal, "malformed virtual network subnet ID %q", id)
	}
	return m[1], m[2], m[3], nil
}

func resourceGroupName(resourceGroup, name string) string {
	return fmt.Sprintf("%s:%s", resourceGroup, name)
}

func selectorValue(parts ...string) string {
	return strings.Join(parts, ":")
}
