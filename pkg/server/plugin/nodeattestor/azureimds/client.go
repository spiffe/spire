package azureimds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// apiClient is an interface representing all API methods the resolver
// needs to do its job.
type apiClient interface {
	GetVirtualMachine(ctx context.Context, vmId string, subscriptionId *string) (*VirtualMachine, error)
	GetVMSSInstance(ctx context.Context, vmId, subscriptionID, ssName string) (*VirtualMachine, error)
}

// VirtualMachine is a subset of the fields returned by the Resource Graph API
type VirtualMachine struct {
	ID            string              `json:"id"`
	Name          string              `json:"name"`
	Location      string              `json:"location"`
	Tags          map[string]any      `json:"tags"`
	VMID          string              `json:"vmId"`
	ResourceGroup string              `json:"resourceGroup"`
	Interfaces    []*NetworkInterface `json:"interfaces"`
}
type NetworkInterface struct {
	Name          string        `json:"name"`
	SecurityGroup SecurityGroup `json:"securityGroup"`
	Subnets       []Subnet      `json:"subnets"`
}
type Subnet struct {
	VNet       string `json:"vnet"`
	SubnetName string `json:"name"`
}

type SecurityGroup struct {
	ResourceGroup string `json:"resourceGroup"`
	Name          string `json:"name"`
}

type VMSSInfo struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Location       string `json:"location"`
	ResourceGroup  string `json:"resourceGroup"`
	SubscriptionID string `json:"subscriptionId"`
}

// azureClient implements apiClient using Azure SDK client implementations
type azureClient struct {
	cred azcore.TokenCredential
	g    *armresourcegraph.Client
}

func newAzureClient(cred azcore.TokenCredential) (apiClient, error) {
	g, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return nil, err
	}

	return &azureClient{
		g:    g,
		cred: cred,
	}, nil
}

// A direct scale set VM api client is needed to support VMSS with an orchestration mode of "Uniform".
func (c *azureClient) newScaleSetVMClient(subscriptionID string) (*armcompute.VirtualMachineScaleSetVMsClient, error) {
	return armcompute.NewVirtualMachineScaleSetVMsClient(subscriptionID, c.cred, nil)
}

func (c *azureClient) GetVirtualMachine(ctx context.Context, vmId string, subscriptionId *string) (*VirtualMachine, error) {
	// For additional fields, see:
	// https://learn.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines?pivots=deployment-language-arm-template
	query := fmt.Sprintf(`
	resources 
	| where type =~ 'microsoft.compute/virtualmachines'
	| where properties.vmId == '%s'
	| project id, name, location, tags, vmId = properties.vmId, networkProfile = properties.networkProfile, resourceGroup`, vmId)
	options := &armresourcegraph.QueryRequestOptions{
		ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
	}
	req := armresourcegraph.QueryRequest{
		Query:   &query,
		Options: options,
	}
	if subscriptionId != nil {
		req.Subscriptions = []*string{subscriptionId}
	}
	resp, err := c.g.Resources(ctx, req, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get virtual machine: %v", err)
	}
	vm, err := extractArmResourceGraphItem[VirtualMachine](resp)
	if err != nil {
		return nil, err
	}
	vm.Interfaces, err = c.getNetworkInterfaces(ctx, vm.ID, subscriptionId)
	if err != nil {
		return nil, err
	}
	return vm, nil
}

func (c *azureClient) GetVMSSInstance(ctx context.Context, vmId, subscriptionID, ssName string) (*VirtualMachine, error) {
	info, err := c.getVMSSInfo(ctx, []*string{&subscriptionID}, ssName)
	if err != nil {
		return nil, err
	}
	client, err := c.newScaleSetVMClient(subscriptionID)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to create scale set VM client: %v", err)
	}
	pager := client.NewListPager(info.ResourceGroup, ssName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to list VMSS instances: %v", err)
		}

		for _, instance := range page.Value {
			if *instance.Properties.VMID == vmId {
				vm, err := buildVirtualMachineFromVMSSInstance(instance, info.ResourceGroup)
				if err != nil {
					return nil, err
				}
				return vm, nil
			}
		}
	}
	return nil, status.Errorf(codes.Internal, "VMSS instance %q not found", vmId)
}

func (c *azureClient) getVMSSInfo(ctx context.Context, subscriptionIDs []*string, name string) (*VMSSInfo, error) {
	if err := validateVMSSName(name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid VMSS name: %v", err)
	}

	query := fmt.Sprintf(`
	resources 
	| where type =~ 'microsoft.compute/virtualmachinescalesets'
	| where name == '%s'
	| project id, name, location, resourceGroup, subscriptionId`, name)
	options := &armresourcegraph.QueryRequestOptions{
		ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
	}
	req := armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: subscriptionIDs,
		Options:       options,
	}
	resp, err := c.g.Resources(ctx, req, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get VMSS info: %v", err)
	}
	return extractArmResourceGraphItem[VMSSInfo](resp)
}

func (c *azureClient) getNetworkInterfaces(ctx context.Context, vmId string, subscriptionId *string) ([]*NetworkInterface, error) {
	query := fmt.Sprintf(`
	Resources
	| where type == "microsoft.network/networkinterfaces"
	| where properties.virtualMachine.id == "%s"
	| mv-expand ipConfig = properties.ipConfigurations
	| extend subnetId = tostring(ipConfig.properties.subnet.id)
	| extend vnetName = extract(@"virtualNetworks/([^/]+)", 1, subnetId)
	| extend subnetName = extract(@"subnets/([^/]+)$", 1, subnetId)
	| extend subnetObj = bag_pack("vnet", vnetName, "name", subnetName)
	| extend nsgId = tostring(properties.networkSecurityGroup.id)
	| extend nsgRg = extract(@"resourceGroups/([^/]+)",1,nsgId)
	| extend nsgName = extract(@"networkSecurityGroups/([^/]+)",1,nsgId)
	| extend securityGroup = bag_pack("resourceGroup", nsgRg, "name",nsgName)
	| summarize 
		subnets = make_list(subnetObj)
		by id, name, resourceGroup, tostring(securityGroup)
	| project name, resourceGroup, subnets, securityGroup`, vmId)
	options := &armresourcegraph.QueryRequestOptions{
		ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
	}
	req := armresourcegraph.QueryRequest{
		Query:   &query,
		Options: options,
	}
	if subscriptionId != nil {
		req.Subscriptions = []*string{subscriptionId}
	}
	resp, err := c.g.Resources(ctx, req, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get network interfaces: %v", err)
	}
	return extractArmResourceGraphItems[NetworkInterface](resp)
}

// buildVirtualMachineFromVMSSInstance creates a VirtualMachine struct from a VMSS instance
// with all network interfaces parsed and populated
func buildVirtualMachineFromVMSSInstance(instance *armcompute.VirtualMachineScaleSetVM, resourceGroup string) (*VirtualMachine, error) {
	if instance == nil {
		return nil, status.Error(codes.Internal, "vmss instance is nil")
	}

	v := &VirtualMachine{
		ID:            *instance.ID,
		Name:          *instance.Name,
		Location:      *instance.Location,
		VMID:          *instance.Properties.VMID,
		ResourceGroup: resourceGroup,
		Interfaces:    []*NetworkInterface{},
	}

	if instance.Tags != nil {
		v.Tags = make(map[string]any)
		for key, value := range instance.Tags {
			v.Tags[key] = value
		}
	}

	for _, interfaceConfig := range instance.Properties.NetworkProfileConfiguration.NetworkInterfaceConfigurations {
		ni, err := parseNetworkInterfaceConfig(interfaceConfig)
		if err != nil {
			continue
		}
		v.Interfaces = append(v.Interfaces, ni)
	}

	return v, nil
}

// parseNetworkInterfaceConfig parses a network interface configuration from a VMSS instance
// and returns a NetworkInterface with parsed security group and subnet information
func parseNetworkInterfaceConfig(interfaceConfig *armcompute.VirtualMachineScaleSetNetworkConfiguration) (*NetworkInterface, error) {
	if interfaceConfig == nil {
		return nil, status.Error(codes.Internal, "network interface configuration is nil")
	}
	nsgResourceGroup, nsgName, err := parseNetworkSecurityGroupID(*interfaceConfig.Properties.NetworkSecurityGroup.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to parse network security group ID: %v", err)
	}

	ni := &NetworkInterface{
		Name: *interfaceConfig.Name,
		SecurityGroup: SecurityGroup{
			ResourceGroup: nsgResourceGroup,
			Name:          nsgName,
		},
	}

	for _, ipconfig := range interfaceConfig.Properties.IPConfigurations {
		if ipconfig == nil {
			continue
		}

		_, networkName, subnetName, err := parseVirtualNetworkSubnetID(*ipconfig.Properties.Subnet.ID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to parse virtual network subnet ID: %v", err)
		}
		ni.Subnets = append(ni.Subnets, Subnet{VNet: networkName, SubnetName: subnetName})
	}

	return ni, nil
}

func extractArmResourceGraphItems[T any](resp armresourcegraph.ClientResourcesResponse) ([]*T, error) {
	if resp.TotalRecords == nil || *resp.TotalRecords == 0 {
		return nil, status.Error(codes.NotFound, "resource not found")
	}

	items, ok := resp.Data.([]any)
	if !ok {
		return nil, errors.New("unable to cast data to []any")
	}

	resultSlice := make([]*T, 0, len(items))
	for _, item := range items {
		nextItem, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("unable to cast item to map[string]any")
		}
		jsonBytes, err := json.Marshal(nextItem)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal item: %w", err)
		}
		resultItem := new(T)
		err = json.Unmarshal(jsonBytes, resultItem)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal item: %w", err)
		}
		resultSlice = append(resultSlice, resultItem)
	}
	return resultSlice, nil
}

func extractArmResourceGraphItem[T any](resp armresourcegraph.ClientResourcesResponse) (*T, error) {
	items, err := extractArmResourceGraphItems[T](resp)
	if err != nil {
		return nil, err
	}
	if len(items) > 1 {
		return nil, status.Error(codes.Internal, "expected one result for resource at most")
	}
	return items[0], nil
}
