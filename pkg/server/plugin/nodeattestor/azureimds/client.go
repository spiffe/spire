package azureimds

import (
	"context"
	"encoding/json"
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
	GetNetworkInterfaces(ctx context.Context, vmId string, subscriptionId *string) ([]*NetworkInterface, error)
	GetVMSSInstance(ctx context.Context, vmId, subscriptionID, ssName string) (*VirtualMachine, error)
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
		g: g,
	}, nil
}

// A direct scale set VM api client is needed to support VMSS with an orchestration mode of "Uniform".
func (c *azureClient) newScaleSetVMClient(subscriptionID string) (*armcompute.VirtualMachineScaleSetVMsClient, error) {
	return armcompute.NewVirtualMachineScaleSetVMsClient(subscriptionID, c.cred, nil)
}

// VirtualMachine is a subset of the fields returned by the Resource Graph API
type VirtualMachine struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Location      string         `json:"location"`
	Tags          map[string]any `json:"tags"`
	VMID          string         `json:"vmId"`
	ResourceGroup string         `json:"resourceGroup"`
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

	return extractArmResourceGraphItem[VirtualMachine](resp)
}

type Subnet struct {
	VNet       string `json:"vnet"`
	SubnetName string `json:"name"`
}
type SecurityGroup struct {
	ResourceGroup string `json:"resourceGroup"`
	Name          string `json:"name"`
}
type NetworkInterface struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	SecurityGroup SecurityGroup `json:"securityGroup"`
	Subnets       []Subnet      `json:"subnets"`
}

func (c *azureClient) GetNetworkInterfaces(ctx context.Context, vmId string, subscriptionId *string) ([]*NetworkInterface, error) {
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

type VMSSInfo struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Location       string `json:"location"`
	ResourceGroup  string `json:"resourceGroup"`
	SubscriptionID string `json:"subscriptionId"`
}

func (c *azureClient) getVMSSInfo(ctx context.Context, subscriptionIDs []*string, name string) (*VMSSInfo, error) {
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
				v := &VirtualMachine{
					ID:            *instance.ID,
					Name:          *instance.Name,
					Location:      *instance.Location,
					VMID:          *instance.Properties.VMID,
					ResourceGroup: info.ResourceGroup,
				}
				if instance.Tags != nil {
					v.Tags = make(map[string]any)
					for key, value := range instance.Tags {
						v.Tags[key] = value
					}
				}
				return v, nil
			}
		}

	}
	return nil, status.Errorf(codes.Internal, "VMSS instance %q not found", vmId)
}

func extractArmResourceGraphItems[T any](resp armresourcegraph.ClientResourcesResponse) ([]*T, error) {
	if resp.TotalRecords == nil || *resp.TotalRecords == 0 {
		return nil, status.Errorf(codes.NotFound, "resource not found")
	}

	items, ok := resp.Data.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unable to cast data to []interface{}")
	}

	resultSlice := make([]*T, 0, len(items))
	for _, item := range items {
		nextItem, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("unable to cast item to map[string]interface{}")
		}
		jsonBytes, err := json.Marshal(nextItem)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal item: %v", err)
		}
		resultItem := new(T)
		err = json.Unmarshal(jsonBytes, resultItem)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal item: %v", err)
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
		return nil, status.Errorf(codes.Internal, "expected one result for resource at most")
	}
	return items[0], nil
}
