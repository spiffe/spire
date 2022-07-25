package azuremsi

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// apiClient is an interface representing all of the API methods the resolver
// needs to do its job.
type apiClient interface {
	SubscriptionID() string
	GetVirtualMachineResourceID(ctx context.Context, principalID string) (string, error)
	GetVirtualMachine(ctx context.Context, resourceGroup string, name string) (*armcompute.VirtualMachine, error)
	GetNetworkInterface(ctx context.Context, resourceGroup string, name string) (*armnetwork.Interface, error)
}

// azureClient implements apiClient using Azure SDK client implementations
type azureClient struct {
	subscriptionID string
	r              *armresources.Client
	v              *armcompute.VirtualMachinesClient
	n              *armnetwork.InterfacesClient
}

func newAzureClient(subscriptionID string, cred azcore.TokenCredential) (apiClient, error) {
	r, err := armresources.NewClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	v, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	n, err := armnetwork.NewInterfacesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return &azureClient{
		subscriptionID: subscriptionID,
		r:              r,
		v:              v,
		n:              n,
	}, nil
}

func (c *azureClient) SubscriptionID() string {
	return c.subscriptionID
}

func (c *azureClient) GetVirtualMachineResourceID(ctx context.Context, principalID string) (string, error) {
	filter := fmt.Sprintf("resourceType eq 'Microsoft.Compute/virtualMachines' and identity/principalId eq '%s'", principalID)
	listPager := c.r.NewListPager(&armresources.ClientListOptions{
		Filter: &filter,
	})

	var values []*armresources.GenericResourceExpanded
	for listPager.More() {
		resp, err := listPager.NextPage(ctx)
		if err != nil {
			return "", status.Errorf(codes.Internal, "unable to list virtual machine by principal: %v", err)
		}
		values = append(values, resp.ResourceListResult.Value...)
	}

	if len(values) == 0 {
		return "", status.Errorf(codes.Internal, "principal %q not found", principalID)
	}
	if len(values) > 1 {
		return "", status.Errorf(codes.Internal, "expected one result for principal %q at most", principalID)
	}
	if values[0].ID == nil || *values[0].ID == "" {
		return "", status.Error(codes.Internal, "virtual machine resource missing ID")
	}

	return *values[0].ID, nil
}

func (c *azureClient) GetVirtualMachine(ctx context.Context, resourceGroup string, name string) (*armcompute.VirtualMachine, error) {
	resp, err := c.v.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get virtual machine: %v", err)
	}
	return &resp.VirtualMachine, nil
}

func (c *azureClient) GetNetworkInterface(ctx context.Context, resourceGroup string, name string) (*armnetwork.Interface, error) {
	resp, err := c.n.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get network interface: %v", err)
	}
	return &resp.Interface, nil
}
