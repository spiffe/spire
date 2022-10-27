package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/go-autorest/autorest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// apiClient is an interface representing all of the API methods the resolver
// needs to do its job.
type apiClient interface {
	SubscriptionID() string
	GetVirtualMachineResourceID(ctx context.Context, principalID string) (string, error)
	GetVirtualMachine(ctx context.Context, resourceGroup string, name string) (*compute.VirtualMachine, error)
	GetNetworkInterface(ctx context.Context, resourceGroup string, name string) (*network.Interface, error)
}

// azureClient implements apiClient using Azure SDK client implementations
type azureClient struct {
	subscriptionID string
	r              resources.Client
	v              compute.VirtualMachinesClient
	n              network.InterfacesClient
}

func newAzureClient(subscriptionID string, authorizer autorest.Authorizer) apiClient {
	r := resources.NewClient(subscriptionID)
	r.Authorizer = authorizer

	v := compute.NewVirtualMachinesClient(subscriptionID)
	v.Authorizer = authorizer

	n := network.NewInterfacesClient(subscriptionID)
	n.Authorizer = authorizer

	return &azureClient{
		subscriptionID: subscriptionID,
		r:              r,
		v:              v,
		n:              n,
	}
}

func (c *azureClient) SubscriptionID() string {
	return c.subscriptionID
}

func (c *azureClient) GetVirtualMachineResourceID(ctx context.Context, principalID string) (string, error) {
	filter := fmt.Sprintf("resourceType eq 'Microsoft.Compute/virtualMachines' and identity/principalId eq '%s'", principalID)
	result, err := c.r.List(ctx, filter, "", nil)
	if err != nil {
		return "", status.Errorf(codes.Internal, "unable to list virtual machine by principal: %v", err)
	}

	values := result.Values()
	for len(values) == 0 {
		nerr := result.NextWithContext(ctx)
		if nerr != nil {
			return "", status.Errorf(codes.Internal, "unable to list virtual machine by principal: %v", nerr)
		}
		values = result.Values()
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

func (c *azureClient) GetVirtualMachine(ctx context.Context, resourceGroup string, name string) (*compute.VirtualMachine, error) {
	vm, err := c.v.Get(ctx, resourceGroup, name, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get virtual machine: %v", err)
	}
	return &vm, nil
}

func (c *azureClient) GetNetworkInterface(ctx context.Context, resourceGroup string, name string) (*network.Interface, error) {
	ni, err := c.n.Get(ctx, resourceGroup, name, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get network interface: %v", err)
	}
	return &ni, nil
}
