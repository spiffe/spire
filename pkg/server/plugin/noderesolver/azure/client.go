package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/go-autorest/autorest"
	"github.com/zeebo/errs"
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
		return "", errs.Wrap(err)
	}

	values := result.Values()
	if len(values) == 0 {
		return "", errs.New("principal %q not found", principalID)
	}
	if len(values) > 1 {
		return "", errs.New("expected one result for principal %q at most", principalID)
	}
	if values[0].ID == nil || *values[0].ID == "" {
		return "", errs.New("resource missing ID")
	}

	return *values[0].ID, nil
}

func (c *azureClient) GetVirtualMachine(ctx context.Context, resourceGroup string, name string) (*compute.VirtualMachine, error) {
	vm, err := c.v.Get(ctx, resourceGroup, name, "")
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &vm, nil
}

func (c *azureClient) GetNetworkInterface(ctx context.Context, resourceGroup string, name string) (*network.Interface, error) {
	ni, err := c.n.Get(ctx, resourceGroup, name, "")
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &ni, nil
}
