package azureimds

import (
	"context"
	"errors"
	"testing"

	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/stretchr/testify/require"
)

func TestResolveVirtualMachineFlexibleUsesStandardVMPath(t *testing.T) {
	client := &stubAPIClient{}
	flexID := "/subscriptions/SUBSCRIPTIONID/resourceGroups/RESOURCEGROUP/providers/Microsoft.Compute/virtualMachines/web-0"
	vmssName := "flex-ss"
	rg := "RESOURCEGROUP"
	client.vm = &VirtualMachine{VMID: "550e8400-e29b-41d4-a716-446655440000"}

	vm, ssName, err := resolveVirtualMachine(context.Background(), client, azure.AgentUntrustedMetadata{
		VMSSName:          &vmssName,
		ResourceGroupName: &rg,
		VMResourceID:      &flexID,
	}, "550e8400-e29b-41d4-a716-446655440000", "SUBSCRIPTIONID")
	require.NoError(t, err)
	require.Equal(t, client.vm, vm)
	require.NotNil(t, ssName)
	require.Equal(t, "flex-ss", *ssName)
	require.Equal(t, 1, client.getVMCalls)
	require.Equal(t, 0, client.getVMSSCalls)
}

func TestResolveVirtualMachineUniformUsesVMSSPath(t *testing.T) {
	client := &stubAPIClient{}
	uniformID := "/subscriptions/SUBSCRIPTIONID/resourceGroups/RESOURCEGROUP/providers/Microsoft.Compute/virtualMachineScaleSets/myss/virtualMachines/0"
	rg := "RESOURCEGROUP"
	client.vm = &VirtualMachine{VMID: "550e8400-e29b-41d4-a716-446655440000"}

	vm, ssName, err := resolveVirtualMachine(context.Background(), client, azure.AgentUntrustedMetadata{
		ResourceGroupName: &rg,
		VMResourceID:      &uniformID,
	}, "550e8400-e29b-41d4-a716-446655440000", "SUBSCRIPTIONID")
	require.NoError(t, err)
	require.Equal(t, client.vm, vm)
	require.NotNil(t, ssName)
	require.Equal(t, "myss", *ssName)
	require.Equal(t, 0, client.getVMCalls)
	require.Equal(t, 1, client.getVMSSCalls)
}

type stubAPIClient struct {
	vm           *VirtualMachine
	getVMCalls   int
	getVMSSCalls int
}

func (s *stubAPIClient) GetVirtualMachine(context.Context, string, *string) (*VirtualMachine, error) {
	s.getVMCalls++
	if s.vm == nil {
		return nil, errors.New("not found")
	}
	return s.vm, nil
}

func (s *stubAPIClient) GetVMSSInstance(context.Context, string, string, string, *string) (*VirtualMachine, error) {
	s.getVMSSCalls++
	if s.vm == nil {
		return nil, errors.New("not found")
	}
	return s.vm, nil
}
