package azureimds

import (
	"context"
	"errors"
	"testing"

	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testAttestedVMID         = "550e8400-e29b-41d4-a716-446655440000"
	testAttestedSubscription = "SUBSCRIPTIONID"
	testResourceGroup        = "RESOURCEGROUP"
)

func TestResolveVirtualMachineFlexibleUsesStandardVMPath(t *testing.T) {
	client := &stubAPIClient{}
	flexID := "/subscriptions/SUBSCRIPTIONID/resourceGroups/RESOURCEGROUP/providers/Microsoft.Compute/virtualMachines/web-0"
	forgedVMSSName := "forged-ss"
	azureVMSSName := "flex-ss"
	rg := "RESOURCEGROUP"
	client.vm = &VirtualMachine{
		VMID:     "550e8400-e29b-41d4-a716-446655440000",
		VMSSName: azureVMSSName,
	}

	vm, ssName, err := resolveVirtualMachine(context.Background(), client, azure.AgentUntrustedMetadata{
		VMSSName:          &forgedVMSSName,
		ResourceGroupName: &rg,
		VMResourceID:      &flexID,
	}, "550e8400-e29b-41d4-a716-446655440000", "SUBSCRIPTIONID")
	require.NoError(t, err)
	require.Equal(t, client.vm, vm)
	require.NotNil(t, ssName)
	require.Equal(t, azureVMSSName, *ssName)
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

func TestResolveVirtualMachineRejectBadHints(t *testing.T) {
	flexID := "/subscriptions/" + testAttestedSubscription + "/resourceGroups/" + testResourceGroup + "/providers/Microsoft.Compute/virtualMachines/web-0"
	uniformID := "/subscriptions/" + testAttestedSubscription + "/resourceGroups/" + testResourceGroup + "/providers/Microsoft.Compute/virtualMachineScaleSets/myss/virtualMachines/0"
	wrongSubFlexID := "/subscriptions/other-sub/resourceGroups/" + testResourceGroup + "/providers/Microsoft.Compute/virtualMachines/web-0"
	unsupportedVMSSID := "/subscriptions/" + testAttestedSubscription + "/resourceGroups/" + testResourceGroup + "/providers/Microsoft.Compute/virtualMachineScaleSets/myss"
	wrongRG := "other-rg"
	vmssName := "myss"

	tests := []struct {
		name            string
		metadata        azure.AgentUntrustedMetadata
		setupClient     func(*stubAPIClient)
		wantCode        codes.Code
		wantMsgContains string
		wantVMCalls     int
		wantVMSSCalls   int
	}{
		{
			name: "vmResourceId subscription mismatch",
			metadata: azure.AgentUntrustedMetadata{
				VMResourceID: &wrongSubFlexID,
			},
			wantCode:        codes.InvalidArgument,
			wantMsgContains: "does not match attested subscription",
		},
		{
			name: "malformed vmResourceId",
			metadata: azure.AgentUntrustedMetadata{
				VMResourceID: strPtr("not-an-arm-id"),
			},
			wantCode:        codes.InvalidArgument,
			wantMsgContains: "invalid vmResourceId hint",
		},
		{
			name: "unsupported vmResourceId shape",
			metadata: azure.AgentUntrustedMetadata{
				VMResourceID: &unsupportedVMSSID,
			},
			wantCode:        codes.InvalidArgument,
			wantMsgContains: "unsupported vmResourceId hint",
		},
		{
			name: "resourceGroupName hint mismatches vmResourceId",
			metadata: azure.AgentUntrustedMetadata{
				VMResourceID:      &uniformID,
				ResourceGroupName: &wrongRG,
			},
			wantCode:        codes.InvalidArgument,
			wantMsgContains: "does not match vmResourceId resource group",
		},
		{
			name: "flexible path vmId mismatch after lookup",
			metadata: azure.AgentUntrustedMetadata{
				VMResourceID: &flexID,
			},
			setupClient: func(c *stubAPIClient) {
				c.vm = &VirtualMachine{VMID: "00000000-0000-0000-0000-000000000001"}
			},
			wantCode:        codes.InvalidArgument,
			wantMsgContains: "does not match attested vmId",
			wantVMCalls:     1,
		},
		{
			name: "uniform path vmId mismatch after lookup",
			metadata: azure.AgentUntrustedMetadata{
				VMResourceID: &uniformID,
			},
			setupClient: func(c *stubAPIClient) {
				c.vm = &VirtualMachine{VMID: "00000000-0000-0000-0000-000000000001"}
			},
			wantCode:        codes.InvalidArgument,
			wantMsgContains: "does not match attested vmId",
			wantVMSSCalls:   1,
		},
		{
			name: "legacy vmssName path vmId mismatch after lookup",
			metadata: azure.AgentUntrustedMetadata{
				VMSSName: &vmssName,
			},
			setupClient: func(c *stubAPIClient) {
				c.vm = &VirtualMachine{VMID: "00000000-0000-0000-0000-000000000001"}
			},
			wantCode:        codes.InvalidArgument,
			wantMsgContains: "does not match attested vmId",
			wantVMSSCalls:   1,
		},
		{
			name: "no hints vmId mismatch after lookup",
			metadata: azure.AgentUntrustedMetadata{},
			setupClient: func(c *stubAPIClient) {
				c.vm = &VirtualMachine{VMID: "00000000-0000-0000-0000-000000000001"}
			},
			wantCode:        codes.InvalidArgument,
			wantMsgContains: "does not match attested vmId",
			wantVMCalls:     1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &stubAPIClient{}
			if tt.setupClient != nil {
				tt.setupClient(client)
			}

			vm, ssName, err := resolveVirtualMachine(
				context.Background(),
				client,
				tt.metadata,
				testAttestedVMID,
				testAttestedSubscription,
			)
			require.Error(t, err)
			require.Nil(t, vm)
			require.Nil(t, ssName)

			st, ok := status.FromError(err)
			require.True(t, ok, "expected gRPC status error, got %v", err)
			require.Equal(t, tt.wantCode, st.Code())
			require.Contains(t, st.Message(), tt.wantMsgContains)
			require.Equal(t, tt.wantVMCalls, client.getVMCalls)
			require.Equal(t, tt.wantVMSSCalls, client.getVMSSCalls)
		})
	}
}

func strPtr(s string) *string {
	return &s
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
