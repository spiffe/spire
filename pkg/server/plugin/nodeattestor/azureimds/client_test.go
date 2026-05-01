package azureimds

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/stretchr/testify/require"
)

func TestParseNetworkInterfaceConfigNoNSG(t *testing.T) {
	nicName := "test-nic"
	subnetID := "/subscriptions/sub-123/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet-1/subnets/subnet-1"
	config := &armcompute.VirtualMachineScaleSetNetworkConfiguration{
		Name: &nicName,
		Properties: &armcompute.VirtualMachineScaleSetNetworkConfigurationProperties{
			IPConfigurations: []*armcompute.VirtualMachineScaleSetIPConfiguration{
				{
					Properties: &armcompute.VirtualMachineScaleSetIPConfigurationProperties{
						Subnet: &armcompute.APIEntityReference{
							ID: &subnetID,
						},
					},
				},
			},
		},
	}

	ni, err := parseNetworkInterfaceConfig(config)
	require.NoError(t, err)
	require.Equal(t, nicName, ni.Name)
	require.Equal(t, SecurityGroup{}, ni.SecurityGroup)
	require.Len(t, ni.Subnets, 1)
	require.Equal(t, "vnet-1", ni.Subnets[0].VNet)
	require.Equal(t, "subnet-1", ni.Subnets[0].SubnetName)
}

func TestParseNetworkInterfaceConfigNoSubnets(t *testing.T) {
	nicName := "test-nic"
	nsgID := "/subscriptions/sub-123/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/nsg-1"

	tests := []struct {
		name   string
		config *armcompute.VirtualMachineScaleSetNetworkConfiguration
	}{
		{
			name: "nil ip configurations",
			config: &armcompute.VirtualMachineScaleSetNetworkConfiguration{
				Name: &nicName,
				Properties: &armcompute.VirtualMachineScaleSetNetworkConfigurationProperties{
					NetworkSecurityGroup: &armcompute.SubResource{ID: &nsgID},
				},
			},
		},
		{
			name: "empty ip configurations",
			config: &armcompute.VirtualMachineScaleSetNetworkConfiguration{
				Name: &nicName,
				Properties: &armcompute.VirtualMachineScaleSetNetworkConfigurationProperties{
					NetworkSecurityGroup: &armcompute.SubResource{ID: &nsgID},
					IPConfigurations:     []*armcompute.VirtualMachineScaleSetIPConfiguration{},
				},
			},
		},
		{
			name: "ip config with nil subnet",
			config: &armcompute.VirtualMachineScaleSetNetworkConfiguration{
				Name: &nicName,
				Properties: &armcompute.VirtualMachineScaleSetNetworkConfigurationProperties{
					NetworkSecurityGroup: &armcompute.SubResource{ID: &nsgID},
					IPConfigurations: []*armcompute.VirtualMachineScaleSetIPConfiguration{
						{
							Properties: &armcompute.VirtualMachineScaleSetIPConfigurationProperties{},
						},
					},
				},
			},
		},
		{
			name: "nil properties",
			config: &armcompute.VirtualMachineScaleSetNetworkConfiguration{
				Name: &nicName,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ni, err := parseNetworkInterfaceConfig(tc.config)
			require.NoError(t, err)
			require.Equal(t, nicName, ni.Name)
			require.Empty(t, ni.Subnets)
		})
	}
}

func TestBuildVirtualMachineFromVMSSInstanceNilFields(t *testing.T) {
	id := "vm-id"
	name := "vm-name"
	location := "westus"
	vmID := "vm-guid"

	tests := []struct {
		name     string
		instance *armcompute.VirtualMachineScaleSetVM
		errMsg   string
	}{
		{
			name:     "nil instance",
			instance: nil,
			errMsg:   "vmss instance is nil",
		},
		{
			name: "nil ID",
			instance: &armcompute.VirtualMachineScaleSetVM{
				Name:     &name,
				Location: &location,
				Properties: &armcompute.VirtualMachineScaleSetVMProperties{
					VMID: &vmID,
				},
			},
			errMsg: "vmss instance ID is nil",
		},
		{
			name: "nil name",
			instance: &armcompute.VirtualMachineScaleSetVM{
				ID:       &id,
				Location: &location,
				Properties: &armcompute.VirtualMachineScaleSetVMProperties{
					VMID: &vmID,
				},
			},
			errMsg: "vmss instance name is nil",
		},
		{
			name: "nil location",
			instance: &armcompute.VirtualMachineScaleSetVM{
				ID:   &id,
				Name: &name,
				Properties: &armcompute.VirtualMachineScaleSetVMProperties{
					VMID: &vmID,
				},
			},
			errMsg: "vmss instance location is nil",
		},
		{
			name: "nil properties",
			instance: &armcompute.VirtualMachineScaleSetVM{
				ID:       &id,
				Name:     &name,
				Location: &location,
			},
			errMsg: "vmss instance properties are nil",
		},
		{
			name: "nil VMID",
			instance: &armcompute.VirtualMachineScaleSetVM{
				ID:         &id,
				Name:       &name,
				Location:   &location,
				Properties: &armcompute.VirtualMachineScaleSetVMProperties{},
			},
			errMsg: "vmss instance VM ID is nil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vm, err := buildVirtualMachineFromVMSSInstance(tc.instance, "rg")
			require.Error(t, err)
			require.Nil(t, vm)
			require.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

func TestBuildVirtualMachineFromVMSSInstanceNoNetworkProfile(t *testing.T) {
	id := "vm-id"
	name := "vm-name"
	location := "westus"
	vmID := "vm-guid"

	instance := &armcompute.VirtualMachineScaleSetVM{
		ID:       &id,
		Name:     &name,
		Location: &location,
		Properties: &armcompute.VirtualMachineScaleSetVMProperties{
			VMID: &vmID,
		},
	}

	vm, err := buildVirtualMachineFromVMSSInstance(instance, "rg")
	require.NoError(t, err)
	require.Equal(t, id, vm.ID)
	require.Equal(t, name, vm.Name)
	require.Equal(t, location, vm.Location)
	require.Equal(t, vmID, vm.VMID)
	require.Equal(t, "rg", vm.ResourceGroup)
	require.Empty(t, vm.Interfaces)
}
