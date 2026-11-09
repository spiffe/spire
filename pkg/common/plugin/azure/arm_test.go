package azure

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSubscriptionIDFromResourceID(t *testing.T) {
	sub, err := SubscriptionIDFromResourceID("/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm")
	require.NoError(t, err)
	require.Equal(t, "abc", sub)

	_, err = SubscriptionIDFromResourceID("not-an-id")
	require.Error(t, err)
}

func TestUniformVMSSInstanceResourceID(t *testing.T) {
	id := "/subscriptions/sub/resourceGroups/prod/providers/Microsoft.Compute/virtualMachineScaleSets/myss/virtualMachines/0"
	require.True(t, IsUniformVMSSInstanceResourceID(id))
	require.False(t, IsStandaloneVirtualMachineResourceID(id))

	rg, ss, err := ParseUniformVMSSInstanceResourceID(id)
	require.NoError(t, err)
	require.Equal(t, "prod", rg)
	require.Equal(t, "myss", ss)
}

func TestStandaloneVirtualMachineResourceID(t *testing.T) {
	id := "/subscriptions/sub/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/web-0"
	require.True(t, IsStandaloneVirtualMachineResourceID(id))
	require.False(t, IsUniformVMSSInstanceResourceID(id))
}
