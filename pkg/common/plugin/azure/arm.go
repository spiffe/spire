package azure

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
)

const (
	resourceTypeVirtualMachines              = "Microsoft.Compute/virtualMachines"
	resourceTypeVirtualMachineScaleSets      = "Microsoft.Compute/virtualMachineScaleSets"
	resourceTypeVMSSVirtualMachines          = "Microsoft.Compute/virtualMachineScaleSets/virtualMachines"
)

// SubscriptionIDFromResourceID returns the subscription ID segment from a well-formed ARM resource ID.
func SubscriptionIDFromResourceID(resourceID string) (string, error) {
	id, err := arm.ParseResourceID(strings.TrimSpace(resourceID))
	if err != nil {
		return "", fmt.Errorf("malformed ARM resource ID %q", resourceID)
	}
	if id.SubscriptionID == "" {
		return "", fmt.Errorf("malformed ARM resource ID %q", resourceID)
	}
	return id.SubscriptionID, nil
}

// ParseUniformVMSSInstanceResourceID parses a Uniform VMSS instance ARM resource ID.
func ParseUniformVMSSInstanceResourceID(resourceID string) (resourceGroup, scaleSetName string, err error) {
	id, err := arm.ParseResourceID(strings.TrimSpace(resourceID))
	if err != nil {
		return "", "", fmt.Errorf("resource ID %q is not a uniform VMSS instance", resourceID)
	}
	if id.ResourceType.String() != resourceTypeVMSSVirtualMachines {
		return "", "", fmt.Errorf("resource ID %q is not a uniform VMSS instance", resourceID)
	}
	if id.Parent == nil || id.Parent.ResourceType.String() != resourceTypeVirtualMachineScaleSets {
		return "", "", fmt.Errorf("resource ID %q is not a uniform VMSS instance", resourceID)
	}
	return id.ResourceGroupName, id.Parent.Name, nil
}

// IsUniformVMSSInstanceResourceID reports whether resourceID refers to a Uniform scale set VM instance.
func IsUniformVMSSInstanceResourceID(resourceID string) bool {
	id, err := arm.ParseResourceID(strings.TrimSpace(resourceID))
	if err != nil {
		return false
	}
	return id.ResourceType.String() == resourceTypeVMSSVirtualMachines
}

// IsStandaloneVirtualMachineResourceID reports whether resourceID refers to a standard
// Microsoft.Compute/virtualMachines resource (including Flexible scale set members).
func IsStandaloneVirtualMachineResourceID(resourceID string) bool {
	id, err := arm.ParseResourceID(strings.TrimSpace(resourceID))
	if err != nil {
		return false
	}
	return id.ResourceType.String() == resourceTypeVirtualMachines
}
