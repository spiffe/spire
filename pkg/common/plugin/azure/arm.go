package azure

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	reResourceIDSubscription = regexp.MustCompile(`(?i)^/subscriptions/([^/]+)/`)
	reUniformVMSSInstanceID  = regexp.MustCompile(`(?i)^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft\.Compute/virtualMachineScaleSets/([^/]+)/virtualMachines/[^/]+$`)
	reStandaloneVMResourceID = regexp.MustCompile(`(?i)^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft\.Compute/virtualMachines/([^/]+)$`)
)

// SubscriptionIDFromResourceID returns the subscription ID segment from a well-formed ARM resource ID.
func SubscriptionIDFromResourceID(resourceID string) (string, error) {
	m := reResourceIDSubscription.FindStringSubmatch(strings.TrimSpace(resourceID))
	if m == nil {
		return "", fmt.Errorf("malformed ARM resource ID %q", resourceID)
	}
	return m[1], nil
}

// ParseUniformVMSSInstanceResourceID parses a Uniform VMSS instance ARM resource ID.
func ParseUniformVMSSInstanceResourceID(resourceID string) (resourceGroup, scaleSetName string, err error) {
	m := reUniformVMSSInstanceID.FindStringSubmatch(strings.TrimSpace(resourceID))
	if m == nil {
		return "", "", fmt.Errorf("resource ID %q is not a uniform VMSS instance", resourceID)
	}
	return m[1], m[2], nil
}

// IsUniformVMSSInstanceResourceID reports whether resourceID refers to a Uniform scale set VM instance.
func IsUniformVMSSInstanceResourceID(resourceID string) bool {
	return reUniformVMSSInstanceID.MatchString(strings.TrimSpace(resourceID))
}

// IsStandaloneVirtualMachineResourceID reports whether resourceID refers to a standard
// Microsoft.Compute/virtualMachines resource (including Flexible scale set members).
func IsStandaloneVirtualMachineResourceID(resourceID string) bool {
	return reStandaloneVMResourceID.MatchString(strings.TrimSpace(resourceID))
}
