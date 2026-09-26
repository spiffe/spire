package azureimds

import (
	"context"
	"strings"

	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func validateVMResourceIDHint(vmResourceID, subscriptionID string) error {
	sub, err := azure.SubscriptionIDFromResourceID(vmResourceID)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid vmResourceId hint: %v", err)
	}
	if !strings.EqualFold(sub, subscriptionID) {
		return status.Errorf(codes.InvalidArgument, "vmResourceId hint subscription %q does not match attested subscription %q", sub, subscriptionID)
	}
	return nil
}

func bindVirtualMachineIdentity(vm *VirtualMachine, vmID string) error {
	if vm == nil {
		return status.Error(codes.Internal, "virtual machine lookup returned nil")
	}
	if !strings.EqualFold(vm.VMID, vmID) {
		return status.Errorf(codes.InvalidArgument, "virtual machine vmId %q does not match attested vmId %q", vm.VMID, vmID)
	}
	return nil
}

func resolveVirtualMachine(ctx context.Context, client apiClient, md azure.AgentUntrustedMetadata, vmID, subscriptionID string) (*VirtualMachine, *string, error) {
	if md.VMResourceID != nil && *md.VMResourceID != "" {
		if err := validateVMResourceIDHint(*md.VMResourceID, subscriptionID); err != nil {
			return nil, nil, err
		}
		switch {
		case azure.IsUniformVMSSInstanceResourceID(*md.VMResourceID):
			rgFromID, ssFromID, err := azure.ParseUniformVMSSInstanceResourceID(*md.VMResourceID)
			if err != nil {
				return nil, nil, status.Errorf(codes.InvalidArgument, "invalid vmResourceId hint: %v", err)
			}
			rgHint, err := mergeResourceGroupHint(md.ResourceGroupName, rgFromID)
			if err != nil {
				return nil, nil, err
			}
			vm, err := client.GetVMSSInstance(ctx, vmID, subscriptionID, ssFromID, rgHint)
			if err != nil {
				return nil, nil, err
			}
			if err := bindVirtualMachineIdentity(vm, vmID); err != nil {
				return nil, nil, err
			}
			ssName := ssFromID
			return vm, &ssName, nil
		case azure.IsStandaloneVirtualMachineResourceID(*md.VMResourceID):
			vm, err := client.GetVirtualMachine(ctx, vmID, &subscriptionID)
			if err != nil {
				return nil, nil, err
			}
			if err := bindVirtualMachineIdentity(vm, vmID); err != nil {
				return nil, nil, err
			}
			return vm, md.VMSSName, nil
		default:
			return nil, nil, status.Errorf(codes.InvalidArgument, "unsupported vmResourceId hint %q", *md.VMResourceID)
		}
	}

	switch {
	case md.VMSSName != nil:
		vm, err := client.GetVMSSInstance(ctx, vmID, subscriptionID, *md.VMSSName, md.ResourceGroupName)
		if err != nil {
			return nil, nil, err
		}
		if err := bindVirtualMachineIdentity(vm, vmID); err != nil {
			return nil, nil, err
		}
		return vm, md.VMSSName, nil
	default:
		vm, err := client.GetVirtualMachine(ctx, vmID, &subscriptionID)
		if err != nil {
			return nil, nil, err
		}
		if err := bindVirtualMachineIdentity(vm, vmID); err != nil {
			return nil, nil, err
		}
		return vm, nil, nil
	}
}

func mergeResourceGroupHint(hint *string, fromResourceID string) (*string, error) {
	if hint != nil && *hint != "" {
		if !strings.EqualFold(*hint, fromResourceID) {
			return nil, status.Errorf(codes.InvalidArgument, "resourceGroupName hint %q does not match vmResourceId resource group %q", *hint, fromResourceID)
		}
		return hint, nil
	}
	rg := fromResourceID
	return &rg, nil
}
