package workloadattestor

import (
	"context"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/reference"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type V1 struct {
	plugin.Facade
	workloadattestorv1.WorkloadAttestorPluginClient
}

// Attest invokes the plugin's PID-based Attest RPC. Older plugins implement
// only this RPC; newer plugins may instead implement only AttestReference.
// To bridge both styles, if Attest returns Unimplemented, we pack the PID as
// a WorkloadPIDReference and retry through AttestReference.
func (v1 *V1) Attest(ctx context.Context, pid int) ([]*common.Selector, error) {
	pidInt32, err := util.CheckedCast[int32](pid)
	if err != nil {
		return nil, v1.WrapErr(fmt.Errorf("invalid value for PID: %w", err))
	}

	selectors, err := v1.attestByPID(ctx, pidInt32)
	if status.Code(err) != codes.Unimplemented {
		return selectors, err
	}

	// Plugin doesn't implement Attest; try AttestReference with a packed
	// WorkloadPIDReference. We call the raw method directly to avoid an
	// infinite loop: if AttestReference is also unimplemented we surface the
	// original Unimplemented to the caller.
	ref, packErr := anypb.New(&reference.WorkloadPIDReference{Pid: pidInt32})
	if packErr != nil {
		return nil, v1.WrapErr(packErr)
	}
	return v1.attestByReference(ctx, ref)
}

// AttestReference invokes the plugin's reference-based AttestReference RPC.
// If the plugin returns Unimplemented and the supplied reference is a
// WorkloadPIDReference, we fall back to the legacy PID-based Attest. Other
// reference types surface the Unimplemented error directly because there's
// no equivalent legacy path.
func (v1 *V1) AttestReference(ctx context.Context, ref *anypb.Any) ([]*common.Selector, error) {
	selectors, err := v1.attestByReference(ctx, ref)
	if status.Code(err) != codes.Unimplemented {
		return selectors, err
	}

	pid, extractErr := extractPIDReference(ref)
	if extractErr != nil {
		// Plugin doesn't implement AttestReference and the reference isn't a
		// PID we can fall back on; surface the Unimplemented to the caller.
		return nil, err
	}
	return v1.attestByPID(ctx, pid)
}

// attestByPID is the raw plugin call without fallback. The wrapping
// public methods orchestrate the cross-RPC fallback so neither raw helper
// can recurse.
func (v1 *V1) attestByPID(ctx context.Context, pid int32) ([]*common.Selector, error) {
	resp, err := v1.WorkloadAttestorPluginClient.Attest(ctx, &workloadattestorv1.AttestRequest{
		Pid: pid,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}
	return v1.selectorsFrom(resp.SelectorValues), nil
}

// attestByReference is the raw plugin call without fallback.
func (v1 *V1) attestByReference(ctx context.Context, ref *anypb.Any) ([]*common.Selector, error) {
	resp, err := v1.WorkloadAttestorPluginClient.AttestReference(ctx, &workloadattestorv1.AttestReferenceRequest{
		Reference: ref,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}
	return v1.selectorsFrom(resp.SelectorValues), nil
}

func (v1 *V1) selectorsFrom(values []string) []*common.Selector {
	if values == nil {
		return nil
	}
	selectors := make([]*common.Selector, 0, len(values))
	for _, value := range values {
		selectors = append(selectors, &common.Selector{
			Type:  v1.Name(),
			Value: value,
		})
	}
	return selectors
}

func extractPIDReference(ref *anypb.Any) (int32, error) {
	if ref.GetTypeUrl() == "type.googleapis.com/spiffe.reference.WorkloadPIDReference" {
		var pidRef reference.WorkloadPIDReference
		if err := anypb.UnmarshalTo(ref, &pidRef, proto.UnmarshalOptions{}); err != nil {
			return 0, fmt.Errorf("unmarshaling PID reference: %w", err)
		}
		return pidRef.Pid, nil
	}
	return 0, errors.New("PID reference not found")
}
