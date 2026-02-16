package workloadattestor

import (
	"context"
	"errors"
	"fmt"

	"github.com/spiffe/spire-api-sdk/proto/spiffe/reference"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type V1 struct {
	plugin.Facade
	workloadattestorv1.WorkloadAttestorPluginClient
}

func (v1 *V1) Attest(ctx context.Context, pid int) ([]*common.Selector, error) {
	pidInt32, err := util.CheckedCast[int32](pid)
	if err != nil {
		return nil, v1.WrapErr(fmt.Errorf("invalid value for PID: %w", err))
	}
	resp, err := v1.WorkloadAttestorPluginClient.Attest(ctx, &workloadattestorv1.AttestRequest{
		Pid: pidInt32,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	var selectors []*common.Selector
	if resp.SelectorValues != nil {
		selectors = make([]*common.Selector, 0, len(resp.SelectorValues))
		for _, selectorValue := range resp.SelectorValues {
			selectors = append(selectors, &common.Selector{
				Type:  v1.Name(),
				Value: selectorValue,
			})
		}
	}
	return selectors, nil
}

func (v1 *V1) AttestReference(ctx context.Context, reference *anypb.Any) ([]*common.Selector, error) {
	pid, err := extractPIDReference(reference)
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return v1.Attest(ctx, int(pid))
}

func extractPIDReference(ref *anypb.Any) (int32, error) {
	if ref.GetTypeUrl() == "type.googleapis.com/spiffe.reference.WorkloadPIDReference" {
		var pidRef reference.WorkloadPIDReference
		if err := anypb.UnmarshalTo(ref, &pidRef, proto.UnmarshalOptions{}); err != nil {
			return 0, fmt.Errorf("unmarshaling PID reference: %w", err)
		}
		return pidRef.Pid, nil
	}
	return -1, errors.New("PID reference not found")
}
