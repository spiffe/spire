package workloadattestor

import (
	"context"
	"fmt"

	workloadattestorv2 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v2"

	"github.com/spiffe/spire-api-sdk/proto/spiffe/reference"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/protobuf/types/known/anypb"
)

type V2 struct {
	plugin.Facade
	workloadattestorv2.WorkloadAttestorPluginClient
}

func (v2 *V2) Attest(ctx context.Context, pid int) ([]*common.Selector, error) {
	pidInt32, err := util.CheckedCast[int32](pid)
	if err != nil {
		return nil, v2.WrapErr(fmt.Errorf("invalid value for PID: %w", err))
	}
	pidReference := reference.WorkloadPIDReference{
		Pid: pidInt32,
	}
	anyPidReference, err := anypb.New(&pidReference)
	if err != nil {
		return nil, v2.WrapErr(err)
	}

	return v2.AttestReference(ctx, anyPidReference)
}

func (v2 *V2) AttestReference(ctx context.Context, reference *anypb.Any) ([]*common.Selector, error) {
	resp, err := v2.WorkloadAttestorPluginClient.AttestReference(ctx, &workloadattestorv2.AttestReferenceRequest{
		Reference: reference,
	})
	if err != nil {
		return nil, v2.WrapErr(err)
	}

	var selectors []*common.Selector
	if resp.SelectorValues != nil {
		selectors = make([]*common.Selector, 0, len(resp.SelectorValues))
		for _, selectorValue := range resp.SelectorValues {
			selectors = append(selectors, &common.Selector{
				Type:  v2.Name(),
				Value: selectorValue,
			})
		}
	}
	return selectors, nil
}
