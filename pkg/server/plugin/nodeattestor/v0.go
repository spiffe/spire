package nodeattestor

import (
	"context"
	"io"

	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/proto/spire/common"
	nodeattestorv0 "github.com/spiffe/spire/proto/spire/server/nodeattestor/v0"
	"google.golang.org/grpc/codes"
)

type V0 struct {
	plugin.Facade

	Plugin nodeattestorv0.NodeAttestor
}

func (v0 V0) Attest(ctx context.Context, payload []byte, challengeFn func(ctx context.Context, challenge []byte) ([]byte, error)) (*AttestResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := v0.Plugin.Attest(ctx)
	if err != nil {
		return nil, v0.WrapErr(err)
	}

	err = stream.Send(&nodeattestorv0.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: v0.Name(),
			Data: payload,
		},
	})
	if err != nil {
		return nil, v0.streamError(err)
	}

	var resp *nodeattestorv0.AttestResponse
	for {
		resp, err = stream.Recv()
		if err != nil {
			return nil, v0.streamError(err)
		}

		if len(resp.Challenge) == 0 {
			break
		}

		response, err := challengeFn(ctx, resp.Challenge)
		if err != nil {
			return nil, err
		}

		err = stream.Send(&nodeattestorv0.AttestRequest{
			Response: response,
		})
		if err != nil {
			return nil, v0.streamError(err)
		}
	}

	if resp.AgentId == "" {
		return nil, v0.Error(codes.Internal, "plugin response missing agent ID")
	}

	return &AttestResult{
		AgentID:   resp.AgentId,
		Selectors: resp.Selectors,
	}, nil
}

func (v0 V0) streamError(err error) error {
	if err == io.EOF {
		return v0.Error(codes.Internal, "plugin closed stream unexpectedly")
	}
	return v0.WrapErr(err)
}
