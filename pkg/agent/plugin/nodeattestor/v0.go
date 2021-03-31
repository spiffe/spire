package nodeattestor

import (
	"context"
	"io"

	"github.com/spiffe/spire/pkg/common/plugin"
	nodeattestorv0 "github.com/spiffe/spire/proto/spire/plugin/agent/nodeattestor/v0"
	"google.golang.org/grpc/codes"
)

type V0 struct {
	plugin.Facade

	Plugin nodeattestorv0.NodeAttestor
}

func (v0 V0) Attest(ctx context.Context, serverStream ServerStream) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	pluginStream, err := v0.Plugin.FetchAttestationData(ctx)
	if err != nil {
		return v0.WrapErr(err)
	}

	resp, err := pluginStream.Recv()
	switch {
	case err == io.EOF:
		return v0.Error(codes.Internal, "plugin closed stream before returning attestation data")
	case err != nil:
		return v0.WrapErr(err)
	}

	switch {
	case resp.AttestationData == nil:
		return v0.Error(codes.Internal, "plugin response missing attestation data")
	case resp.AttestationData.Type == "":
		return v0.Error(codes.Internal, "plugin response missing attestation data type")
	case resp.AttestationData.Data == nil:
		return v0.Error(codes.Internal, "plugin response missing attestation data payload")
	}

	challenge, err := serverStream.SendAttestationData(ctx, AttestationData{
		Type:    resp.AttestationData.Type,
		Payload: resp.AttestationData.Data,
	})
	if err != nil {
		return err
	}

	for {
		if challenge == nil {
			return nil
		}

		err = pluginStream.Send(&nodeattestorv0.FetchAttestationDataRequest{
			Challenge: challenge,
		})
		switch {
		case err == io.EOF:
			return v0.Error(codes.Internal, "plugin closed stream after being issued a challenge")
		case err != nil:
			return v0.WrapErr(err)
		}

		resp, err := pluginStream.Recv()
		switch {
		case err != nil:
			return v0.WrapErr(err)
		case resp.Response == nil:
			return v0.Error(codes.Internal, "plugin response missing challenge response")
		}

		challenge, err = serverStream.SendChallengeResponse(ctx, resp.Response)
		if err != nil {
			return err
		}
	}
}
