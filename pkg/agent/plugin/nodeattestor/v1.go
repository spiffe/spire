package nodeattestor

import (
	"context"
	"errors"
	"io"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	"github.com/spiffe/spire/pkg/common/plugin"
	"google.golang.org/grpc/codes"
)

type V1 struct {
	plugin.Facade
	nodeattestorv1.NodeAttestorPluginClient
}

func (v1 *V1) Attest(ctx context.Context, serverStream ServerStream) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	pluginStream, err := v1.NodeAttestorPluginClient.AidAttestation(ctx)
	if err != nil {
		return v1.WrapErr(err)
	}

	payloadOrChallengeResponse, err := pluginStream.Recv()
	switch {
	case errors.Is(err, io.EOF):
		return v1.Error(codes.Internal, "plugin closed stream before returning attestation data")
	case err != nil:
		return v1.WrapErr(err)
	}

	payload := payloadOrChallengeResponse.GetPayload()
	if len(payload) == 0 {
		return v1.Error(codes.Internal, "plugin response missing attestation payload")
	}

	challenge, err := serverStream.SendAttestationData(ctx, AttestationData{
		Type:    v1.Name(),
		Payload: payload,
	})
	if err != nil {
		return err
	}

	for {
		if challenge == nil {
			return nil
		}

		err = pluginStream.Send(&nodeattestorv1.Challenge{
			Challenge: challenge,
		})
		switch {
		case errors.Is(err, io.EOF):
			return v1.Error(codes.Internal, "plugin closed stream before handling the challenge")
		case err != nil:
			return v1.WrapErr(err)
		}

		payloadOrChallengeResponse, err := pluginStream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			return v1.Error(codes.Internal, "plugin closed stream before handling the challenge")
		case err != nil:
			return v1.WrapErr(err)
		}

		challengeResponse := payloadOrChallengeResponse.GetChallengeResponse()
		if len(challengeResponse) == 0 {
			return v1.Error(codes.Internal, "plugin response missing challenge response")
		}

		challenge, err = serverStream.SendChallengeResponse(ctx, challengeResponse)
		if err != nil {
			return err
		}
	}
}
