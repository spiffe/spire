package nodeattestor

import (
	"context"
	"errors"
	"io"
	"net"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// This header contains the value of the gRPC :authority pseudo-header as received from the client.
	// Warning: This value is set by the client and is not authenticated or validated by SPIRE.
	// It must not be used for security decisions (such as authentication, authorization, or trust domain selection) in attestor plugins without threat assessment.
	// Valid uses include diagnostics, logging, or configuration side-loading
	XForwardedHostKey = "X-Untrusted-Forwarded-Host"
)

type V1 struct {
	plugin.Facade
	nodeattestorv1.NodeAttestorPluginClient
}

func (v1 *V1) Attest(ctx context.Context, payload []byte, challengeFn func(ctx context.Context, challenge []byte) ([]byte, error)) (*AttestResult, error) {
	switch {
	case len(payload) == 0:
		return nil, status.Error(codes.InvalidArgument, "payload cannot be empty")
	case challengeFn == nil:
		return nil, status.Error(codes.InvalidArgument, "challenge function cannot be nil")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// forward original request host to downstream plugins
	originalHost, err := getOriginalHost(ctx)
	if err != nil {
		v1.Log.WithError(err).Warn("Failed to extract ':authority' header from gRPC metadata")
	}
	ctx = metadata.AppendToOutgoingContext(ctx, XForwardedHostKey, originalHost)

	stream, err := v1.NodeAttestorPluginClient.Attest(ctx)
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	err = stream.Send(&nodeattestorv1.AttestRequest{
		Request: &nodeattestorv1.AttestRequest_Payload{
			Payload: payload,
		},
	})
	if err != nil {
		return nil, v1.streamError(err)
	}

	var attribs *nodeattestorv1.AgentAttributes
	for {
		resp, err := stream.Recv()
		if err != nil {
			return nil, v1.streamError(err)
		}

		if attribs = resp.GetAgentAttributes(); attribs != nil {
			break
		}

		challenge := resp.GetChallenge()
		if challenge == nil {
			return nil, v1.Error(codes.Internal, "plugin response missing challenge or agent attributes")
		}

		response, err := challengeFn(ctx, challenge)
		if err != nil {
			return nil, err
		}

		err = stream.Send(&nodeattestorv1.AttestRequest{
			Request: &nodeattestorv1.AttestRequest_ChallengeResponse{
				ChallengeResponse: response,
			},
		})
		if err != nil {
			return nil, v1.streamError(err)
		}
	}

	if attribs.SpiffeId == "" {
		return nil, v1.Error(codes.Internal, "plugin response missing agent ID")
	}

	var selectors []*common.Selector
	if attribs.SelectorValues != nil {
		selectors = make([]*common.Selector, 0, len(attribs.SelectorValues))
		for _, selectorValue := range attribs.SelectorValues {
			selectors = append(selectors, &common.Selector{
				Type:  v1.Name(),
				Value: selectorValue,
			})
		}
	}

	return &AttestResult{
		AgentID:     attribs.SpiffeId,
		Selectors:   selectors,
		CanReattest: attribs.CanReattest,
	}, nil
}

func (v1 *V1) streamError(err error) error {
	if errors.Is(err, io.EOF) {
		return v1.Error(codes.Internal, "plugin closed stream unexpectedly")
	}
	return v1.WrapErr(err)
}

func getOriginalHost(ctx context.Context) (string, error) {
	authority := metadata.ValueFromIncomingContext(ctx, ":authority")
	if len(authority) == 0 {
		return "", errors.New("empty :authority header")
	}
	// should be just one in a slice
	// example value: spire-server-xyz.spiffe.io:8081
	host, _, err := net.SplitHostPort(authority[0])
	if err != nil {
		return "", err
	}
	return host, nil
}
