package attestor

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"google.golang.org/grpc"
)

func (a *attestor) getSVID(ctx context.Context, conn *grpc.ClientConn, csr []byte, attestor nodeattestor.NodeAttestor) ([]*x509.Certificate, bool, error) {
	// make sure all of the streams are cancelled if something goes awry
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream := &ServerStream{Client: agentv1.NewAgentClient(conn), Csr: csr, Log: a.c.Log}

	if err := attestor.Attest(ctx, stream); err != nil {
		return nil, false, err
	}

	return stream.SVID, stream.Reattestable, nil
}

func (a *attestor) getBundle(ctx context.Context, conn *grpc.ClientConn) (*spiffebundle.Bundle, error) {
	updatedBundle, err := bundlev1.NewBundleClient(conn).GetBundle(ctx, &bundlev1.GetBundleRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get updated bundle %w", err)
	}

	b, err := bundleutil.CommonBundleFromProto(updatedBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trust domain bundle: %w", err)
	}

	bundle, err := bundleutil.SPIFFEBundleFromProto(b)
	if err != nil {
		return nil, fmt.Errorf("invalid trust domain bundle: %w", err)
	}

	return bundle, err
}

func getSVIDFromAttestAgentResponse(r *agentv1.AttestAgentResponse) ([]*x509.Certificate, error) {
	if r.GetResult().Svid == nil {
		return nil, errors.New("attest response is missing SVID")
	}

	svid, err := x509util.RawCertsToCertificates(r.GetResult().Svid.CertChain)
	if err != nil {
		return nil, fmt.Errorf("invalid SVID cert chain: %w", err)
	}

	if len(svid) == 0 {
		return nil, errors.New("empty SVID cert chain")
	}

	return svid, nil
}

type ServerStream struct {
	Client       agentv1.AgentClient
	Csr          []byte
	Log          logrus.FieldLogger
	SVID         []*x509.Certificate
	Reattestable bool
	stream       agentv1.Agent_AttestAgentClient
}

func (ss *ServerStream) SendAttestationData(ctx context.Context, attestationData nodeattestor.AttestationData) ([]byte, error) {
	return ss.sendRequest(ctx, &agentv1.AttestAgentRequest{
		Step: &agentv1.AttestAgentRequest_Params_{
			Params: &agentv1.AttestAgentRequest_Params{
				Data: &types.AttestationData{
					Type:    attestationData.Type,
					Payload: attestationData.Payload,
				},
				Params: &agentv1.AgentX509SVIDParams{
					Csr: ss.Csr,
				},
			},
		},
	})
}

func (ss *ServerStream) SendChallengeResponse(ctx context.Context, response []byte) ([]byte, error) {
	return ss.sendRequest(ctx, &agentv1.AttestAgentRequest{
		Step: &agentv1.AttestAgentRequest_ChallengeResponse{
			ChallengeResponse: response,
		},
	})
}

func (ss *ServerStream) sendRequest(ctx context.Context, req *agentv1.AttestAgentRequest) ([]byte, error) {
	if ss.stream == nil {
		stream, err := ss.Client.AttestAgent(ctx)
		if err != nil {
			return nil, fmt.Errorf("could not open attestation stream to SPIRE server: %w", err)
		}
		ss.stream = stream
	}

	if err := ss.stream.Send(req); err != nil {
		return nil, fmt.Errorf("failed to send attestation request to SPIRE server: %w", err)
	}

	resp, err := ss.stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive attestation response: %w", err)
	}

	if challenge := resp.GetChallenge(); challenge != nil {
		return challenge, nil
	}

	svid, err := getSVIDFromAttestAgentResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation response: %w", err)
	}

	if err := ss.stream.CloseSend(); err != nil {
		ss.Log.WithError(err).Warn("failed to close stream send side")
	}

	ss.Reattestable = resp.GetResult().Reattestable
	ss.SVID = svid
	return nil, nil
}
