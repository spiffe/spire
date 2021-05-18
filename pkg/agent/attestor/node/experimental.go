package attestor

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"google.golang.org/grpc"
)

func (a *attestor) getSVID(ctx context.Context, conn *grpc.ClientConn, csr []byte, attestor nodeattestor.NodeAttestor) ([]*x509.Certificate, error) {
	// make sure all of the streams are cancelled if something goes awry
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream := &serverStream{client: agentv1.NewAgentClient(conn), csr: csr}

	if err := attestor.Attest(ctx, stream); err != nil {
		return nil, err
	}

	return stream.svid, nil
}

func (a *attestor) getBundle(ctx context.Context, conn *grpc.ClientConn) (*bundleutil.Bundle, error) {
	updatedBundle, err := bundlev1.NewBundleClient(conn).GetBundle(ctx, &bundlev1.GetBundleRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get updated bundle %w", err)
	}

	b, err := bundleutil.CommonBundleFromProto(updatedBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trust domain bundle: %w", err)
	}

	bundle, err := bundleutil.BundleFromProto(b)
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

type serverStream struct {
	log    logrus.FieldLogger
	client agentv1.AgentClient
	csr    []byte
	stream agentv1.Agent_AttestAgentClient
	svid   []*x509.Certificate
}

func (ss *serverStream) SendAttestationData(ctx context.Context, attestationData nodeattestor.AttestationData) ([]byte, error) {
	return ss.sendRequest(ctx, &agentv1.AttestAgentRequest{
		Step: &agentv1.AttestAgentRequest_Params_{
			Params: &agentv1.AttestAgentRequest_Params{
				Data: &types.AttestationData{
					Type:    attestationData.Type,
					Payload: attestationData.Payload,
				},
				Params: &agentv1.AgentX509SVIDParams{
					Csr: ss.csr,
				},
			},
		},
	})
}

func (ss *serverStream) SendChallengeResponse(ctx context.Context, response []byte) ([]byte, error) {
	return ss.sendRequest(ctx, &agentv1.AttestAgentRequest{
		Step: &agentv1.AttestAgentRequest_ChallengeResponse{
			ChallengeResponse: response,
		},
	})
}

func (ss *serverStream) sendRequest(ctx context.Context, req *agentv1.AttestAgentRequest) ([]byte, error) {
	if ss.stream == nil {
		stream, err := ss.client.AttestAgent(ctx)
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
		ss.log.WithError(err).Warn("failed to close stream send side")
	}

	ss.svid = svid
	return nil, nil
}
