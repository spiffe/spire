package attestor

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc"
)

func (a *attestor) getSVID(ctx context.Context, conn *grpc.ClientConn, csr []byte, fetchStream nodeattestor.NodeAttestor_FetchAttestationDataClient) ([]*x509.Certificate, error) {
	data, err := a.fetchAttestationData(fetchStream, nil)
	if err != nil {
		return nil, err
	}

	attestReq := &agentv1.AttestAgentRequest{
		Step: &agentv1.AttestAgentRequest_Params_{
			Params: &agentv1.AttestAgentRequest_Params{
				Data: protoFromAttestationData(data.AttestationData),
				Params: &agentv1.AgentX509SVIDParams{
					Csr: csr,
				},
			},
		},
	}

	attestStream, err := agentv1.NewAgentClient(conn).AttestAgent(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create new agent client for attestation: %v", err)
	}

	if err := attestStream.Send(attestReq); err != nil {
		return nil, fmt.Errorf("error sending attestation request to SPIRE server: %v", err)
	}

	var attestResp *agentv1.AttestAgentResponse
	for {
		// if the response has no additional data then break out and parse
		// the response.
		attestResp, err = attestStream.Recv()
		if err != nil {
			return nil, fmt.Errorf("error getting attestation response from SPIRE server: %v", err)
		}
		if attestResp.GetChallenge() == nil {
			break
		}

		data, err := a.fetchAttestationData(fetchStream, attestResp.GetChallenge())
		if err != nil {
			return nil, err
		}

		attestReq = &agentv1.AttestAgentRequest{
			Step: &agentv1.AttestAgentRequest_ChallengeResponse{
				ChallengeResponse: data.Response,
			},
		}

		if err := attestStream.Send(attestReq); err != nil {
			return nil, fmt.Errorf("sending attestation request to SPIRE server: %v", err)
		}
	}

	if fetchStream != nil {
		if err := fetchStream.CloseSend(); err != nil {
			return nil, fmt.Errorf("failed to close send on fetch stream: %v", err)
		}
		if _, err := fetchStream.Recv(); err != io.EOF {
			a.c.Log.WithError(err).Warn("Received unexpected result on trailing recv")
		}
	}
	if err := attestStream.CloseSend(); err != nil {
		return nil, fmt.Errorf("failed to close send on attest stream: %v", err)
	}

	if _, err := attestStream.Recv(); err != io.EOF {
		a.c.Log.WithError(err).Warn("Received unexpected result on trailing recv")
	}

	svid, err := getSVIDFromAttestAgentResponse(attestResp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation response: %v", err)
	}

	return svid, nil
}

func (a *attestor) getBundle(ctx context.Context, conn *grpc.ClientConn) (*bundleutil.Bundle, error) {
	updatedBundle, err := bundlev1.NewBundleClient(conn).GetBundle(ctx, &bundlev1.GetBundleRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get updated bundle %v", err)
	}

	b, err := bundleutil.CommonBundleFromProto(updatedBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trust domain bundle: %v", err)
	}

	bundle, err := bundleutil.BundleFromProto(b)
	if err != nil {
		return nil, fmt.Errorf("invalid trust domain bundle: %v", err)
	}

	return bundle, err
}

func getSVIDFromAttestAgentResponse(r *agentv1.AttestAgentResponse) ([]*x509.Certificate, error) {
	if r.GetResult().Svid == nil {
		return nil, errors.New("attest response is missing SVID")
	}

	svid, err := x509util.RawCertsToCertificates(r.GetResult().Svid.CertChain)
	if err != nil {
		return nil, fmt.Errorf("invalid SVID cert chain: %v", err)
	}

	if len(svid) == 0 {
		return nil, errors.New("empty SVID cert chain")
	}

	return svid, nil
}

func protoFromAttestationData(attData *common.AttestationData) *types.AttestationData {
	if attData == nil {
		return nil
	}

	return &types.AttestationData{
		Type:    attData.Type,
		Payload: attData.Data,
	}
}
