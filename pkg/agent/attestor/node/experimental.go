package attestor

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire-next/api/server/agent/v1"
	bundlepb "github.com/spiffe/spire/proto/spire-next/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc"
)

func (a *attestor) getSVID(ctx context.Context, conn *grpc.ClientConn, csr []byte, fetchStream nodeattestor.NodeAttestor_FetchAttestationDataClient) ([]*x509.Certificate, error) {
	attestStream, err := a.createNewAgentClient(conn).AttestAgent(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create new agent client for attestation: %v", err)
	}

	attestResp := new(agent.AttestAgentResponse)
	for {
		data, err := a.fetchAttestationData(fetchStream, attestResp.GetChallenge())
		if err != nil {
			return nil, err
		}

		var attestReq *agent.AttestAgentRequest
		if data.AttestationData != nil {
			attestReq = &agent.AttestAgentRequest{
				Step: &agent.AttestAgentRequest_Params_{
					Params: &agent.AttestAgentRequest_Params{
						Data: protoFromAttestationData(data.AttestationData),
						Params: &agent.AgentX509SVIDParams{
							Csr: csr,
						},
					},
				},
			}
		} else {
			attestReq = &agent.AttestAgentRequest{
				Step: &agent.AttestAgentRequest_ChallengeResponse{
					ChallengeResponse: data.Response,
				},
			}
		}
		if err := attestStream.Send(attestReq); err != nil {
			return nil, fmt.Errorf("sending attestation request to SPIRE server: %v", err)
		}

		attestResp, err = attestStream.Recv()
		if err != nil {
			return nil, fmt.Errorf("error getting attestation response from SPIRE server: %v", err)
		}

		// if the response has no additional data then break out and parse
		// the response.
		if attestResp.GetChallenge() == nil {
			break
		}
	}

	if fetchStream != nil {
		if err := fetchStream.CloseSend(); err != nil {
			return nil, fmt.Errorf("failed to close send on fetch stream: %v", err)
		}
		if _, err := fetchStream.Recv(); err != io.EOF {
			a.c.Log.WithError(err).Warn("received unexpected result on trailing recv")
		}
	}
	if err := attestStream.CloseSend(); err != nil {
		return nil, fmt.Errorf("failed to close send on attest stream: %v", err)
	}

	if _, err := attestStream.Recv(); err != io.EOF {
		a.c.Log.WithError(err).Warn("received unexpected result on trailing recv")
	}

	svid, err := getSVIDFromAttestAgentResponse(attestResp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation response: %v", err)
	}

	return svid, nil
}

func (a *attestor) getBundle(ctx context.Context, conn *grpc.ClientConn) (*bundleutil.Bundle, error) {
	updatedBundle, err := a.createNewBundleClient(conn).GetBundle(ctx, &bundlepb.GetBundleRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get updated bundle %v", err)
	}

	b, err := api.ProtoToBundle(updatedBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trust domain bundle: %v", err)
	}

	bundle, err := bundleutil.BundleFromProto(b)
	if err != nil {
		return nil, fmt.Errorf("invalid trust domain bundle: %v", err)
	}

	return bundle, err
}

func getSVIDFromAttestAgentResponse(r *agent.AttestAgentResponse) ([]*x509.Certificate, error) {
	if r.GetResult().Svid == nil {
		return nil, errors.New("missing svid update")
	}

	var svid []*x509.Certificate
	for _, rawCert := range r.GetResult().Svid.CertChain {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, fmt.Errorf("invalid svid cert chain: %v", err)
		}
		svid = append(svid, cert)
	}

	if len(svid) == 0 {
		return nil, errors.New("empty svid cert chain")
	}

	return svid, nil
}

func protoFromAttestationData(attData *common.AttestationData) *types.AttestationData {
	if attData == nil {
		return nil
	}

	return &types.AttestationData{
		Type:    attData.Type,
		Payload: string(attData.Data),
	}
}
