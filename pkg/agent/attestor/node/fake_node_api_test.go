package attestor

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"

	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"
	servernodeattestor "github.com/spiffe/spire/proto/spire/server/nodeattestor"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func startNodeServer(t *testing.T, tlsConfig *tls.Config, apiConfig fakeNodeAPIConfig) (string, func()) {
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	node.RegisterNodeServer(server, newFakeNodeAPI(apiConfig))
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	return listener.Addr().String(), func() {
		server.Stop()
		require.NoError(t, ignoreServerClosed(<-errCh))
	}
}

func ignoreServerClosed(err error) error {
	if err == grpc.ErrServerStopped {
		return nil
	}
	return err
}

type fakeNodeAPIConfig struct {
	CACert             *x509.Certificate
	Attestor           servernodeattestor.NodeAttestor
	OmitSVIDUpdate     bool
	OverrideSVIDUpdate *node.X509SVIDUpdate
	FailAttestCall     bool
}

type fakeNodeAPI struct {
	node.NodeServer
	c fakeNodeAPIConfig
}

func newFakeNodeAPI(config fakeNodeAPIConfig) *fakeNodeAPI {
	return &fakeNodeAPI{
		c: config,
	}
}

func (n *fakeNodeAPI) Attest(stream node.Node_AttestServer) error {
	// ensure streams are cleaned up
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	attestorStream, err := n.c.Attestor.Attest(ctx)
	if err != nil {
		return err
	}

	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		if n.c.FailAttestCall {
			return errors.New("attestation has been purposefully failed")
		}

		csr, err := x509.ParseCertificateRequest(req.Csr)
		if err != nil {
			return err
		}

		if req.AttestationData.Type == "join_token" {
			resp, err := n.createAttestResponse(csr, idutil.AgentID("domain.test", "/join_token/"+string(req.AttestationData.Data)))
			if err != nil {
				return err
			}

			return stream.Send(resp)
		}

		if err := attestorStream.Send(&servernodeattestor.AttestRequest{
			AttestationData: req.AttestationData,
			Response:        req.Response,
		}); err != nil {
			return err
		}

		attestResp, err := attestorStream.Recv()
		if err != nil {
			return err
		}

		if attestResp.Challenge != nil {
			if err := stream.Send(&node.AttestResponse{
				Challenge: attestResp.Challenge,
			}); err != nil {
				return err
			}
			continue
		}

		resp, err := n.createAttestResponse(csr, attestResp.AgentId)
		if err != nil {
			return err
		}

		return stream.Send(resp)
	}
}

func (n *fakeNodeAPI) createAttestResponse(csr *x509.CertificateRequest, agentID string) (*node.AttestResponse, error) {
	uri, err := idutil.ParseSpiffeID(agentID, idutil.AllowAnyTrustDomainAgent())
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		URIs:         []*url.URL{uri},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, n.c.CACert, csr.PublicKey, testKey)
	if err != nil {
		return nil, err
	}

	svidUpdate := &node.X509SVIDUpdate{
		Svids: map[string]*node.X509SVID{
			agentID: {
				CertChain: certDER,
			},
		},
		Bundles: map[string]*common.Bundle{
			"spiffe://domain.test": {
				TrustDomainId: "spiffe://domain.test",
				RootCas: []*common.Certificate{
					{DerBytes: n.c.CACert.Raw},
				},
			},
		},
	}

	if n.c.OverrideSVIDUpdate != nil {
		svidUpdate = n.c.OverrideSVIDUpdate
	}

	resp := &node.AttestResponse{}
	if !n.c.OmitSVIDUpdate {
		resp.SvidUpdate = svidUpdate
	}

	return resp, nil
}
