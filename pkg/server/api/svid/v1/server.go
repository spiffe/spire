package svid

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/proto/spire-next/api/server/svid/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterService registers the service on the gRPC server.
func RegisterService(s *grpc.Server, service Service) {
	svid.RegisterSVIDServer(s, server{service: service})
}

type server struct {
	service Service
}

func (s server) MintX509SVID(ctx context.Context, req *svid.MintX509SVIDRequest) (*svid.MintX509SVIDResponse, error) {
	log := rpccontext.Logger(ctx)

	if len(req.Csr) == 0 {
		log.Error("Request missing CSR")
		return nil, status.Errorf(codes.InvalidArgument, "request missing CSR")
	}

	csr, err := x509.ParseCertificateRequest(req.Csr)
	if err != nil {
		log.WithError(err).Error("Invalid CSR")
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: %v", err)
	}

	x509Svid, err := s.service.MintX509SVID(ctx, csr, time.Duration(req.Ttl)*time.Second)
	if err != nil {
		return nil, err
	}

	return &svid.MintX509SVIDResponse{
		Svid: &types.X509SVID{
			Id: &types.SPIFFEID{
				TrustDomain: x509Svid.ID.TrustDomain().String(),
				Path:        x509Svid.ID.Path(),
			},
			CertChain: x509util.RawCertsFromCertificates(x509Svid.CertChain),
			ExpiresAt: x509Svid.ExpiresAt.Unix(),
		},
	}, nil
}

func (s server) MintJWTSVID(context.Context, *svid.MintJWTSVIDRequest) (*svid.MintJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s server) BatchNewX509SVID(context.Context, *svid.BatchNewX509SVIDRequest) (*svid.BatchNewX509SVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s server) NewJWTSVID(context.Context, *svid.NewJWTSVIDRequest) (*svid.NewJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s server) NewDownstreamX509CA(context.Context, *svid.NewDownstreamX509CARequest) (*svid.NewDownstreamX509CAResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
