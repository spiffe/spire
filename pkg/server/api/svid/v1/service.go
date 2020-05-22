package svid

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/proto/spire-next/api/server/svid/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterService registers the service on the gRPC server.
func RegisterService(s *grpc.Server, service *Service) {
	svid.RegisterSVIDServer(s, service)
}

// Config is the service configuration
type Config struct {
	ServerCA    ca.ServerCA
	TrustDomain spiffeid.TrustDomain
}

// New creates a new SVID service
func New(config Config) *Service {
	return &Service{
		ca: config.ServerCA,
		td: config.TrustDomain,
	}
}

// Service implements the v1 SVID service
type Service struct {
	ca ca.ServerCA
	td spiffeid.TrustDomain
}

func (s *Service) MintX509SVID(ctx context.Context, req *svid.MintX509SVIDRequest) (*svid.MintX509SVIDResponse, error) {
	log := rpccontext.Logger(ctx)

	if len(req.Csr) == 0 {
		log.Error("Request missing CSR")
		return nil, status.Errorf(codes.InvalidArgument, "request missing CSR")
	}

	csr, err := x509.ParseCertificateRequest(req.Csr)
	if err != nil {
		log.WithError(err).Error("Malformed CSR")
		return nil, status.Errorf(codes.InvalidArgument, "malformed CSR: %v", err)
	}

	if err := csr.CheckSignature(); err != nil {
		log.WithError(err).Error("Invalid CSR: signature verify failed")
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: signature verify failed")
	}

	switch {
	case len(csr.URIs) == 0:
		log.Error("Invalid CSR: URI SAN is required")
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: URI SAN is required")
	case len(csr.URIs) > 1:
		log.Error("Invalid CSR: only one URI SAN is expected")
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: only one URI SAN is expected")
	}

	id, err := spiffeid.FromURI(csr.URIs[0])
	if err != nil {
		log.WithError(err).Error("Invalid CSR: URI SAN is not a valid SPIFFE ID")
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: URI SAN is not a valid SPIFFE ID: %v", err)
	}

	if err := idutil.ValidateTrustDomainWorkload(id, s.td); err != nil {
		log.Errorf("Invalid SPIFFE ID in CSR: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid SPIFFE ID in CSR: %v", err)
	}

	for _, dnsName := range csr.DNSNames {
		if err := x509util.ValidateDNS(dnsName); err != nil {
			log.WithError(err).Error("Invalid CSR: DNS name is not valid")
			return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: DNS name is not valid: %v", err)
		}
	}

	x509SVID, err := s.ca.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  id.String(),
		PublicKey: csr.PublicKey,
		TTL:       time.Duration(req.Ttl) * time.Second,
		DNSList:   csr.DNSNames,
		Subject:   csr.Subject,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign X509-SVID")
		return nil, status.Errorf(codes.Internal, "failed to sign X509-SVID: %v", err)
	}

	return &svid.MintX509SVIDResponse{
		Svid: &types.X509SVID{
			Id:        api.ProtoFromID(id),
			CertChain: x509util.RawCertsFromCertificates(x509SVID),
			ExpiresAt: x509SVID[0].NotAfter.Unix(),
		},
	}, nil
}

func (s *Service) MintJWTSVID(ctx context.Context, req *svid.MintJWTSVIDRequest) (*svid.MintJWTSVIDResponse, error) {
	log := rpccontext.Logger(ctx)

	id, err := api.IDFromProto(req.Id)
	if err != nil {
		log.WithError(err).Error("Failed to parse SPIFFE ID")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := idutil.ValidateTrustDomainWorkload(id, s.td); err != nil {
		log.Errorf("Invalid SPIFFE ID: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid SPIFFE ID: %v", err)
	}

	if len(req.Audience) == 0 {
		log.Error("At least one audience is required")
		return nil, status.Error(codes.InvalidArgument, "at least one audience is required")
	}

	token, err := s.ca.SignJWTSVID(ctx, ca.JWTSVIDParams{
		SpiffeID: id.String(),
		TTL:      time.Duration(req.Ttl) * time.Second,
		Audience: req.Audience,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign JWT-SVID")
		return nil, status.Errorf(codes.Internal, "failed to sign JWT-SVID: %v", err)
	}

	issuedAt, expiresAt, err := jwtsvid.GetTokenExpiry(token)
	if err != nil {
		log.WithError(err).Error("Failed to get JWT-SVID expiry")
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &svid.MintJWTSVIDResponse{
		Svid: &types.JWTSVID{
			Token:     token,
			Id:        api.ProtoFromID(id),
			ExpiresAt: expiresAt.Unix(),
			IssuedAt:  issuedAt.Unix(),
		},
	}, nil
}

func (s *Service) BatchNewX509SVID(context.Context, *svid.BatchNewX509SVIDRequest) (*svid.BatchNewX509SVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s *Service) NewJWTSVID(context.Context, *svid.NewJWTSVIDRequest) (*svid.NewJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s *Service) NewDownstreamX509CA(context.Context, *svid.NewDownstreamX509CARequest) (*svid.NewDownstreamX509CAResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
