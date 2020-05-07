package svid

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Config is the service configuration
type Config struct {
}

// Service is the SVID service interface
type Service interface {
	MintX509SVID(ctx context.Context, csr *x509.CertificateRequest, ttl time.Duration) (*api.X509SVID, error)
	MintJWTSVID(ctx context.Context, id spiffeid.ID, audience []string, ttl time.Duration) (*api.JWTSVID, error)
	NewX509SVID(ctx context.Context, entryID string, csr *x509.CertificateRequest) (*api.X509SVID, error)
	NewJWTSVID(ctx context.Context, entryID string, audience []string) (*api.JWTSVID, error)
}

// New creates a new SVID service
func New(config Config) Service {
	return &service{}
}

type service struct {
}

func (s *service) MintX509SVID(ctx context.Context, csr *x509.CertificateRequest, ttl time.Duration) (*api.X509SVID, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s *service) MintJWTSVID(ctx context.Context, id spiffeid.ID, audience []string, ttl time.Duration) (*api.JWTSVID, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s *service) NewX509SVID(ctx context.Context, entryID string, csr *x509.CertificateRequest) (*api.X509SVID, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s *service) NewJWTSVID(ctx context.Context, entryID string, audience []string) (*api.JWTSVID, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
