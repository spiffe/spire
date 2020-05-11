package svid

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/ca"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var isDNSLabel = regexp.MustCompile(`^[a-zA-Z0-9]([-]*[a-zA-Z0-9])+$`).MatchString

// Config is the service configuration
type Config struct {
	ServerCA    ca.ServerCA
	TrustDomain spiffeid.TrustDomain
}

// Service is the SVID service interface
type Service interface {
	MintX509SVID(ctx context.Context, csr *x509.CertificateRequest, ttl time.Duration) (*api.X509SVID, error)
	MintJWTSVID(ctx context.Context, id spiffeid.ID, audience []string, ttl time.Duration) (*api.JWTSVID, error)
	NewX509SVID(ctx context.Context, entryID string, csr *x509.CertificateRequest) (*api.X509SVID, error)
	NewJWTSVID(ctx context.Context, entryID string, audience []string) (*api.JWTSVID, error)
}

// New creates a new SVID service
func New(config *Config) Service {
	return &service{
		ServerCA:    config.ServerCA,
		TrustDomain: config.TrustDomain,
	}
}

type service struct {
	ServerCA    ca.ServerCA
	TrustDomain spiffeid.TrustDomain
}

func (s *service) MintX509SVID(ctx context.Context, csr *x509.CertificateRequest, ttl time.Duration) (*api.X509SVID, error) {
	log := rpccontext.Logger(ctx)

	if err := csr.CheckSignature(); err != nil {
		log.WithError(err).Error("Invalid CSR: signature verify failed")
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: signature verify failed")
	}

	if len(csr.URIs) != 1 {
		log.Error("Invalid CSR: a valid URI is required")
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: a valid URI is required")
	}

	spiffeID, err := spiffeid.FromURI(csr.URIs[0])
	if err != nil {
		log.WithError(err).Error("Invalid SPIFFE ID")
		return nil, status.Errorf(codes.InvalidArgument, "invalid SPIFFE ID: %v", err)
	}

	if !spiffeID.MemberOf(s.TrustDomain) {
		log.Error("Invalid SPIFFE ID: not member of the servers trust domain")
		return nil, status.Error(codes.InvalidArgument, "invalid SPIFFE ID: not member of the servers trust domain")
	}

	for _, dnsName := range csr.DNSNames {
		if err := validateDNS(dnsName); err != nil {
			log.WithError(err).Error("Invalid DNS name")
			return nil, status.Errorf(codes.InvalidArgument, "invalid DNS name: %v", err)
		}
	}

	svid, err := s.ServerCA.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  spiffeID.String(),
		PublicKey: csr.PublicKey,
		// SignX509SVID is taking care of of ttl comparation against bundle
		TTL:     ttl,
		DNSList: csr.DNSNames,
		Subject: csr.Subject,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign X.509 SVID")
		return nil, status.Errorf(codes.Internal, "failed to sign X509-SVID: %v", err)
	}

	return &api.X509SVID{
		ID:        spiffeID,
		CertChain: svid,
		ExpiresAt: svid[0].NotAfter.UTC(),
	}, nil
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

func validateDNS(dns string) error {
	// follow https://tools.ietf.org/html/rfc5280#section-4.2.1.6
	// do not allow empty or the technically valid DNS " "
	dns = strings.TrimSpace(dns)
	if len(dns) == 0 {
		return errors.New("empty or only whitespace")
	}

	// handle up to 255 characters
	if len(dns) > 255 {
		return errors.New("length exceeded")
	}

	// a DNS is split into labels by "."
	splitDNS := strings.Split(dns, ".")
	for _, label := range splitDNS {
		if err := validateDNSLabel(label); err != nil {
			return err
		}
	}

	return nil
}

func validateDNSLabel(label string) error {
	// follow https://tools.ietf.org/html/rfc5280#section-4.2.1.6 guidance
	// <label> ::= <let-dig> [ [ <ldh-str> ] <let-dig> ]
	// <ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>
	switch {
	case len(label) == 0:
		return errors.New("label is empty")
	case len(label) > 63:
		return fmt.Errorf("label length exceeded: %v", label)
	case !isDNSLabel(label):
		return fmt.Errorf("label does not match regex: %v", label)
	}

	return nil
}
