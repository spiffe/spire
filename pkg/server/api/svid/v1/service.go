package svid

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/spiffe/spire/proto/spire-next/types"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/ca"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthorizedEntryFetcher interface {
	FetchAuthorizedEntries(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error)
}

type AuthorizedEntryFetcherFunc func(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error)

func (fn AuthorizedEntryFetcherFunc) FetchAuthorizedEntries(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
	return fn(ctx, agentID)
}

// Config is the service configuration
type Config struct {
	ServerCA     ca.ServerCA
	EntryFetcher AuthorizedEntryFetcher
	TrustDomain  spiffeid.TrustDomain
}

// Service is the SVID service interface
type Service interface {
	MintX509SVID(ctx context.Context, csr *x509.CertificateRequest, ttl time.Duration) (*api.X509SVID, error)
	MintJWTSVID(ctx context.Context, id spiffeid.ID, audience []string, ttl time.Duration) (*api.JWTSVID, error)
	BatchNewX509SVID(ctx context.Context, reqs []*X509SVIDParams) ([]*X509SVIDResult, error)
	NewJWTSVID(ctx context.Context, entryID string, audience []string) (*api.JWTSVID, error)
}

// New creates a new SVID service
func New(config Config) Service {
	return &service{
		ca: config.ServerCA,
		ef: config.EntryFetcher,
		td: config.TrustDomain,
	}
}

type service struct {
	ca ca.ServerCA
	ef AuthorizedEntryFetcher
	td spiffeid.TrustDomain
}

func (s *service) MintX509SVID(ctx context.Context, csr *x509.CertificateRequest, ttl time.Duration) (*api.X509SVID, error) {
	log := rpccontext.Logger(ctx)

	spiffeID, err := validateCSR(csr, log, s.td)
	if err != nil {
		return nil, err
	}

	for _, dnsName := range csr.DNSNames {
		if err := x509util.ValidateDNS(dnsName); err != nil {
			log.WithError(err).Error("Invalid CSR: DNS name is not valid")
			return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: DNS name is not valid: %v", err)
		}
	}

	svid, err := s.ca.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  spiffeID.String(),
		PublicKey: csr.PublicKey,
		TTL:       ttl,
		DNSList:   csr.DNSNames,
		Subject:   csr.Subject,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign X509-SVID")
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

func (s *service) BatchNewX509SVID(ctx context.Context, reqs []*X509SVIDParams) ([]*X509SVIDResult, error) {
	// TODO: must I add metrics here? or middleware take care about it?
	log := rpccontext.Logger(ctx)
	callerID, ok := rpccontext.CallerID(ctx)
	if !ok {
		log.Error("CallerID is required")
		return nil, status.Error(codes.Internal, "callerID is required")
	}

	typeEntries, err := s.ef.FetchAuthorizedEntries(ctx, callerID)
	if err != nil {
		log.WithError(err).Error("Failed to fetch registration entries")
		return nil, status.Error(codes.Internal, "failed to fetch registration entries")
	}

	regEntriesMap := make(map[string]*types.Entry)
	for _, entry := range typeEntries {
		regEntriesMap[entry.Id] = entry
	}

	var resp []*X509SVIDResult
	for _, req := range reqs {
		newSvid, err := s.newX509SVID(ctx, req, regEntriesMap)
		resp = append(resp, &X509SVIDResult{
			Svid: newSvid,
			Err:  err,
		})
	}
	return resp, nil
}

func (s *service) newX509SVID(ctx context.Context, req *X509SVIDParams, typeEntries map[string]*types.Entry) (*api.X509SVID, error) {
	log := rpccontext.Logger(ctx).WithField(telemetry.RegistrationID, req.EntryID)
	entry, ok := typeEntries[req.EntryID]
	if !ok {
		log.Error("Invalid registration entry: not found")
		return nil, status.Errorf(codes.NotFound, "invalid entry id: %q not found", req.EntryID)
	}

	if err := req.Csr.CheckSignature(); err != nil {
		log.WithError(err).Error("Invalid CSR: signature verify failed")
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: signature verify failed")
	}

	spiffeID, err := api.SpiffeIDFromProto(entry.SpiffeId)
	if err != nil {
		// It may never happens, it is not possible to add invalid SPIFFE IDs on datastore
		log.WithError(err).Error("Invalid Spiffe ID")
		return nil, status.Error(codes.Internal, "invalid Spiffe ID")
	}
	log = log.WithField(telemetry.SPIFFEID, spiffeID.String())

	svid, err := s.ca.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  spiffeID.String(),
		PublicKey: req.Csr.PublicKey,
		DNSList:   entry.DnsNames,
		TTL:       time.Duration(entry.Ttl) * time.Second,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign X509-SVID")
		return nil, status.Errorf(codes.Internal, "failed to sign X509-SVID: %v", err)
	}

	return &api.X509SVID{
		ID:        spiffeID,
		CertChain: svid,
		ExpiresAt: svid[0].NotAfter.UTC(),
	}, nil
}

func (s *service) NewJWTSVID(ctx context.Context, entryID string, audience []string) (*api.JWTSVID, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

type X509SVIDParams struct {
	EntryID string
	Csr     *x509.CertificateRequest
}

// NewX509SVIDParams creates a new X509SVIDParams
func NewX509SVIDParams(entryID string, csr *x509.CertificateRequest) *X509SVIDParams {
	return &X509SVIDParams{
		EntryID: entryID,
		Csr:     csr,
	}
}

type X509SVIDResult struct {
	Svid *api.X509SVID
	Err  error
}

// NewX509SVIDResult creates a new NewX509SVIDResult
func NewX509SVIDResult(svid *api.X509SVID, err error) *X509SVIDResult {
	return &X509SVIDResult{
		Svid: svid,
		Err:  err,
	}
}

func validateCSR(csr *x509.CertificateRequest, log logrus.FieldLogger, td spiffeid.TrustDomain) (spiffeid.ID, error) {
	if err := csr.CheckSignature(); err != nil {
		log.WithError(err).Error("Invalid CSR: signature verify failed")
		return spiffeid.ID{}, status.Errorf(codes.InvalidArgument, "invalid CSR: signature verify failed")
	}

	switch {
	case len(csr.URIs) == 0:
		log.Error("Invalid CSR: URI SAN is required")
		return spiffeid.ID{}, status.Error(codes.InvalidArgument, "invalid CSR: URI SAN is required")
	case len(csr.URIs) > 1:
		log.Error("Invalid CSR: only one URI SAN is expected")
		return spiffeid.ID{}, status.Errorf(codes.InvalidArgument, "invalid CSR: only one URI SAN is expected")
	}

	spiffeID, err := spiffeid.FromURI(csr.URIs[0])
	if err != nil {
		log.WithError(err).Error("Invalid CSR: URI SAN is not a valid SPIFFE ID")
		return spiffeid.ID{}, status.Errorf(codes.InvalidArgument, "invalid CSR: URI SAN is not a valid SPIFFE ID: %v", err)
	}

	if !spiffeID.MemberOf(td) {
		log.Error("Invalid CSR: SPIFFE ID is not a member of the server trust domain")
		return spiffeid.ID{}, status.Error(codes.InvalidArgument, "invalid CSR: SPIFFE ID is not a member of the server trust domain")
	}

	return spiffeID, nil
}
