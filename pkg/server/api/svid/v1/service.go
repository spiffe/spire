package svid

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/telemetry"
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

type AuthorizedEntryFetcher interface {
	FetchAuthorizedEntries(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error)
}

type AuthorizedEntryFetcherFunc func(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error)

func (fn AuthorizedEntryFetcherFunc) FetchAuthorizedEntries(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
	return fn(ctx, agentID)
}

// Config is the service configuration
type Config struct {
	EntryFetcher AuthorizedEntryFetcher
	ServerCA     ca.ServerCA
	TrustDomain  spiffeid.TrustDomain
}

// New creates a new SVID service
func New(config Config) *Service {
	return &Service{
		ca: config.ServerCA,
		ef: config.EntryFetcher,
		td: config.TrustDomain,
	}
}

// Service implements the v1 SVID service
type Service struct {
	ca ca.ServerCA
	ef AuthorizedEntryFetcher
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
	jwtsvid, err := s.mintJWTSVID(ctx, req.Id, req.Audience, req.Ttl)
	if err != nil {
		return nil, err
	}

	return &svid.MintJWTSVIDResponse{
		Svid: jwtsvid,
	}, nil
}

func (s *Service) BatchNewX509SVID(ctx context.Context, req *svid.BatchNewX509SVIDRequest) (*svid.BatchNewX509SVIDResponse, error) {
	log := rpccontext.Logger(ctx)

	if len(req.Params) == 0 {
		log.Error("Request missing parameters")
		return nil, status.Error(codes.InvalidArgument, "request missing parameters")
	}

	if err := rpccontext.RateLimit(ctx, len(req.Params)); err != nil {
		log.WithError(err).Error("Rejecting request due to certificate signing rate limiting")
		return nil, err
	}

	// Fetch authorized entries
	entriesMap, err := s.fetchEntries(ctx, log)
	if err != nil {
		return nil, err
	}

	resp := &svid.BatchNewX509SVIDResponse{}
	for _, svidParam := range req.Params {
		//  Create new SVID
		bundle, err := s.newX509SVID(ctx, svidParam, entriesMap)
		resp.Results = append(resp.Results, &svid.BatchNewX509SVIDResponse_Result{
			Bundle: bundle,
			Status: api.StatusFromError(err),
		})
	}

	return resp, nil
}

// fetchEntries fetches authorized entries using caller ID from context
func (s *Service) fetchEntries(ctx context.Context, log logrus.FieldLogger) (map[string]*types.Entry, error) {
	callerID, ok := rpccontext.CallerID(ctx)
	if !ok {
		log.Error("Caller ID missing from request context")
		return nil, status.Error(codes.Internal, "caller ID missing from request context")
	}

	entries, err := s.ef.FetchAuthorizedEntries(ctx, callerID)
	if err != nil {
		log.WithError(err).Error("Failed to fetch registration entries")
		return nil, status.Error(codes.Internal, "failed to fetch registration entries")
	}

	entriesMap := make(map[string]*types.Entry)
	for _, entry := range entries {
		entriesMap[entry.Id] = entry
	}

	return entriesMap, nil
}

// newX509SVID creates an X509-SVID using data from registration entry and key from CSR
func (s *Service) newX509SVID(ctx context.Context, param *svid.NewX509SVIDParams, typeEntries map[string]*types.Entry) (*types.X509SVID, error) {
	log := rpccontext.Logger(ctx)

	switch {
	case param.EntryId == "":
		log.Error("Invalid request: missing entry ID")
		return nil, status.Error(codes.InvalidArgument, "missing entry ID")
	case len(param.Csr) == 0:
		log.Error("Invalid request: missing CSR")
		return nil, status.Error(codes.InvalidArgument, "missing CSR")
	}

	log = log.WithField(telemetry.RegistrationID, param.EntryId)

	entry, ok := typeEntries[param.EntryId]
	if !ok {
		log.Error("Invalid request: entry not found or not authorized")
		return nil, status.Error(codes.NotFound, "entry not found or not authorized")
	}

	csr, err := x509.ParseCertificateRequest(param.Csr)
	if err != nil {
		log.WithError(err).Error("Invalid request: malformed CSR")
		return nil, status.Errorf(codes.InvalidArgument, "malformed CSR: %v", err)
	}

	if err := csr.CheckSignature(); err != nil {
		log.WithError(err).Error("Invalid request: invalid CSR signature")
		return nil, status.Error(codes.InvalidArgument, "invalid CSR signature")
	}

	spiffeID, err := api.IDFromProto(entry.SpiffeId)
	if err != nil {
		// This shouldn't be the case unless there is invalid data in the datastore
		log.WithError(err).Error("Entry has malformed SPIFFE ID")
		return nil, status.Error(codes.Internal, "entry has malformed SPIFFE ID")
	}
	log = log.WithField(telemetry.SPIFFEID, spiffeID.String())

	x509Svid, err := s.ca.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  spiffeID.String(),
		PublicKey: csr.PublicKey,
		DNSList:   entry.DnsNames,
		TTL:       time.Duration(entry.Ttl) * time.Second,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign X509-SVID")
		return nil, status.Errorf(codes.Internal, "failed to sign X509-SVID: %v", err)
	}

	return &types.X509SVID{
		Id:        entry.SpiffeId,
		CertChain: x509util.RawCertsFromCertificates(x509Svid),
		ExpiresAt: x509Svid[0].NotAfter.UTC().Unix(),
	}, nil
}

func (s *Service) mintJWTSVID(ctx context.Context, protoID *types.SPIFFEID, audience []string, ttl int32) (*types.JWTSVID, error) {
	log := rpccontext.Logger(ctx)

	id, err := api.IDFromProto(protoID)
	if err != nil {
		log.WithError(err).Error("Failed to parse SPIFFE ID")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := idutil.ValidateTrustDomainWorkload(id, s.td); err != nil {
		log.Errorf("Invalid SPIFFE ID: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid SPIFFE ID: %v", err)
	}

	log = log.WithField(telemetry.SPIFFEID, id.String())

	if len(audience) == 0 {
		log.Error("At least one audience is required")
		return nil, status.Error(codes.InvalidArgument, "at least one audience is required")
	}

	token, err := s.ca.SignJWTSVID(ctx, ca.JWTSVIDParams{
		SpiffeID: id.String(),
		TTL:      time.Duration(ttl) * time.Second,
		Audience: audience,
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

	return &types.JWTSVID{
		Token:     token,
		Id:        api.ProtoFromID(id),
		ExpiresAt: expiresAt.Unix(),
		IssuedAt:  issuedAt.Unix(),
	}, nil
}

func (s *Service) NewJWTSVID(ctx context.Context, req *svid.NewJWTSVIDRequest) (resp *svid.NewJWTSVIDResponse, err error) {
	log := rpccontext.Logger(ctx)

	if err := rpccontext.RateLimit(ctx, 1); err != nil {
		log.WithError(err).Error("Rejecting request due to JWT signing request rate limiting")
		return nil, err
	}

	// Fetch authorized entries
	entriesMap, err := s.fetchEntries(ctx, log)
	if err != nil {
		return nil, err
	}

	entry, ok := entriesMap[req.EntryId]
	if !ok {
		log.Error("Invalid request: entry not found")
		return nil, status.Error(codes.NotFound, "entry not found or not authorized")
	}

	jwtsvid, err := s.mintJWTSVID(ctx, entry.SpiffeId, req.Audience, entry.Ttl)
	if err != nil {
		return nil, err
	}

	return &svid.NewJWTSVIDResponse{
		Svid: jwtsvid,
	}, nil
}

func (s *Service) NewDownstreamX509CA(context.Context, *svid.NewDownstreamX509CARequest) (*svid.NewDownstreamX509CAResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
