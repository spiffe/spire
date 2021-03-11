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
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire/proto/spire/types"
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
	EntryFetcher api.AuthorizedEntryFetcher
	ServerCA     ca.ServerCA
	TrustDomain  spiffeid.TrustDomain
	DataStore    datastore.DataStore
}

// New creates a new SVID service
func New(config Config) *Service {
	return &Service{
		ca: config.ServerCA,
		ef: config.EntryFetcher,
		td: config.TrustDomain,
		ds: config.DataStore,
	}
}

// Service implements the v1 SVID service
type Service struct {
	svid.UnsafeSVIDServer

	ca ca.ServerCA
	ef api.AuthorizedEntryFetcher
	td spiffeid.TrustDomain
	ds datastore.DataStore
}

func (s *Service) MintX509SVID(ctx context.Context, req *svid.MintX509SVIDRequest) (*svid.MintX509SVIDResponse, error) {
	log := rpccontext.Logger(ctx)

	if len(req.Csr) == 0 {
		return nil, api.MakeErr(log, codes.InvalidArgument, "missing CSR", nil)
	}

	csr, err := x509.ParseCertificateRequest(req.Csr)
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "malformed CSR", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "failed to verify CSR signature", err)
	}

	switch {
	case len(csr.URIs) == 0:
		return nil, api.MakeErr(log, codes.InvalidArgument, "CSR URI SAN is required", nil)
	case len(csr.URIs) > 1:
		return nil, api.MakeErr(log, codes.InvalidArgument, "only one URI SAN is expected", nil)
	}

	id, err := spiffeid.FromURI(csr.URIs[0])
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "CSR URI SAN is not a valid SPIFFE ID", err)
	}

	if err := api.VerifyTrustDomainWorkloadID(s.td, id); err != nil {
		log.Errorf("Invalid CSR: %v", err)
		return nil, api.MakeErr(log, codes.InvalidArgument, "CSR URI SAN is invalid", err)
	}

	if err := idutil.CheckIDURLNormalization(csr.URIs[0]); err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "CSR URI SAN is malformed", err)
	}

	for _, dnsName := range csr.DNSNames {
		if err := x509util.ValidateDNS(dnsName); err != nil {
			return nil, api.MakeErr(log, codes.InvalidArgument, "CSR DNS name is not valid", err)
		}
	}

	x509SVID, err := s.ca.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  id,
		PublicKey: csr.PublicKey,
		TTL:       time.Duration(req.Ttl) * time.Second,
		DNSList:   csr.DNSNames,
		Subject:   csr.Subject,
	})
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to sign X509-SVID", err)
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
		return nil, api.MakeErr(log, codes.InvalidArgument, "missing parameters", nil)
	}

	if err := rpccontext.RateLimit(ctx, len(req.Params)); err != nil {
		return nil, api.MakeErr(log, status.Code(err), "rejecting request due to certificate signing rate limiting", err)
	}

	// Fetch authorized entries
	entriesMap, err := s.fetchEntries(ctx, log)
	if err != nil {
		return nil, err
	}

	var results []*svid.BatchNewX509SVIDResponse_Result
	for _, svidParam := range req.Params {
		//  Create new SVID
		results = append(results, s.newX509SVID(ctx, svidParam, entriesMap))
	}

	return &svid.BatchNewX509SVIDResponse{Results: results}, nil
}

// fetchEntries fetches authorized entries using caller ID from context
func (s *Service) fetchEntries(ctx context.Context, log logrus.FieldLogger) (map[string]*types.Entry, error) {
	callerID, ok := rpccontext.CallerID(ctx)
	if !ok {
		return nil, api.MakeErr(log, codes.Internal, "caller ID missing from request context", nil)
	}

	entries, err := s.ef.FetchAuthorizedEntries(ctx, callerID)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to fetch registration entries", err)
	}

	entriesMap := make(map[string]*types.Entry, len(entries))
	for _, entry := range entries {
		entriesMap[entry.Id] = entry
	}

	return entriesMap, nil
}

// newX509SVID creates an X509-SVID using data from registration entry and key from CSR
func (s *Service) newX509SVID(ctx context.Context, param *svid.NewX509SVIDParams, entries map[string]*types.Entry) *svid.BatchNewX509SVIDResponse_Result {
	log := rpccontext.Logger(ctx)

	switch {
	case param.EntryId == "":
		return &svid.BatchNewX509SVIDResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "missing entry ID", nil),
		}
	case len(param.Csr) == 0:
		return &svid.BatchNewX509SVIDResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "missing CSR", nil),
		}
	}

	log = log.WithField(telemetry.RegistrationID, param.EntryId)

	entry, ok := entries[param.EntryId]
	if !ok {
		return &svid.BatchNewX509SVIDResponse_Result{
			Status: api.MakeStatus(log, codes.NotFound, "entry not found or not authorized", nil),
		}
	}

	csr, err := x509.ParseCertificateRequest(param.Csr)
	if err != nil {
		return &svid.BatchNewX509SVIDResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "malformed CSR", err),
		}
	}

	if err := csr.CheckSignature(); err != nil {
		return &svid.BatchNewX509SVIDResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "invalid CSR signature", err),
		}
	}

	spiffeID, err := api.TrustDomainMemberIDFromProto(s.td, entry.SpiffeId)
	if err != nil {
		// This shouldn't be the case unless there is invalid data in the datastore
		return &svid.BatchNewX509SVIDResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "entry has malformed SPIFFE ID", err),
		}
	}
	log = log.WithField(telemetry.SPIFFEID, spiffeID.String())

	x509Svid, err := s.ca.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  spiffeID,
		PublicKey: csr.PublicKey,
		DNSList:   entry.DnsNames,
		TTL:       time.Duration(entry.Ttl) * time.Second,
	})
	if err != nil {
		return &svid.BatchNewX509SVIDResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "failed to sign X509-SVID", err),
		}
	}

	return &svid.BatchNewX509SVIDResponse_Result{
		Svid: &types.X509SVID{
			Id:        entry.SpiffeId,
			CertChain: x509util.RawCertsFromCertificates(x509Svid),
			ExpiresAt: x509Svid[0].NotAfter.UTC().Unix(),
		},
		Status: api.OK(),
	}
}

func (s *Service) mintJWTSVID(ctx context.Context, protoID *types.SPIFFEID, audience []string, ttl int32) (*types.JWTSVID, error) {
	log := rpccontext.Logger(ctx)

	id, err := api.TrustDomainWorkloadIDFromProto(s.td, protoID)
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "invalid SPIFFE ID", err)
	}

	if err := idutil.CheckIDProtoNormalization(protoID); err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "spiffe ID is malformed", err)
	}

	log = log.WithField(telemetry.SPIFFEID, id.String())

	if len(audience) == 0 {
		return nil, api.MakeErr(log, codes.InvalidArgument, "at least one audience is required", nil)
	}

	token, err := s.ca.SignJWTSVID(ctx, ca.JWTSVIDParams{
		SpiffeID: id,
		TTL:      time.Duration(ttl) * time.Second,
		Audience: audience,
	})
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to sign JWT-SVID", err)
	}

	issuedAt, expiresAt, err := jwtsvid.GetTokenExpiry(token)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to get JWT-SVID expiry", err)
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
		return nil, api.MakeErr(log, status.Code(err), "rejecting request due to JWT signing request rate limiting", err)
	}

	// Fetch authorized entries
	entriesMap, err := s.fetchEntries(ctx, log)
	if err != nil {
		return nil, err
	}

	entry, ok := entriesMap[req.EntryId]
	if !ok {
		return nil, api.MakeErr(log, codes.NotFound, "entry not found or not authorized", nil)
	}

	jwtsvid, err := s.mintJWTSVID(ctx, entry.SpiffeId, req.Audience, entry.Ttl)
	if err != nil {
		return nil, err
	}

	return &svid.NewJWTSVIDResponse{
		Svid: jwtsvid,
	}, nil
}

func (s *Service) NewDownstreamX509CA(ctx context.Context, req *svid.NewDownstreamX509CARequest) (*svid.NewDownstreamX509CAResponse, error) {
	log := rpccontext.Logger(ctx)

	if err := rpccontext.RateLimit(ctx, 1); err != nil {
		return nil, api.MakeErr(log, status.Code(err), "rejecting request due to downstream CA signing rate limit", err)
	}

	downstreamEntries, isDownstream := rpccontext.CallerDownstreamEntries(ctx)
	if !isDownstream {
		return nil, api.MakeErr(log, codes.Internal, "caller is not a downstream workload", nil)
	}

	entry := downstreamEntries[0]

	csr, err := parseAndCheckCSR(ctx, req.Csr)
	if err != nil {
		return nil, err
	}

	x509CASvid, err := s.ca.SignX509CASVID(ctx, ca.X509CASVIDParams{
		SpiffeID:  s.td.ID(),
		PublicKey: csr.PublicKey,
		TTL:       time.Duration(entry.Ttl) * time.Second,
	})
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to sign downstream X.509 CA", err)
	}

	dsResp, err := s.ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: s.td.IDString(),
	})
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to fetch bundle", err)
	}

	if dsResp.Bundle == nil {
		return nil, api.MakeErr(log, codes.NotFound, "bundle not found", nil)
	}

	rawRootCerts := make([][]byte, 0, len(dsResp.Bundle.RootCas))
	for _, cert := range dsResp.Bundle.RootCas {
		rawRootCerts = append(rawRootCerts, cert.DerBytes)
	}

	return &svid.NewDownstreamX509CAResponse{
		CaCertChain:     x509util.RawCertsFromCertificates(x509CASvid),
		X509Authorities: rawRootCerts,
	}, nil
}

func parseAndCheckCSR(ctx context.Context, csrBytes []byte) (*x509.CertificateRequest, error) {
	log := rpccontext.Logger(ctx)

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "malformed CSR", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "invalid CSR signature", err)
	}

	return csr, nil
}
