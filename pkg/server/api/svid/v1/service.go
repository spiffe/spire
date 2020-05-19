package svid

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/util/regentryutil"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Config is the service configuration
type Config struct {
	ServerCA    ca.ServerCA
	DataStore   datastore.DataStore
	TrustDomain spiffeid.TrustDomain
}

// Service is the SVID service interface
type Service interface {
	MintX509SVID(ctx context.Context, csr *x509.CertificateRequest, ttl time.Duration) (*api.X509SVID, error)
	MintJWTSVID(ctx context.Context, id spiffeid.ID, audience []string, ttl time.Duration) (*api.JWTSVID, error)
	BatchNewX509SVID(ctx context.Context, req []*BatchNewX509SVIDRequest) ([]*BatchNewX509SVIDResponse, error)
	NewJWTSVID(ctx context.Context, entryID string, audience []string) (*api.JWTSVID, error)
}

// New creates a new SVID service
func New(config Config) Service {
	return &service{
		ca: config.ServerCA,
		ds: config.DataStore,
		td: config.TrustDomain,
	}
}

type service struct {
	ca ca.ServerCA
	ds datastore.DataStore
	td spiffeid.TrustDomain
}

func (s *service) MintX509SVID(ctx context.Context, csr *x509.CertificateRequest, ttl time.Duration) (*api.X509SVID, error) {
	log := rpccontext.Logger(ctx)

	spiffeID, err := s.validateCSR(csr, log)
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

func (s *service) BatchNewX509SVID(ctx context.Context, req []*BatchNewX509SVIDRequest) ([]*BatchNewX509SVIDResponse, error) {
	// TODO: must I add metrics here? or middleware take care about it?
	log := rpccontext.Logger(ctx)
	callerID, ok := rpccontext.CallerID(ctx)
	if !ok {
		log.Error("CallerID is required")
		return nil, status.Error(codes.Internal, "callerID is required")
	}

	regEntries, err := regentryutil.FetchRegistrationEntries(ctx, s.ds, callerID.String())
	if err != nil {
		log.WithError(err).Error("Failed to fetch registration entries")
		return nil, status.Error(codes.Internal, "failed to fetch registration entries")
	}

	regEntriesMap := make(map[string]*common.RegistrationEntry)
	for _, entry := range regEntries {
		regEntriesMap[entry.EntryId] = entry
	}

	var resp []*BatchNewX509SVIDResponse
	for _, eachReq := range req {
		newSvid, err := s.newX509SVID(ctx, eachReq, regEntriesMap)
		resp = append(resp, &BatchNewX509SVIDResponse{
			Svid: newSvid,
			Err:  err,
		})
	}
	return resp, nil
}

func (s *service) newX509SVID(ctx context.Context, req *BatchNewX509SVIDRequest, regEntries map[string]*common.RegistrationEntry) (*api.X509SVID, error) {
	log := rpccontext.Logger(ctx).WithField(telemetry.RegistrationID, req.EntryID)
	entry, ok := regEntries[req.EntryID]
	if !ok {
		log.Error("Invalid registration entry: not allowed")
		return nil, status.Errorf(codes.InvalidArgument, "invalid entry id: %q is not allowed", req.EntryID)
	}

	csr := req.Csr
	spiffeID, err := s.validateCSR(csr, log)
	if err != nil {
		return nil, err
	}

	log = log.WithField(telemetry.SPIFFEID, spiffeID.String())

	svid, err := s.ca.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  spiffeID.String(),
		PublicKey: csr.PublicKey,
		DNSList:   entry.DnsNames,
		TTL:       time.Duration(entry.Ttl),
		// TODO: want we to do it?
		Subject: csr.Subject,
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

type BatchNewX509SVIDRequest struct {
	EntryID string
	Csr     *x509.CertificateRequest
}

type BatchNewX509SVIDResponse struct {
	Svid *api.X509SVID
	Err  error
}

func (s *service) validateCSR(csr *x509.CertificateRequest, log logrus.FieldLogger) (spiffeID spiffeid.ID, err error) {
	if err = csr.CheckSignature(); err != nil {
		log.WithError(err).Error("Invalid CSR: signature verify failed")
		return spiffeID, status.Errorf(codes.InvalidArgument, "invalid CSR: signature verify failed")
	}

	switch {
	case len(csr.URIs) == 0:
		log.Error("Invalid CSR: URI SAN is required")
		return spiffeID, status.Error(codes.InvalidArgument, "invalid CSR: URI SAN is required")
	case len(csr.URIs) > 1:
		log.Error("Invalid CSR: only one URI SAN is expected")
		return spiffeID, status.Errorf(codes.InvalidArgument, "invalid CSR: only one URI SAN is expected")
	}

	spiffeID, err = spiffeid.FromURI(csr.URIs[0])
	if err != nil {
		log.WithError(err).Error("Invalid CSR: URI SAN is not a valid SPIFFE ID")
		return spiffeID, status.Errorf(codes.InvalidArgument, "invalid CSR: URI SAN is not a valid SPIFFE ID: %v", err)
	}

	if !spiffeID.MemberOf(s.td) {
		log.Error("Invalid CSR: SPIFFE ID is not a member of the server trust domain")
		return spiffeID, status.Error(codes.InvalidArgument, "invalid CSR: SPIFFE ID is not a member of the server trust domain")
	}

	return spiffeID, nil
}
