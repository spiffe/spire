package localauthority

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/ca/manager"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/private/server/journal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CAManager interface {
	// JWT
	GetCurrentJWTKeySlot() manager.Slot
	GetNextJWTKeySlot() manager.Slot
	PrepareJWTKey(ctx context.Context) error
	RotateJWTKey()

	// X509
	GetCurrentX509CASlot() manager.Slot
	GetNextX509CASlot() manager.Slot
	PrepareX509CA(ctx context.Context) error
	RotateX509CA()
}

// Config is the service configuration
type Config struct {
	TrustDomain spiffeid.TrustDomain
	DataStore   datastore.DataStore
	CAManager   CAManager
}

// New creates a new LocalAuthority service
func New(config Config) *Service {
	return &Service{
		td: config.TrustDomain,
		ds: config.DataStore,
		ca: config.CAManager,
	}
}

// Service implements the v1 LocalAuthority service
type Service struct {
	localauthorityv1.UnsafeLocalAuthorityServer

	td spiffeid.TrustDomain
	ds datastore.DataStore
	ca CAManager
}

func (s *Service) GetJWTAuthorityState(context.Context, *localauthorityv1.GetJWTAuthorityStateRequest) (*localauthorityv1.GetJWTAuthorityStateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) PrepareJWTAuthority(context.Context, *localauthorityv1.PrepareJWTAuthorityRequest) (*localauthorityv1.PrepareJWTAuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) ActivateJWTAuthority(context.Context, *localauthorityv1.ActivateJWTAuthorityRequest) (*localauthorityv1.ActivateJWTAuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) TaintJWTAuthority(context.Context, *localauthorityv1.TaintJWTAuthorityRequest) (*localauthorityv1.TaintJWTAuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) RevokeJWTAuthority(context.Context, *localauthorityv1.RevokeJWTAuthorityRequest) (*localauthorityv1.RevokeJWTAuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) GetX509AuthorityState(ctx context.Context, _ *localauthorityv1.GetX509AuthorityStateRequest) (*localauthorityv1.GetX509AuthorityStateResponse, error) {
	log := rpccontext.Logger(ctx)

	current := s.ca.GetCurrentX509CASlot()
	switch {
	case current.Status() != journal.Status_ACTIVE:
		return nil, api.MakeErr(log, codes.Unavailable, "server is initializing", nil)
	case current.AuthorityID() == "":
		return nil, api.MakeErr(log, codes.Internal, "current slot does not contains authority ID", nil)
	}

	resp := &localauthorityv1.GetX509AuthorityStateResponse{
		Active: stateFromSlot(current),
	}

	next := s.ca.GetNextX509CASlot()
	// when next has a key indicates that it was initialized
	if next.AuthorityID() != "" {
		switch next.Status() {
		case journal.Status_OLD:
			resp.Old = stateFromSlot(next)
		case journal.Status_PREPARED:
			resp.Prepared = stateFromSlot(next)
		case journal.Status_UNKNOWN:
			log.WithField(telemetry.LocalAuthorityID, next.AuthorityID()).Error("Slot has an unknown status")
		}
	}

	rpccontext.AuditRPC(ctx)

	return resp, nil
}

func (s *Service) PrepareX509Authority(ctx context.Context, _ *localauthorityv1.PrepareX509AuthorityRequest) (*localauthorityv1.PrepareX509AuthorityResponse, error) {
	log := rpccontext.Logger(ctx)

	current := s.ca.GetCurrentX509CASlot()
	if current.Status() != journal.Status_ACTIVE {
		return nil, api.MakeErr(log, codes.Unavailable, "server is initializing", nil)
	}

	if err := s.ca.PrepareX509CA(ctx); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to prepare X.509 authority", err)
	}

	slot := s.ca.GetNextX509CASlot()

	rpccontext.AuditRPC(ctx)

	return &localauthorityv1.PrepareX509AuthorityResponse{
		PreparedAuthority: &localauthorityv1.AuthorityState{
			AuthorityId: slot.AuthorityID(),
			ExpiresAt:   slot.NotAfter().Unix(),
		},
	}, nil
}

func (s *Service) ActivateX509Authority(ctx context.Context, req *localauthorityv1.ActivateX509AuthorityRequest) (*localauthorityv1.ActivateX509AuthorityResponse, error) {
	rpccontext.AddRPCAuditFields(ctx, buildAuditLogFields(req.AuthorityId))
	log := rpccontext.Logger(ctx)
	if req.AuthorityId != "" {
		log = log.WithField(telemetry.LocalAuthorityID, req.AuthorityId)
	}

	nextSlot := s.ca.GetNextX509CASlot()

	switch {
	// Authority ID is required
	case req.AuthorityId == "":
		return nil, api.MakeErr(log, codes.InvalidArgument, "no authority ID provided", nil)

	/// Only next local authority can be Activated
	case req.AuthorityId != nextSlot.AuthorityID():
		return nil, api.MakeErr(log, codes.InvalidArgument, "unexpected authority ID", nil)

	// Only PREPARED local authorities can be Activated
	case nextSlot.Status() != journal.Status_PREPARED:
		return nil, api.MakeErr(log, codes.Internal, "only Prepared authorities can be activated", nil)
	}

	// Move next into current and reset next to clean CA
	s.ca.RotateX509CA()

	current := s.ca.GetCurrentX509CASlot()
	state := &localauthorityv1.AuthorityState{
		AuthorityId: current.AuthorityID(),
		ExpiresAt:   current.NotAfter().Unix(),
	}
	rpccontext.AuditRPC(ctx)

	return &localauthorityv1.ActivateX509AuthorityResponse{
		ActivatedAuthority: state,
	}, nil
}

func (s *Service) TaintX509Authority(ctx context.Context, req *localauthorityv1.TaintX509AuthorityRequest) (*localauthorityv1.TaintX509AuthorityResponse, error) {
	rpccontext.AddRPCAuditFields(ctx, buildAuditLogFields(req.AuthorityId))
	log := rpccontext.Logger(ctx)
	if req.AuthorityId != "" {
		log = log.WithField(telemetry.LocalAuthorityID, req.AuthorityId)
	}

	nextSlot := s.ca.GetNextX509CASlot()

	switch {
	// Authority ID is required
	case req.AuthorityId == "":
		return nil, api.MakeErr(log, codes.InvalidArgument, "no authority ID provided", nil)

	// It is not possible to taint Active authority
	case req.AuthorityId == s.ca.GetCurrentX509CASlot().AuthorityID():
		return nil, api.MakeErr(log, codes.InvalidArgument, "unable to taint current local authority", nil)

	// Only next local authority can be tainted
	case req.AuthorityId != nextSlot.AuthorityID():
		return nil, api.MakeErr(log, codes.InvalidArgument, "unexpected authority ID", nil)

	// Only OLD authorities can be tainted
	case nextSlot.Status() != journal.Status_OLD:
		return nil, api.MakeErr(log, codes.InvalidArgument, "only Old local authorities can be tainted", nil)
	}

	if err := s.ds.TaintX509CA(ctx, s.td.IDString(), nextSlot.PublicKey()); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to taint X.509 authority", err)
	}

	state := &localauthorityv1.AuthorityState{
		AuthorityId: nextSlot.AuthorityID(),
	}

	rpccontext.AuditRPC(ctx)
	log.Info("X.509 authority tainted successfully")

	return &localauthorityv1.TaintX509AuthorityResponse{
		TaintedAuthority: state,
	}, nil
}

func (s *Service) RevokeX509Authority(ctx context.Context, req *localauthorityv1.RevokeX509AuthorityRequest) (*localauthorityv1.RevokeX509AuthorityResponse, error) {
	rpccontext.AddRPCAuditFields(ctx, buildAuditLogFields(req.AuthorityId))
	log := rpccontext.Logger(ctx)

	authorityID, publicKey, err := s.getX509PublicKey(ctx, req.AuthorityId)
	if err != nil {
		if req.AuthorityId != "" {
			log = log.WithField(telemetry.LocalAuthorityID, req.AuthorityId)
		}
		return nil, api.MakeErr(log, codes.InvalidArgument, "invalid authority ID", err)
	}

	log = log.WithField(telemetry.LocalAuthorityID, authorityID)
	if err := s.ds.RevokeX509CA(ctx, s.td.IDString(), publicKey); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to revoke X.509 authority", err)
	}

	state := &localauthorityv1.AuthorityState{
		AuthorityId: authorityID,
	}

	rpccontext.AuditRPC(ctx)
	log.Info("X.509 authority revoked successfully")

	return &localauthorityv1.RevokeX509AuthorityResponse{
		RevokedAuthority: state,
	}, nil
}

// getX509PublicKey validates provided authority ID, and return OLD associated public key
func (s *Service) getX509PublicKey(ctx context.Context, authorityID string) (string, crypto.PublicKey, error) {
	if authorityID == "" {
		return "", nil, errors.New("no authority ID provided")
	}

	nextSlot := s.ca.GetNextX509CASlot()
	if authorityID == nextSlot.AuthorityID() {
		if nextSlot.Status() == journal.Status_PREPARED {
			return "", nil, errors.New("unable to use a prepared key")
		}

		return nextSlot.AuthorityID(), nextSlot.PublicKey(), nil
	}

	currentSlot := s.ca.GetCurrentX509CASlot()
	if currentSlot.AuthorityID() == authorityID {
		return "", nil, errors.New("unable to use current authority")
	}

	bundle, err := s.ds.FetchBundle(ctx, s.td.IDString())
	if err != nil {
		return "", nil, err
	}

	for _, ca := range bundle.RootCas {
		cert, err := x509.ParseCertificate(ca.DerBytes)
		if err != nil {
			return "", nil, err
		}

		subjectKeyID := x509util.SubjectKeyIDToString(cert.SubjectKeyId)
		if authorityID == subjectKeyID {
			return subjectKeyID, cert.PublicKey, nil
		}
	}

	return "", nil, errors.New("no ca found with provided authority ID")
}

func buildAuditLogFields(authorityID string) logrus.Fields {
	fields := logrus.Fields{}
	if authorityID != "" {
		fields[telemetry.LocalAuthorityID] = authorityID
	}
	return fields
}

func stateFromSlot(s manager.Slot) *localauthorityv1.AuthorityState {
	return &localauthorityv1.AuthorityState{
		AuthorityId: s.AuthorityID(),
		ExpiresAt:   s.NotAfter().Unix(),
	}
}
