package localauthority

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/ca/manager"
	"github.com/spiffe/spire/pkg/server/datastore"
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

func (s *Service) GetJWTAuthorityState(ctx context.Context, _ *localauthorityv1.GetJWTAuthorityStateRequest) (*localauthorityv1.GetJWTAuthorityStateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) PrepareJWTAuthority(ctx context.Context, req *localauthorityv1.PrepareJWTAuthorityRequest) (*localauthorityv1.PrepareJWTAuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) ActivateJWTAuthority(context.Context, *localauthorityv1.ActivateJWTAuthorityRequest) (*localauthorityv1.ActivateJWTAuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) TaintJWTAuthority(ctx context.Context, req *localauthorityv1.TaintJWTAuthorityRequest) (*localauthorityv1.TaintJWTAuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) RevokeJWTAuthority(ctx context.Context, req *localauthorityv1.RevokeJWTAuthorityRequest) (*localauthorityv1.RevokeJWTAuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) GetX509AuthorityState(ctx context.Context, _ *localauthorityv1.GetX509AuthorityStateRequest) (*localauthorityv1.GetX509AuthorityStateResponse, error) {
	log := rpccontext.Logger(ctx)

	var states []*localauthorityv1.AuthorityState
	current := s.ca.GetCurrentX509CASlot()
	if !current.IsEmpty() {
		if current.AuthorityID() == "" {
			return nil, api.MakeErr(log, codes.Internal, "current slot does not contains authority ID", nil)
		}

		states = append(states, &localauthorityv1.AuthorityState{
			AuthorityId: current.AuthorityID(),
			Status:      localauthorityv1.AuthorityState_ACTIVE,
		})
	}

	next := s.ca.GetNextX509CASlot()
	// when next has a key indicates that it was initialized
	if next.AuthorityID() != "" {
		status := localauthorityv1.AuthorityState_PREPARED
		// CA is removed from slot on rotation
		if next.IsEmpty() {
			status = localauthorityv1.AuthorityState_OLD
		}

		states = append(states, &localauthorityv1.AuthorityState{
			AuthorityId: next.AuthorityID(),
			Status:      status,
		})
	}

	rpccontext.AuditRPC(ctx)

	return &localauthorityv1.GetX509AuthorityStateResponse{
		States: states,
	}, nil
}

func (s *Service) PrepareX509Authority(ctx context.Context, req *localauthorityv1.PrepareX509AuthorityRequest) (*localauthorityv1.PrepareX509AuthorityResponse, error) {
	log := rpccontext.Logger(ctx)

	if err := s.ca.PrepareX509CA(ctx); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to prepare X.509 authority", err)
	}

	slot := s.ca.GetNextX509CASlot()
	// Prepare is going to use current slot when it is empty
	if !slot.IsEmpty() {
		slot = s.ca.GetCurrentX509CASlot()
	}

	rpccontext.AuditRPC(ctx)

	return &localauthorityv1.PrepareX509AuthorityResponse{
		PreparedAuthority: &localauthorityv1.AuthorityState{
			AuthorityId: slot.AuthorityID(),
			Status:      localauthorityv1.AuthorityState_PREPARED,
		},
	}, nil
}

func (s *Service) ActivateX509Authority(ctx context.Context, req *localauthorityv1.ActivateX509AuthorityRequest) (*localauthorityv1.ActivateX509AuthorityResponse, error) {
	rpccontext.AddRPCAuditFields(ctx, buildAuditLogFields(req.AuthorityId))
	log := rpccontext.Logger(ctx)

	// TODO: implement a way to activate an OLD authority
	if req.AuthorityId != "" {
		log = log.WithField(telemetry.LocalAuthorityID, req.AuthorityId)
		return nil, api.MakeErr(log, codes.InvalidArgument, "activating an old authority is not supported yet", nil)
	}

	if s.ca.GetNextX509CASlot().IsEmpty() {
		return nil, api.MakeErr(log, codes.Internal, "no prepared authority found", nil)
	}

	// Move next into current and reset next to clean CA
	s.ca.RotateX509CA()

	current := s.ca.GetCurrentX509CASlot()
	state := &localauthorityv1.AuthorityState{
		AuthorityId: current.AuthorityID(),
		Status:      localauthorityv1.AuthorityState_ACTIVE,
	}
	rpccontext.AuditRPC(ctx)

	return &localauthorityv1.ActivateX509AuthorityResponse{
		ActivatedAuthority: state,
	}, nil
}

func (s *Service) TaintX509Authority(ctx context.Context, req *localauthorityv1.TaintX509AuthorityRequest) (*localauthorityv1.TaintX509AuthorityResponse, error) {
	rpccontext.AddRPCAuditFields(ctx, buildAuditLogFields(req.AuthorityId))
	log := rpccontext.Logger(ctx)

	authorityID, err := s.getX509AuthorityID(req.AuthorityId)
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "invalid authority ID", err)
	}

	log.WithField(telemetry.LocalAuthorityID, authorityID)
	if err := s.ds.TaintX509CA(ctx, s.td.IDString(), authorityID); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to taint X.509 authority", err)
	}

	status := &localauthorityv1.AuthorityState{
		AuthorityId: authorityID,
		Status:      localauthorityv1.AuthorityState_OLD,
	}

	rpccontext.AuditRPC(ctx)
	log.Info("Key tainted successfully")

	return &localauthorityv1.TaintX509AuthorityResponse{
		TaintedAuthority: status,
	}, nil
}

func (s *Service) RevokeX509Authority(ctx context.Context, req *localauthorityv1.RevokeX509AuthorityRequest) (*localauthorityv1.RevokeX509AuthorityResponse, error) {
	rpccontext.AddRPCAuditFields(ctx, buildAuditLogFields(req.AuthorityId))
	log := rpccontext.Logger(ctx)

	authorityToRevoke, err := s.getX509AuthorityID(req.AuthorityId)
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "invalid authority ID", err)
	}

	log.WithField(telemetry.LocalAuthorityID, authorityToRevoke)
	if err := s.ds.RevokeX509CA(ctx, s.td.IDString(), authorityToRevoke); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to revoke X.509 authority", err)
	}

	state := &localauthorityv1.AuthorityState{
		AuthorityId: authorityToRevoke,
		Status:      localauthorityv1.AuthorityState_OLD,
	}

	rpccontext.AuditRPC(ctx)
	log.Info("Key revoked successfully")

	return &localauthorityv1.RevokeX509AuthorityResponse{
		RevokedAuthority: state,
	}, nil
}

// getX509AuthorityPublicKey gets authority key based on rawKey or next X.509 authority if it is in OLD status
func (s *Service) getX509AuthorityID(authorityID string) (string, error) {
	if authorityID == "" {
		// No key provided, taint OLD key
		nextSlot := s.ca.GetNextX509CASlot()
		if !nextSlot.IsEmpty() {
			return "", errors.New("unable to use a prepared key")
		}

		return nextSlot.AuthorityID(), nil
	}

	currentSlot := s.ca.GetCurrentX509CASlot()
	if currentSlot.AuthorityID() == authorityID {
		return "", errors.New("unable to use current authority")
	}

	return authorityID, nil
}

func buildAuditLogFields(authorityID string) logrus.Fields {
	fields := logrus.Fields{}
	if authorityID != "" {
		fields[telemetry.LocalAuthorityID] = authorityID
	}
	return fields
}
