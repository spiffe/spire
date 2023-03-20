package localauthority

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
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
		state, err := slotToProto(current, localauthorityv1.AuthorityState_ACTIVE)
		if err != nil {
			return nil, api.MakeErr(log, codes.Internal, "failed to get current slot", err)
		}
		states = append(states, state)
	}

	next := s.ca.GetNextX509CASlot()
	// when next has a key indicates that it was initialized
	if next.GetPublicKey() != nil {
		status := localauthorityv1.AuthorityState_PREPARED
		// CA is removed from slot on rotation
		if next.IsEmpty() {
			status = localauthorityv1.AuthorityState_OLD
		}

		state, err := slotToProto(next, status)
		if err != nil {
			return nil, api.MakeErr(log, codes.Internal, "failed to get next slot", err)
		}
		states = append(states, state)
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
	if slot.IsEmpty() {
		slot = s.ca.GetCurrentX509CASlot()
	}

	authorityState, err := slotToProto(slot, localauthorityv1.AuthorityState_PREPARED)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to create response", err)
	}

	rpccontext.AuditRPC(ctx)

	return &localauthorityv1.PrepareX509AuthorityResponse{
		PreparedAuthority: authorityState,
	}, nil
}

func (s *Service) ActivateX509Authority(ctx context.Context, req *localauthorityv1.ActivateX509AuthorityRequest) (*localauthorityv1.ActivateX509AuthorityResponse, error) {
	log := rpccontext.Logger(ctx)

	if s.ca.GetNextX509CASlot().IsEmpty() {
		return nil, api.MakeErr(log, codes.Internal, "no prepared authority found", nil)
	}

	// Move next into current and reset next to clean CA
	s.ca.RotateX509CA()

	current := s.ca.GetCurrentX509CASlot()

	state, err := slotToProto(current, localauthorityv1.AuthorityState_ACTIVE)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to parse current slot", err)
	}

	rpccontext.AuditRPC(ctx)

	return &localauthorityv1.ActivateX509AuthorityResponse{
		ActivatedAuthority: state,
	}, nil
}

func (s *Service) TaintX509Authority(ctx context.Context, req *localauthorityv1.TaintX509AuthorityRequest) (*localauthorityv1.TaintX509AuthorityResponse, error) {
	parseRequest := func() logrus.Fields {
		fields := logrus.Fields{}
		if len(req.PublicKey) > 0 {
			fields[telemetry.X509AuthorityPublicKeySHA256] = api.HashByte(req.PublicKey)
		}
		return fields
	}
	rpccontext.AddRPCAuditFields(ctx, parseRequest())
	log := rpccontext.Logger(ctx)

	keyToTaint, err := s.getX509AuthorityPublicKey(req.PublicKey)
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "invalid public key", err)
	}

	if err := s.ds.TaintX509CA(ctx, s.td.IDString(), keyToTaint); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to taint X.509 authority", err)
	}

	status, err := publicKeyToProto(keyToTaint, localauthorityv1.AuthorityState_OLD)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to create response", err)
	}

	rpccontext.AuditRPC(ctx)

	return &localauthorityv1.TaintX509AuthorityResponse{
		TaintedAuthority: status,
	}, nil
}

func (s *Service) RevokeX509Authority(ctx context.Context, req *localauthorityv1.RevokeX509AuthorityRequest) (*localauthorityv1.RevokeX509AuthorityResponse, error) {
	parseRequest := func() logrus.Fields {
		fields := logrus.Fields{}
		if len(req.PublicKey) > 0 {
			fields[telemetry.X509AuthorityPublicKeySHA256] = api.HashByte(req.PublicKey)
		}
		return fields
	}
	rpccontext.AddRPCAuditFields(ctx, parseRequest())
	log := rpccontext.Logger(ctx)

	keyToRevoke, err := s.getX509AuthorityPublicKey(req.PublicKey)
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "invalid public key", err)
	}

	if err := s.ds.RevokeX509CA(ctx, s.td.IDString(), keyToRevoke); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to revoke X.509 authority", err)
	}

	state, err := publicKeyToProto(keyToRevoke, localauthorityv1.AuthorityState_OLD)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to create response", err)
	}

	rpccontext.AuditRPC(ctx)

	return &localauthorityv1.RevokeX509AuthorityResponse{
		RevokedAuthority: state,
	}, nil
}

// getX509AuthorityPublicKey gets authority key based on rawKey or next X.509 authority if it is in OLD status
func (s *Service) getX509AuthorityPublicKey(rawKey []byte) (crypto.PublicKey, error) {
	if len(rawKey) == 0 {
		// No key provided, taint OLD key
		nextSlot := s.ca.GetNextX509CASlot()
		if !nextSlot.IsEmpty() {
			return nil, errors.New("unable to use a prepared key")
		}

		return nextSlot.GetPublicKey(), nil
	}

	keyToTaint, err := x509.ParsePKIXPublicKey(rawKey)
	if err != nil {
		return nil, fmt.Errorf("unable to parse public key: %w", err)
	}
	currentSlot := s.ca.GetCurrentX509CASlot()
	ok, err := cryptoutil.PublicKeyEqual(currentSlot.GetPublicKey(), keyToTaint)
	if err != nil {
		return nil, fmt.Errorf("unable to compare provided public key: %w", err)
	}
	if ok {
		return nil, errors.New("unable to use current authority")
	}

	return keyToTaint, nil
}

func slotToProto(slot manager.Slot, status localauthorityv1.AuthorityState_Status) (*localauthorityv1.AuthorityState, error) {
	publicKey := slot.GetPublicKey()
	if publicKey == nil {
		return nil, errors.New("slot does not have a public key")
	}

	return publicKeyToProto(publicKey, status)
}

func publicKeyToProto(publicKey crypto.PublicKey, status localauthorityv1.AuthorityState_Status) (*localauthorityv1.AuthorityState, error) {
	pKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &localauthorityv1.AuthorityState{
		PublicKey: pKey,
		Status:    status,
	}, nil
}
