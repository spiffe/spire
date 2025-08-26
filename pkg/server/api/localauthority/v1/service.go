package localauthority

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/ca/manager"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/private/server/journal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type CAManager interface {
	// JWT
	GetCurrentJWTKeySlot() manager.Slot
	GetNextJWTKeySlot() manager.Slot
	PrepareJWTKey(ctx context.Context) error
	RotateJWTKey(ctx context.Context)
	IsJWTSVIDsDisabled() bool

	// X509
	GetCurrentX509CASlot() manager.Slot
	GetNextX509CASlot() manager.Slot
	PrepareX509CA(ctx context.Context) error
	RotateX509CA(ctx context.Context)

	IsUpstreamAuthority() bool
	NotifyTaintedX509Authority(ctx context.Context, authorityID string) error
}

// RegisterService registers the service on the gRPC server.
func RegisterService(s grpc.ServiceRegistrar, service *Service) {
	localauthorityv1.RegisterLocalAuthorityServer(s, service)
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
	log := rpccontext.Logger(ctx)
	if s.isJWTSVIDsDisabled() {
		return nil, api.MakeErr(log, codes.Unimplemented, "JWT functionality is disabled", nil)
	}

	current := s.ca.GetCurrentJWTKeySlot()
	switch {
	case current.Status() != journal.Status_ACTIVE:
		return nil, api.MakeErr(log, codes.Unavailable, "server is initializing", nil)
	case current.AuthorityID() == "":
		return nil, api.MakeErr(log, codes.Internal, "current slot does not contain authority ID", nil)
	}

	resp := &localauthorityv1.GetJWTAuthorityStateResponse{
		Active: stateFromSlot(current),
	}

	next := s.ca.GetNextJWTKeySlot()

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

func (s *Service) PrepareJWTAuthority(ctx context.Context, _ *localauthorityv1.PrepareJWTAuthorityRequest) (*localauthorityv1.PrepareJWTAuthorityResponse, error) {
	log := rpccontext.Logger(ctx)
	if s.isJWTSVIDsDisabled() {
		return nil, api.MakeErr(log, codes.Unimplemented, "JWT functionality is disabled", nil)
	}

	current := s.ca.GetCurrentJWTKeySlot()
	if current.Status() != journal.Status_ACTIVE {
		return nil, api.MakeErr(log, codes.Unavailable, "server is initializing", nil)
	}

	if err := s.ca.PrepareJWTKey(ctx); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to prepare JWT authority", err)
	}

	slot := s.ca.GetNextJWTKeySlot()

	rpccontext.AuditRPC(ctx)

	return &localauthorityv1.PrepareJWTAuthorityResponse{
		PreparedAuthority: &localauthorityv1.AuthorityState{
			AuthorityId: slot.AuthorityID(),
			ExpiresAt:   slot.NotAfter().Unix(),
		},
	}, nil
}

func (s *Service) ActivateJWTAuthority(ctx context.Context, req *localauthorityv1.ActivateJWTAuthorityRequest) (*localauthorityv1.ActivateJWTAuthorityResponse, error) {
	rpccontext.AddRPCAuditFields(ctx, buildAuditLogFields(req.AuthorityId))
	log := rpccontext.Logger(ctx)

	if s.isJWTSVIDsDisabled() {
		return nil, api.MakeErr(log, codes.Unimplemented, "JWT functionality is disabled", nil)
	}

	if req.AuthorityId != "" {
		log = log.WithField(telemetry.LocalAuthorityID, req.AuthorityId)
	}

	nextSlot := s.ca.GetNextJWTKeySlot()

	switch {
	// Authority ID is required
	case req.AuthorityId == "":
		return nil, api.MakeErr(log, codes.InvalidArgument, "no authority ID provided", nil)

	/// Only next local authority can be Activated
	case req.AuthorityId != nextSlot.AuthorityID():
		return nil, api.MakeErr(log, codes.InvalidArgument, "unexpected authority ID", nil)

	// Only PREPARED local authorities can be Activated
	case nextSlot.Status() != journal.Status_PREPARED:
		return nil, api.MakeErr(log, codes.Internal, "only Prepared authorities can be activated", fmt.Errorf("unsupported local authority status: %v", nextSlot.Status()))
	}

	s.ca.RotateJWTKey(ctx)

	current := s.ca.GetCurrentJWTKeySlot()
	state := &localauthorityv1.AuthorityState{
		AuthorityId: current.AuthorityID(),
		ExpiresAt:   current.NotAfter().Unix(),
	}
	rpccontext.AuditRPC(ctx)

	return &localauthorityv1.ActivateJWTAuthorityResponse{
		ActivatedAuthority: state,
	}, nil
}

func (s *Service) TaintJWTAuthority(ctx context.Context, req *localauthorityv1.TaintJWTAuthorityRequest) (*localauthorityv1.TaintJWTAuthorityResponse, error) {
	rpccontext.AddRPCAuditFields(ctx, buildAuditLogFields(req.AuthorityId))
	log := rpccontext.Logger(ctx)

	if s.isJWTSVIDsDisabled() {
		return nil, api.MakeErr(log, codes.Unimplemented, "JWT functionality is disabled", nil)
	}

	if req.AuthorityId != "" {
		log = log.WithField(telemetry.LocalAuthorityID, req.AuthorityId)
	}

	nextSlot := s.ca.GetNextJWTKeySlot()

	switch {
	// Authority ID is required
	case req.AuthorityId == "":
		return nil, api.MakeErr(log, codes.InvalidArgument, "no authority ID provided", nil)

	// It is not possible to taint Active authority
	case req.AuthorityId == s.ca.GetCurrentJWTKeySlot().AuthorityID():
		return nil, api.MakeErr(log, codes.InvalidArgument, "unable to taint current local authority", nil)

	// Only next local authority can be tainted
	case req.AuthorityId != nextSlot.AuthorityID():
		return nil, api.MakeErr(log, codes.InvalidArgument, "unexpected authority ID", nil)

	// Only OLD authorities can be tainted
	case nextSlot.Status() != journal.Status_OLD:
		return nil, api.MakeErr(log, codes.InvalidArgument, "only Old local authorities can be tainted", fmt.Errorf("unsupported local authority status: %v", nextSlot.Status()))
	}

	if _, err := s.ds.TaintJWTKey(ctx, s.td.IDString(), nextSlot.AuthorityID()); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to taint JWT authority", err)
	}

	state := &localauthorityv1.AuthorityState{
		AuthorityId: nextSlot.AuthorityID(),
	}

	rpccontext.AuditRPC(ctx)
	log.Info("JWT authority tainted successfully")

	return &localauthorityv1.TaintJWTAuthorityResponse{
		TaintedAuthority: state,
	}, nil
}

func (s *Service) RevokeJWTAuthority(ctx context.Context, req *localauthorityv1.RevokeJWTAuthorityRequest) (*localauthorityv1.RevokeJWTAuthorityResponse, error) {
	rpccontext.AddRPCAuditFields(ctx, buildAuditLogFields(req.AuthorityId))
	log := rpccontext.Logger(ctx)
	if s.isJWTSVIDsDisabled() {
		return nil, api.MakeErr(log, codes.Unimplemented, "JWT functionality is disabled", nil)
	}

	authorityID := req.AuthorityId

	if err := s.validateAuthorityID(ctx, authorityID); err != nil {
		if req.AuthorityId != "" {
			log = log.WithField(telemetry.LocalAuthorityID, req.AuthorityId)
		}
		return nil, api.MakeErr(log, codes.InvalidArgument, "invalid authority ID", err)
	}

	log = log.WithField(telemetry.LocalAuthorityID, authorityID)
	if _, err := s.ds.RevokeJWTKey(ctx, s.td.IDString(), authorityID); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to revoke JWT authority", err)
	}

	state := &localauthorityv1.AuthorityState{
		AuthorityId: authorityID,
	}

	rpccontext.AuditRPC(ctx)
	log.Info("JWT authority revoked successfully")

	return &localauthorityv1.RevokeJWTAuthorityResponse{
		RevokedAuthority: state,
	}, nil
}

func (s *Service) GetX509AuthorityState(ctx context.Context, _ *localauthorityv1.GetX509AuthorityStateRequest) (*localauthorityv1.GetX509AuthorityStateResponse, error) {
	log := rpccontext.Logger(ctx)

	current := s.ca.GetCurrentX509CASlot()
	switch {
	case current.Status() != journal.Status_ACTIVE:
		return nil, api.MakeErr(log, codes.Unavailable, "server is initializing", nil)
	case current.AuthorityID() == "":
		return nil, api.MakeErr(log, codes.Internal, "current slot does not contain authority ID", nil)
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
			AuthorityId:                   slot.AuthorityID(),
			ExpiresAt:                     slot.NotAfter().Unix(),
			UpstreamAuthoritySubjectKeyId: slot.UpstreamAuthorityID(),
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
		return nil, api.MakeErr(log, codes.Internal, "only Prepared authorities can be activated", fmt.Errorf("unsupported local authority status: %v", nextSlot.Status()))
	}

	// Move next into current and reset next to clean CA
	s.ca.RotateX509CA(ctx)

	current := s.ca.GetCurrentX509CASlot()
	state := &localauthorityv1.AuthorityState{
		AuthorityId:                   current.AuthorityID(),
		ExpiresAt:                     current.NotAfter().Unix(),
		UpstreamAuthoritySubjectKeyId: current.UpstreamAuthorityID(),
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

	if s.ca.IsUpstreamAuthority() {
		return nil, api.MakeErr(log, codes.FailedPrecondition, "local authority can't be tainted if there is an upstream authority", nil)
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
		return nil, api.MakeErr(log, codes.InvalidArgument, "only Old local authorities can be tainted", fmt.Errorf("unsupported local authority status: %v", nextSlot.Status()))
	}

	if err := s.ds.TaintX509CA(ctx, s.td.IDString(), nextSlot.AuthorityID()); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to taint X.509 authority", err)
	}

	state := &localauthorityv1.AuthorityState{
		AuthorityId:                   nextSlot.AuthorityID(),
		ExpiresAt:                     nextSlot.NotAfter().Unix(),
		UpstreamAuthoritySubjectKeyId: nextSlot.UpstreamAuthorityID(),
	}

	if err := s.ca.NotifyTaintedX509Authority(ctx, nextSlot.AuthorityID()); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to notify tainted authority", err)
	}

	rpccontext.AuditRPC(ctx)
	log.Info("X.509 authority tainted successfully")

	return &localauthorityv1.TaintX509AuthorityResponse{
		TaintedAuthority: state,
	}, nil
}

func (s *Service) TaintX509UpstreamAuthority(ctx context.Context, req *localauthorityv1.TaintX509UpstreamAuthorityRequest) (*localauthorityv1.TaintX509UpstreamAuthorityResponse, error) {
	rpccontext.AddRPCAuditFields(ctx, buildAuditUpstreamLogFields(req.SubjectKeyId))
	log := rpccontext.Logger(ctx)

	if req.SubjectKeyId != "" {
		log = log.WithField(telemetry.SubjectKeyID, req.SubjectKeyId)
	}

	if !s.ca.IsUpstreamAuthority() {
		return nil, api.MakeErr(log, codes.FailedPrecondition, "upstream authority is not configured", nil)
	}

	// TODO: may we request in lower case?
	// Normalize SKID
	subjectKeyIDRequest := strings.ToLower(req.SubjectKeyId)
	if err := s.validateUpstreamAuthoritySubjectKey(subjectKeyIDRequest); err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "provided subject key id is not valid", err)
	}

	if err := s.ds.TaintX509CA(ctx, s.td.IDString(), subjectKeyIDRequest); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to taint upstream authority", err)
	}

	if err := s.ca.NotifyTaintedX509Authority(ctx, subjectKeyIDRequest); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to notify tainted authority", err)
	}

	rpccontext.AuditRPC(ctx)
	log.Info("X.509 upstream authority tainted successfully")

	return &localauthorityv1.TaintX509UpstreamAuthorityResponse{
		UpstreamAuthoritySubjectKeyId: subjectKeyIDRequest,
	}, nil
}

func (s *Service) RevokeX509Authority(ctx context.Context, req *localauthorityv1.RevokeX509AuthorityRequest) (*localauthorityv1.RevokeX509AuthorityResponse, error) {
	rpccontext.AddRPCAuditFields(ctx, buildAuditLogFields(req.AuthorityId))
	log := rpccontext.Logger(ctx)

	if req.AuthorityId != "" {
		log = log.WithField(telemetry.LocalAuthorityID, req.AuthorityId)
	}

	if s.ca.IsUpstreamAuthority() {
		return nil, api.MakeErr(log, codes.FailedPrecondition, "local authority can't be revoked if there is an upstream authority", nil)
	}

	if err := s.validateLocalAuthorityID(req.AuthorityId); err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "invalid authority ID", err)
	}

	log = log.WithField(telemetry.LocalAuthorityID, req.AuthorityId)
	if err := s.ds.RevokeX509CA(ctx, s.td.IDString(), req.AuthorityId); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to revoke X.509 authority", err)
	}

	state := &localauthorityv1.AuthorityState{
		AuthorityId: req.AuthorityId,
	}

	rpccontext.AuditRPC(ctx)
	log.Info("X.509 authority revoked successfully")

	return &localauthorityv1.RevokeX509AuthorityResponse{
		RevokedAuthority: state,
	}, nil
}

func (s *Service) RevokeX509UpstreamAuthority(ctx context.Context, req *localauthorityv1.RevokeX509UpstreamAuthorityRequest) (*localauthorityv1.RevokeX509UpstreamAuthorityResponse, error) {
	rpccontext.AddRPCAuditFields(ctx, buildAuditUpstreamLogFields(req.SubjectKeyId))
	log := rpccontext.Logger(ctx)

	if req.SubjectKeyId != "" {
		log = log.WithField(telemetry.SubjectKeyID, req.SubjectKeyId)
	}

	if !s.ca.IsUpstreamAuthority() {
		return nil, api.MakeErr(log, codes.FailedPrecondition, "upstream authority is not configured", nil)
	}

	// TODO: may we request in lower case?
	// Normalize SKID
	subjectKeyIDRequest := strings.ToLower(req.SubjectKeyId)
	if err := s.validateUpstreamAuthoritySubjectKey(subjectKeyIDRequest); err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "invalid subject key ID", err)
	}

	if err := s.ds.RevokeX509CA(ctx, s.td.IDString(), subjectKeyIDRequest); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to revoke X.509 upstream authority", err)
	}

	rpccontext.AuditRPC(ctx)
	log.Info("X.509 upstream authority successfully revoked")

	return &localauthorityv1.RevokeX509UpstreamAuthorityResponse{
		UpstreamAuthoritySubjectKeyId: subjectKeyIDRequest,
	}, nil
}

func (s *Service) isJWTSVIDsDisabled() bool {
	return s.ca.IsJWTSVIDsDisabled()
}

// validateLocalAuthorityID validates provided authority ID, and return OLD associated public key
func (s *Service) validateLocalAuthorityID(authorityID string) error {
	nextSlot := s.ca.GetNextX509CASlot()
	switch {
	case authorityID == "":
		return errors.New("no authority ID provided")
	case authorityID == s.ca.GetCurrentX509CASlot().AuthorityID():
		return errors.New("unable to use current authority")
	case authorityID != nextSlot.AuthorityID():
		return errors.New("only Old local authority can be revoked")
	case nextSlot.Status() != journal.Status_OLD:
		return errors.New("only Old local authority can be revoked")
	}

	return nil
}

func (s *Service) validateUpstreamAuthoritySubjectKey(subjectKeyIDRequest string) error {
	if subjectKeyIDRequest == "" {
		return errors.New("no subject key ID provided")
	}

	currentSlot := s.ca.GetCurrentX509CASlot()
	if subjectKeyIDRequest == currentSlot.UpstreamAuthorityID() {
		return errors.New("unable to use upstream authority singing current authority")
	}

	nextSlot := s.ca.GetNextX509CASlot()
	if subjectKeyIDRequest != nextSlot.UpstreamAuthorityID() {
		return errors.New("upstream authority didn't sign the old local authority")
	}

	if nextSlot.Status() == journal.Status_PREPARED {
		return errors.New("only upstream authorities signing an old authority can be used")
	}

	return nil
}

// validateAuthorityID validates provided authority ID
func (s *Service) validateAuthorityID(ctx context.Context, authorityID string) error {
	if authorityID == "" {
		return errors.New("no authority ID provided")
	}

	nextSlot := s.ca.GetNextJWTKeySlot()
	if authorityID == nextSlot.AuthorityID() {
		if nextSlot.Status() == journal.Status_PREPARED {
			return errors.New("unable to use a prepared key")
		}

		return nil
	}

	currentSlot := s.ca.GetCurrentJWTKeySlot()
	if currentSlot.AuthorityID() == authorityID {
		return errors.New("unable to use current authority")
	}

	bundle, err := s.ds.FetchBundle(ctx, s.td.IDString())
	if err != nil {
		return err
	}

	for _, jwtAuthority := range bundle.JwtSigningKeys {
		if jwtAuthority.Kid == authorityID {
			return nil
		}
	}

	return errors.New("no JWT authority found with provided authority ID")
}

func buildAuditLogFields(authorityID string) logrus.Fields {
	fields := logrus.Fields{}
	if authorityID != "" {
		fields[telemetry.LocalAuthorityID] = authorityID
	}
	return fields
}

func buildAuditUpstreamLogFields(authorityID string) logrus.Fields {
	fields := logrus.Fields{}
	if authorityID != "" {
		fields[telemetry.SubjectKeyID] = authorityID
	}
	return fields
}

func stateFromSlot(s manager.Slot) *localauthorityv1.AuthorityState {
	return &localauthorityv1.AuthorityState{
		AuthorityId:                   s.AuthorityID(),
		ExpiresAt:                     s.NotAfter().Unix(),
		UpstreamAuthoritySubjectKeyId: s.UpstreamAuthorityID(),
	}
}
