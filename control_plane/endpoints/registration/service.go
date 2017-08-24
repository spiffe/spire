package registration

import (
	"context"

	"github.com/spiffe/sri/pkg/common"
	"github.com/spiffe/sri/control_plane/api/registration/proto"
	"github.com/spiffe/sri/services"
)

//RegistrationService is used to register SPIFFE IDs, and the attestation logic that should be performed on a workload before those IDs can be issued.
type RegistrationService interface {
	CreateEntry(ctx context.Context, request common.RegistrationEntry) (reply sri_proto.RegistrationEntryID, err error)
	DeleteEntry(ctx context.Context, request sri_proto.RegistrationEntryID) (reply common.RegistrationEntry, err error)
	FetchEntry(ctx context.Context, request sri_proto.RegistrationEntryID) (reply common.RegistrationEntry, err error)
	UpdateEntry(ctx context.Context, request sri_proto.UpdateEntryRequest) (reply common.RegistrationEntry, err error)
	ListByParentID(ctx context.Context, request sri_proto.ParentID) (reply common.RegistrationEntries, err error)
	ListBySelector(ctx context.Context, request common.Selector) (reply common.RegistrationEntries, err error)
	ListBySpiffeID(ctx context.Context, request sri_proto.SpiffeID) (reply common.RegistrationEntries, err error)
	CreateFederatedBundle(ctx context.Context, request sri_proto.CreateFederatedBundleRequest) (reply common.Empty, err error)
	ListFederatedBundles(ctx context.Context, request common.Empty) (reply sri_proto.ListFederatedBundlesReply, err error)
	UpdateFederatedBundle(ctx context.Context, request sri_proto.FederatedBundle) (reply common.Empty, err error)
	DeleteFederatedBundle(ctx context.Context, request sri_proto.FederatedSpiffeID) (reply common.Empty, err error)
}

type stubRegistrationService struct {
	registration services.Registration
}

//NewService gets a new instance of the service
func NewService(registration services.Registration) (s *stubRegistrationService) {
	s = &stubRegistrationService{}
	s.registration = registration
	return s
}

// Implement the business logic of CreateEntry
func (re *stubRegistrationService) CreateEntry(ctx context.Context, request common.RegistrationEntry) (sri_proto.RegistrationEntryID, error) {
	registeredID, err := re.registration.CreateEntry(&request)
	return sri_proto.RegistrationEntryID{Id: registeredID}, err
}

// Implement the business logic of DeleteEntry
func (re *stubRegistrationService) DeleteEntry(ctx context.Context, request sri_proto.RegistrationEntryID) (reply common.RegistrationEntry, err error) {
	return reply, err
}

// Implement the business logic of FetchEntry
func (re *stubRegistrationService) FetchEntry(ctx context.Context, request sri_proto.RegistrationEntryID) (common.RegistrationEntry, error) {
	reply, err := re.registration.FetchEntry(request.Id)
	if err != nil {
		return common.RegistrationEntry{}, err
	}
	return *reply, err
}

// Implement the business logic of UpdateEntry
func (re *stubRegistrationService) UpdateEntry(ctx context.Context, request sri_proto.UpdateEntryRequest) (reply common.RegistrationEntry, err error) {
	return reply, err
}

// Implement the business logic of ListByParentID
func (re *stubRegistrationService) ListByParentID(ctx context.Context, request sri_proto.ParentID) (reply common.RegistrationEntries, err error) {
	return reply, err
}

// Implement the business logic of ListBySelector
func (re *stubRegistrationService) ListBySelector(ctx context.Context, request common.Selector) (reply common.RegistrationEntries, err error) {
	return reply, err
}

// Implement the business logic of ListBySpiffeID
func (re *stubRegistrationService) ListBySpiffeID(ctx context.Context, request sri_proto.SpiffeID) (reply common.RegistrationEntries, err error) {
	return reply, err
}

// Implement the business logic of CreateFederatedBundle
func (re *stubRegistrationService) CreateFederatedBundle(ctx context.Context, request sri_proto.CreateFederatedBundleRequest) (reply common.Empty, err error) {
	return reply, err
}

// Implement the business logic of ListFederatedBundles
func (re *stubRegistrationService) ListFederatedBundles(ctx context.Context, request common.Empty) (reply sri_proto.ListFederatedBundlesReply, err error) {
	return reply, err
}

// Implement the business logic of UpdateFederatedBundle
func (re *stubRegistrationService) UpdateFederatedBundle(ctx context.Context, request sri_proto.FederatedBundle) (reply common.Empty, err error) {
	return reply, err
}

// Implement the business logic of DeleteFederatedBundle
func (re *stubRegistrationService) DeleteFederatedBundle(ctx context.Context, request sri_proto.FederatedSpiffeID) (reply common.Empty, err error) {
	return reply, err
}
