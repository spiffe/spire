package registration

import (
	"context"

	pb "github.com/spiffe/spire/pkg/api/registration"
	"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/services"
)

//RegistrationService is used to register SPIFFE IDs, and the attestation logic that should be performed on a workload before those IDs can be issued.
type RegistrationService interface {
	CreateEntry(ctx context.Context, request common.RegistrationEntry) (reply pb.RegistrationEntryID, err error)
	DeleteEntry(ctx context.Context, request pb.RegistrationEntryID) (reply common.RegistrationEntry, err error)
	FetchEntry(ctx context.Context, request pb.RegistrationEntryID) (reply common.RegistrationEntry, err error)
	UpdateEntry(ctx context.Context, request pb.UpdateEntryRequest) (reply common.RegistrationEntry, err error)
	ListByParentID(ctx context.Context, request pb.ParentID) (reply common.RegistrationEntries, err error)
	ListBySelector(ctx context.Context, request common.Selector) (reply common.RegistrationEntries, err error)
	ListBySpiffeID(ctx context.Context, request pb.SpiffeID) (reply common.RegistrationEntries, err error)
	CreateFederatedBundle(ctx context.Context, request pb.CreateFederatedBundleRequest) (reply common.Empty, err error)
	ListFederatedBundles(ctx context.Context, request common.Empty) (reply pb.ListFederatedBundlesReply, err error)
	UpdateFederatedBundle(ctx context.Context, request pb.FederatedBundle) (reply common.Empty, err error)
	DeleteFederatedBundle(ctx context.Context, request pb.FederatedSpiffeID) (reply common.Empty, err error)
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
func (re *stubRegistrationService) CreateEntry(ctx context.Context, request common.RegistrationEntry) (pb.RegistrationEntryID, error) {
	registeredID, err := re.registration.CreateEntry(&request)
	return pb.RegistrationEntryID{Id: registeredID}, err
}

// Implement the business logic of DeleteEntry
func (re *stubRegistrationService) DeleteEntry(ctx context.Context, request pb.RegistrationEntryID) (reply common.RegistrationEntry, err error) {
	return reply, err
}

// Implement the business logic of FetchEntry
func (re *stubRegistrationService) FetchEntry(ctx context.Context, request pb.RegistrationEntryID) (common.RegistrationEntry, error) {
	reply, err := re.registration.FetchEntry(request.Id)
	if err != nil {
		return common.RegistrationEntry{}, err
	}
	return *reply, err
}

// Implement the business logic of UpdateEntry
func (re *stubRegistrationService) UpdateEntry(ctx context.Context, request pb.UpdateEntryRequest) (reply common.RegistrationEntry, err error) {
	return reply, err
}

// Implement the business logic of ListByParentID
func (re *stubRegistrationService) ListByParentID(ctx context.Context, request pb.ParentID) (reply common.RegistrationEntries, err error) {
	return reply, err
}

// Implement the business logic of ListBySelector
func (re *stubRegistrationService) ListBySelector(ctx context.Context, request common.Selector) (reply common.RegistrationEntries, err error) {
	return reply, err
}

// Implement the business logic of ListBySpiffeID
func (re *stubRegistrationService) ListBySpiffeID(ctx context.Context, request pb.SpiffeID) (reply common.RegistrationEntries, err error) {
	entries,err := re.registration.ListEntryByParentSpiffeID(request.Id)
	reply = common.RegistrationEntries{Entries:entries}
	return
}

// Implement the business logic of CreateFederatedBundle
func (re *stubRegistrationService) CreateFederatedBundle(ctx context.Context, request pb.CreateFederatedBundleRequest) (reply common.Empty, err error) {
	return reply, err
}

// Implement the business logic of ListFederatedBundles
func (re *stubRegistrationService) ListFederatedBundles(ctx context.Context, request common.Empty) (reply pb.ListFederatedBundlesReply, err error) {
	return reply, err
}

// Implement the business logic of UpdateFederatedBundle
func (re *stubRegistrationService) UpdateFederatedBundle(ctx context.Context, request pb.FederatedBundle) (reply common.Empty, err error) {
	return reply, err
}

// Implement the business logic of DeleteFederatedBundle
func (re *stubRegistrationService) DeleteFederatedBundle(ctx context.Context, request pb.FederatedSpiffeID) (reply common.Empty, err error) {
	return reply, err
}
