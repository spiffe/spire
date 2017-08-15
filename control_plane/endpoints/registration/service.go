package registration

import (
	"context"

	proto "github.com/spiffe/sri/control_plane/api/registration/proto"
)

//RegistrationService  is used to register SPIFFE IDs, and the attestation logic that should be performed on a workload before those IDs can be issued.
type RegistrationService interface {
	CreateEntry(ctx context.Context, request proto.RegisteredEntry) (reply proto.RegisteredEntryID, err error)
	DeleteEntry(ctx context.Context, request proto.RegisteredEntryID) (reply proto.RegisteredEntry, err error)
	FetchEntry(ctx context.Context, request proto.RegisteredEntryID) (reply proto.RegisteredEntry, err error)
	UpdateEntry(ctx context.Context, request proto.UpdateEntryRequest) (reply proto.RegisteredEntry, err error)
	ListByParentID(ctx context.Context, request proto.ParentID) (reply proto.RegisteredEntries, err error)
	ListBySelector(ctx context.Context, request proto.Selector) (reply proto.RegisteredEntries, err error)
	ListBySpiffeID(ctx context.Context, request proto.SpiffeID) (reply proto.RegisteredEntries, err error)
	CreateFederatedBundle(ctx context.Context, request proto.CreateFederatedBundleRequest) (reply proto.Empty, err error)
	ListFederatedBundles(ctx context.Context, request proto.Empty) (reply proto.ListFederatedBundlesReply, err error)
	UpdateFederatedBundle(ctx context.Context, request proto.FederatedBundle) (reply proto.Empty, err error)
	DeleteFederatedBundle(ctx context.Context, request proto.FederatedSpiffeID) (reply proto.Empty, err error)
}

type stubRegistrationService struct{}

// Get a new instance of the service.
// If you want to add service middleware this is the place to put them.
func NewService() (s *stubRegistrationService) {
	s = &stubRegistrationService{}
	return s
}

// Implement the business logic of CreateEntry
func (re *stubRegistrationService) CreateEntry(ctx context.Context, request proto.RegisteredEntry) (reply proto.RegisteredEntryID, err error) {
	return reply, err
}

// Implement the business logic of DeleteEntry
func (re *stubRegistrationService) DeleteEntry(ctx context.Context, request proto.RegisteredEntryID) (reply proto.RegisteredEntry, err error) {
	return reply, err
}

// Implement the business logic of FetchEntry
func (re *stubRegistrationService) FetchEntry(ctx context.Context, request proto.RegisteredEntryID) (reply proto.RegisteredEntry, err error) {
	return reply, err
}

// Implement the business logic of UpdateEntry
func (re *stubRegistrationService) UpdateEntry(ctx context.Context, request proto.UpdateEntryRequest) (reply proto.RegisteredEntry, err error) {
	return reply, err
}

// Implement the business logic of ListByParentID
func (re *stubRegistrationService) ListByParentID(ctx context.Context, request proto.ParentID) (reply proto.RegisteredEntries, err error) {
	return reply, err
}

// Implement the business logic of ListBySelector
func (re *stubRegistrationService) ListBySelector(ctx context.Context, request proto.Selector) (reply proto.RegisteredEntries, err error) {
	return reply, err
}

// Implement the business logic of ListBySpiffeID
func (re *stubRegistrationService) ListBySpiffeID(ctx context.Context, request proto.SpiffeID) (reply proto.RegisteredEntries, err error) {
	return reply, err
}

// Implement the business logic of CreateFederatedBundle
func (re *stubRegistrationService) CreateFederatedBundle(ctx context.Context, request proto.CreateFederatedBundleRequest) (reply proto.Empty, err error) {
	return reply, err
}

// Implement the business logic of ListFederatedBundles
func (re *stubRegistrationService) ListFederatedBundles(ctx context.Context, request proto.Empty) (reply proto.ListFederatedBundlesReply, err error) {
	return reply, err
}

// Implement the business logic of UpdateFederatedBundle
func (re *stubRegistrationService) UpdateFederatedBundle(ctx context.Context, request proto.FederatedBundle) (reply proto.Empty, err error) {
	return reply, err
}

// Implement the business logic of DeleteFederatedBundle
func (re *stubRegistrationService) DeleteFederatedBundle(ctx context.Context, request proto.FederatedSpiffeID) (reply proto.Empty, err error) {
	return reply, err
}
