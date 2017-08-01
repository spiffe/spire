package registration

import (
	"context"

	"github.com/spiffe/control-plane/api/registration/pb"
)

// Implement yor service methods methods.
// e.x: Foo(ctx context.Context,s string)(rs string, err error)
type RegistrationService interface {
	CreateEntry(ctx context.Context, request pb.CreateEntryRequest) (response pb.CreateEntryResponse)
	DeleteEntry(ctx context.Context, request pb.DeleteEntryRequest) (response pb.DeleteEntryResponse)

	ListByAttestor(ctx context.Context, request pb.ListByAttestorRequest) (response pb.ListByAttestorResponse)
	ListBySelector(ctx context.Context, request pb.ListBySelectorRequest) (response pb.ListBySelectorResponse)
	ListBySpiffeID(ctx context.Context, request pb.ListBySpiffeIDRequest) (response pb.ListBySpiffeIDResponse)

	CreateFederatedBundle(ctx context.Context, request pb.CreateFederatedBundleRequest) (response pb.CreateFederatedBundleResponse)
	ListFederatedBundles(ctx context.Context, request pb.ListFederatedBundlesRequest) (response pb.ListFederatedBundlesResponse)
	UpdateFederatedBundle(ctx context.Context, request pb.UpdateFederatedBundleRequest) (response pb.UpdateFederatedBundleResponse)
	DeleteFederatedBundle(ctx context.Context, request pb.DeleteFederatedBundleRequest) (response pb.DeleteFederatedBundleResponse)
}
type stubRegistrationService struct{}

// Get a new instance of the service.
// If you want to add service middleware this is the place to put them.
func NewService() (s *stubRegistrationService) {
	s = &stubRegistrationService{}
	return s
}

// Implement the business logic of CreateEntry
func (re *stubRegistrationService) CreateEntry(ctx context.Context, request pb.CreateEntryRequest) (response pb.CreateEntryResponse) {
	return response
}

// Implement the business logic of DeleteEntry
func (re *stubRegistrationService) DeleteEntry(ctx context.Context, request pb.DeleteEntryRequest) (response pb.DeleteEntryResponse) {
	return response
}

// Implement the business logic of ListByAttestor
func (re *stubRegistrationService) ListByAttestor(ctx context.Context, request pb.ListByAttestorRequest) (response pb.ListByAttestorResponse) {
	return response
}

// Implement the business logic of ListBySelector
func (re *stubRegistrationService) ListBySelector(ctx context.Context, request pb.ListBySelectorRequest) (response pb.ListBySelectorResponse) {
	return response
}

// Implement the business logic of ListBySpiffeID
func (re *stubRegistrationService) ListBySpiffeID(ctx context.Context, request pb.ListBySpiffeIDRequest) (response pb.ListBySpiffeIDResponse) {
	return response
}

// Implement the business logic of CreateFederatedBundle
func (re *stubRegistrationService) CreateFederatedBundle(ctx context.Context, request pb.CreateFederatedBundleRequest) (response pb.CreateFederatedBundleResponse) {
	return response
}

// Implement the business logic of ListFederatedBundles
func (re *stubRegistrationService) ListFederatedBundles(ctx context.Context, request pb.ListFederatedBundlesRequest) (response pb.ListFederatedBundlesResponse) {
	return response
}

// Implement the business logic of UpdateFederatedBundle
func (re *stubRegistrationService) UpdateFederatedBundle(ctx context.Context, request pb.UpdateFederatedBundleRequest) (response pb.UpdateFederatedBundleResponse) {
	return response
}

// Implement the business logic of DeleteFederatedBundle
func (re *stubRegistrationService) DeleteFederatedBundle(ctx context.Context, request pb.DeleteFederatedBundleRequest) (response pb.DeleteFederatedBundleResponse) {
	return response
}
