package registration

import (
	"context"

	"github.com/spiffe/control-plane/api/registration/pb"
)

// Implement yor service methods methods.
// e.x: Foo(ctx context.Context,s string)(rs string, err error)
type RegistrationService interface {
	CreateFederatedEntry(ctx context.Context, request pb.CreateFederatedEntryRequest) (response pb.CreateFederatedEntryResponse)
	CreateFederatedBundle(ctx context.Context, request pb.CreateFederatedBundleRequest) (response pb.CreateFederatedBundleResponse)
	ListFederatedBundles(ctx context.Context, request pb.ListFederatedBundlesRequest) (response pb.ListFederatedBundlesResponse)
	UpdateFederatedBundle(ctx context.Context, request pb.UpdateFederatedBundleRequest) (response pb.UpdateFederatedBundleResponse)
	DeleteFederatedBundle(ctx context.Context, request pb.DeleteFederatedBundleRequest) (response pb.DeleteFederatedBundleResponse)
	CreateEntry(ctx context.Context, request pb.CreateEntryRequest) (response pb.CreateEntryResponse)
	ListAttestorEntries(ctx context.Context, request pb.ListAttestorEntriesRequest) (response pb.ListAttestorEntriesResponse)
	ListSelectorEntries(ctx context.Context, request pb.ListSelectorEntriesRequest) (response pb.ListSelectorEntriesResponse)
	ListSpiffeEntries(ctx context.Context, request pb.ListSpiffeEntriesRequest) (response pb.ListSpiffeEntriesResponse)
	DeleteEntry(ctx context.Context, request pb.DeleteEntryRequest) (response pb.DeleteEntryResponse)
}

type stubRegistrationService struct{}

// Get a new instance of the service.
// If you want to add service middleware this is the place to put them.
func NewService() (s *stubRegistrationService) {
	s = &stubRegistrationService{}
	return s
}

// Implement the business logic of CreateFederatedEntry
func (re *stubRegistrationService) CreateFederatedEntry(ctx context.Context, request pb.CreateFederatedEntryRequest) (response pb.CreateFederatedEntryResponse) {
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

// Implement the business logic of CreateEntry
func (re *stubRegistrationService) CreateEntry(ctx context.Context, request pb.CreateEntryRequest) (response pb.CreateEntryResponse) {
	return response
}

// Implement the business logic of ListAttestorEntries
func (re *stubRegistrationService) ListAttestorEntries(ctx context.Context, request pb.ListAttestorEntriesRequest) (response pb.ListAttestorEntriesResponse) {
	return response
}

// Implement the business logic of ListSelectorEntries
func (re *stubRegistrationService) ListSelectorEntries(ctx context.Context, request pb.ListSelectorEntriesRequest) (response pb.ListSelectorEntriesResponse) {
	return response
}

// Implement the business logic of ListSpiffeEntries
func (re *stubRegistrationService) ListSpiffeEntries(ctx context.Context, request pb.ListSpiffeEntriesRequest) (response pb.ListSpiffeEntriesResponse) {
	return response
}

// Implement the business logic of DeleteEntry
func (re *stubRegistrationService) DeleteEntry(ctx context.Context, request pb.DeleteEntryRequest) (response pb.DeleteEntryResponse) {
	return response
}
