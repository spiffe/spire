package registration

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/services"
)

//Service is used to register SPIFFE IDs, and the attestation logic that should be performed on a workload before those IDs can be issued.
type Service interface {
	CreateEntry(ctx context.Context, request common.RegistrationEntry) (reply registration.RegistrationEntryID, err error)
	DeleteEntry(ctx context.Context, request registration.RegistrationEntryID) (reply common.RegistrationEntry, err error)
	FetchEntry(ctx context.Context, request registration.RegistrationEntryID) (reply common.RegistrationEntry, err error)
	UpdateEntry(ctx context.Context, request registration.UpdateEntryRequest) (reply common.RegistrationEntry, err error)
	ListByParentID(ctx context.Context, request registration.ParentID) (reply common.RegistrationEntries, err error)
	ListBySelector(ctx context.Context, request common.Selector) (reply common.RegistrationEntries, err error)
	ListBySpiffeID(ctx context.Context, request registration.SpiffeID) (reply common.RegistrationEntries, err error)
	CreateFederatedBundle(ctx context.Context, request registration.CreateFederatedBundleRequest) (reply common.Empty, err error)
	ListFederatedBundles(ctx context.Context, request common.Empty) (reply registration.ListFederatedBundlesReply, err error)
	UpdateFederatedBundle(ctx context.Context, request registration.FederatedBundle) (reply common.Empty, err error)
	DeleteFederatedBundle(ctx context.Context, request registration.FederatedSpiffeID) (reply common.Empty, err error)
}

type service struct {
	l            logrus.FieldLogger
	dataStore    datastore.DataStore
	registration services.Registration
}

//Config is a configuration struct to init the service.
type Config struct {
	Logger       logrus.FieldLogger
	DataStore    datastore.DataStore
	Registration services.Registration
}

//NewService creates a registration service with the necessary dependencies.
func NewService(config Config) Service {
	return &service{
		l:            config.Logger,
		dataStore:    config.DataStore,
		registration: config.Registration,
	}
}

//Creates an entry in the Registration table, used to assign SPIFFE IDs to nodes and workloads.
func (s *service) CreateEntry(ctx context.Context, request common.RegistrationEntry) (registration.RegistrationEntryID, error) {
	registeredID, err := s.registration.CreateEntry(&request)
	return registration.RegistrationEntryID{Id: registeredID}, err
}

// Implement the business logic of DeleteEntry
func (s *service) DeleteEntry(ctx context.Context, request registration.RegistrationEntryID) (reply common.RegistrationEntry, err error) {
	return reply, err
}

//Retrieves a specific registered entry
func (s *service) FetchEntry(ctx context.Context, request registration.RegistrationEntryID) (common.RegistrationEntry, error) {
	reply, err := s.registration.FetchEntry(request.Id)
	if err != nil {
		return common.RegistrationEntry{}, err
	}
	return *reply, err
}

// Implement the business logic of UpdateEntry
func (s *service) UpdateEntry(ctx context.Context, request registration.UpdateEntryRequest) (reply common.RegistrationEntry, err error) {
	return reply, err
}

// Implement the business logic of ListByParentID
func (s *service) ListByParentID(ctx context.Context, request registration.ParentID) (reply common.RegistrationEntries, err error) {
	entries, err := s.registration.ListEntryByParentSpiffeID(request.Id)
	reply = common.RegistrationEntries{Entries: entries}
	return reply, err
}

// Implement the business logic of ListBySelector
func (s *service) ListBySelector(ctx context.Context, request common.Selector) (reply common.RegistrationEntries, err error) {
	return reply, err
}

// Implement the business logic of ListBySpiffeID
func (s *service) ListBySpiffeID(ctx context.Context, request registration.SpiffeID) (reply common.RegistrationEntries, err error) {
	return
}

// Implement the business logic of CreateFederatedBundle
func (s *service) CreateFederatedBundle(ctx context.Context, request registration.CreateFederatedBundleRequest) (reply common.Empty, err error) {
	return reply, err
}

// Implement the business logic of ListFederatedBundles
func (s *service) ListFederatedBundles(ctx context.Context, request common.Empty) (reply registration.ListFederatedBundlesReply, err error) {
	return reply, err
}

// Implement the business logic of UpdateFederatedBundle
func (s *service) UpdateFederatedBundle(ctx context.Context, request registration.FederatedBundle) (reply common.Empty, err error) {
	return reply, err
}

// Implement the business logic of DeleteFederatedBundle
func (s *service) DeleteFederatedBundle(ctx context.Context, request registration.FederatedSpiffeID) (reply common.Empty, err error) {
	return reply, err
}
