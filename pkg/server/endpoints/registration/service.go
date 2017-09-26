package registration

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
)

//Service is used to register SPIFFE IDs, and the attestation logic that should
//be performed on a workload before those IDs can be issued.
type Service interface {
	CreateEntry(context.Context, common.RegistrationEntry) (
		registration.RegistrationEntryID, error)
	DeleteEntry(context.Context, registration.RegistrationEntryID) (
		common.RegistrationEntry, error)
	FetchEntry(context.Context, registration.RegistrationEntryID) (
		common.RegistrationEntry, error)
	UpdateEntry(context.Context, registration.UpdateEntryRequest) (
		common.RegistrationEntry, error)
	ListByParentID(context.Context, registration.ParentID) (
		common.RegistrationEntries, error)
	ListBySelector(context.Context, common.Selector) (
		common.RegistrationEntries, error)
	ListBySpiffeID(context.Context, registration.SpiffeID) (
		common.RegistrationEntries, error)
	CreateFederatedBundle(context.Context, registration.CreateFederatedBundleRequest) (
		common.Empty, error)
	ListFederatedBundles(context.Context, common.Empty) (
		registration.ListFederatedBundlesReply, error)
	UpdateFederatedBundle(context.Context, registration.FederatedBundle) (
		common.Empty, error)
	DeleteFederatedBundle(context.Context, registration.FederatedSpiffeID) (
		common.Empty, error)
}

type service struct {
	l         logrus.FieldLogger
	catalog   catalog.Catalog
	dataStore datastore.DataStore
}

//Config is a configuration struct to init the service.
type Config struct {
	Logger  logrus.FieldLogger
	Catalog catalog.Catalog
}

//NewService creates a registration service with the necessary dependencies.
func NewService(config Config) (Service, error) {
	ds, err := config.Catalog.DataStores()
	if err != nil {
		config.Logger.Error(err)
		return &service{}, errors.New("Error trying to get DataStore plugins")
	}
	return &service{
		l:         config.Logger,
		catalog:   config.Catalog,
		dataStore: *ds[0],
	}, nil
}

//Creates an entry in the Registration table,
//used to assign SPIFFE IDs to nodes and workloads.
func (s *service) CreateEntry(
	ctx context.Context, request common.RegistrationEntry) (
	response registration.RegistrationEntryID, err error) {

	createResponse, err := s.dataStore.CreateRegistrationEntry(
		&datastore.CreateRegistrationEntryRequest{RegisteredEntry: &request},
	)

	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to create entry")
	}

	return registration.RegistrationEntryID{Id: createResponse.RegisteredEntryId}, nil
}

// Implement the business logic of DeleteEntry
func (s *service) DeleteEntry(
	ctx context.Context, request registration.RegistrationEntryID) (
	response common.RegistrationEntry, err error) {
	return response, err
}

//Retrieves a specific registered entry
func (s *service) FetchEntry(
	ctx context.Context, request registration.RegistrationEntryID) (
	response common.RegistrationEntry, err error) {

	fetchResponse, err := s.dataStore.FetchRegistrationEntry(
		&datastore.FetchRegistrationEntryRequest{RegisteredEntryId: request.Id},
	)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to fetch entry")
	}
	return *fetchResponse.RegisteredEntry, nil
}

// Implement the business logic of UpdateEntry
func (s *service) UpdateEntry(
	ctx context.Context, request registration.UpdateEntryRequest) (
	response common.RegistrationEntry, err error) {
	return response, err
}

// Implement the business logic of ListByParentID
func (s *service) ListByParentID(
	ctx context.Context, request registration.ParentID) (
	response common.RegistrationEntries, err error) {

	listResponse, err := s.dataStore.ListParentIDEntries(
		&datastore.ListParentIDEntriesRequest{ParentId: request.Id},
	)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to list entries by parent ID")
	}

	return common.RegistrationEntries{
		Entries: listResponse.RegisteredEntryList,
	}, nil
}

// Implement the business logic of ListBySelector
func (s *service) ListBySelector(
	ctx context.Context, request common.Selector) (
	response common.RegistrationEntries, err error) {
	return response, err
}

// Implement the business logic of ListBySpiffeID
func (s *service) ListBySpiffeID(
	ctx context.Context, request registration.SpiffeID) (
	response common.RegistrationEntries, err error) {
	return
}

// Implement the business logic of CreateFederatedBundle
func (s *service) CreateFederatedBundle(
	ctx context.Context, request registration.CreateFederatedBundleRequest) (
	response common.Empty, err error) {
	return response, err
}

// Implement the business logic of ListFederatedBundles
func (s *service) ListFederatedBundles(
	ctx context.Context, request common.Empty) (
	response registration.ListFederatedBundlesReply, err error) {
	return response, err
}

// Implement the business logic of UpdateFederatedBundle
func (s *service) UpdateFederatedBundle(
	ctx context.Context, request registration.FederatedBundle) (
	response common.Empty, err error) {
	return response, err
}

// Implement the business logic of DeleteFederatedBundle
func (s *service) DeleteFederatedBundle(
	ctx context.Context, request registration.FederatedSpiffeID) (
	response common.Empty, err error) {
	return response, err
}
