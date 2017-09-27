package server

import (
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
	"golang.org/x/net/context"
)

//Service is used to register SPIFFE IDs, and the attestation logic that should
//be performed on a workload before those IDs can be issued.
type registrationServer struct {
	l         logrus.FieldLogger
	catalog   catalog.Catalog
	dataStore datastore.DataStore
}

//Creates an entry in the Registration table,
//used to assign SPIFFE IDs to nodes and workloads.
func (s *registrationServer) CreateEntry(
	ctx context.Context, request *common.RegistrationEntry) (
	response *registration.RegistrationEntryID, err error) {

	createResponse, err := s.dataStore.CreateRegistrationEntry(
		&datastore.CreateRegistrationEntryRequest{RegisteredEntry: request},
	)

	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to create entry")
	}

	return &registration.RegistrationEntryID{Id: createResponse.RegisteredEntryId}, nil
}

// Implement the business logic of DeleteEntry
func (s *registrationServer) DeleteEntry(
	ctx context.Context, request *registration.RegistrationEntryID) (
	response *common.RegistrationEntry, err error) {
	return response, err
}

//Retrieves a specific registered entry
func (s *registrationServer) FetchEntry(
	ctx context.Context, request *registration.RegistrationEntryID) (
	response *common.RegistrationEntry, err error) {

	fetchResponse, err := s.dataStore.FetchRegistrationEntry(
		&datastore.FetchRegistrationEntryRequest{RegisteredEntryId: request.Id},
	)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to fetch entry")
	}
	return fetchResponse.RegisteredEntry, nil
}

// Implement the business logic of UpdateEntry
func (s *registrationServer) UpdateEntry(
	ctx context.Context, request *registration.UpdateEntryRequest) (
	response *common.RegistrationEntry, err error) {
	return response, err
}

// Implement the business logic of ListByParentID
func (s *registrationServer) ListByParentID(
	ctx context.Context, request *registration.ParentID) (
	response *common.RegistrationEntries, err error) {

	listResponse, err := s.dataStore.ListParentIDEntries(
		&datastore.ListParentIDEntriesRequest{ParentId: request.Id},
	)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to list entries by parent ID")
	}

	return &common.RegistrationEntries{
		Entries: listResponse.RegisteredEntryList,
	}, nil
}

// Implement the business logic of ListBySelector
func (s *registrationServer) ListBySelector(
	ctx context.Context, request *common.Selector) (
	response *common.RegistrationEntries, err error) {
	return response, err
}

// Implement the business logic of ListBySpiffeID
func (s *registrationServer) ListBySpiffeID(
	ctx context.Context, request *registration.SpiffeID) (
	response *common.RegistrationEntries, err error) {
	return
}

// Implement the business logic of CreateFederatedBundle
func (s *registrationServer) CreateFederatedBundle(
	ctx context.Context, request *registration.CreateFederatedBundleRequest) (
	response *common.Empty, err error) {
	return response, err
}

// Implement the business logic of ListFederatedBundles
func (s *registrationServer) ListFederatedBundles(
	ctx context.Context, request *common.Empty) (
	response *registration.ListFederatedBundlesReply, err error) {
	return response, err
}

// Implement the business logic of UpdateFederatedBundle
func (s *registrationServer) UpdateFederatedBundle(
	ctx context.Context, request *registration.FederatedBundle) (
	response *common.Empty, err error) {
	return response, err
}

// Implement the business logic of DeleteFederatedBundle
func (s *registrationServer) DeleteFederatedBundle(
	ctx context.Context, request *registration.FederatedSpiffeID) (
	response *common.Empty, err error) {
	return response, err
}
