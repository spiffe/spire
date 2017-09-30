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
	l       logrus.FieldLogger
	catalog catalog.Catalog
}

//Creates an entry in the Registration table,
//used to assign SPIFFE IDs to nodes and workloads.
func (s *registrationServer) CreateEntry(
	ctx context.Context, request *common.RegistrationEntry) (
	response *registration.RegistrationEntryID, err error) {

	dataStore := s.catalog.DataStores()[0]
	createResponse, err := dataStore.CreateRegistrationEntry(
		&datastore.CreateRegistrationEntryRequest{RegisteredEntry: request},
	)

	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to create entry")
	}

	return &registration.RegistrationEntryID{Id: createResponse.RegisteredEntryId}, nil
}

//TODO
func (s *registrationServer) DeleteEntry(
	ctx context.Context, request *registration.RegistrationEntryID) (
	response *common.RegistrationEntry, err error) {
	return response, err
}

//Retrieves a specific registered entry
func (s *registrationServer) FetchEntry(
	ctx context.Context, request *registration.RegistrationEntryID) (
	response *common.RegistrationEntry, err error) {

	dataStore := s.catalog.DataStores()[0]
	fetchResponse, err := dataStore.FetchRegistrationEntry(
		&datastore.FetchRegistrationEntryRequest{RegisteredEntryId: request.Id},
	)
	if err != nil {
		s.l.Error(err)
		return response, errors.New("Error trying to fetch entry")
	}
	return fetchResponse.RegisteredEntry, nil
}

//TODO
func (s *registrationServer) UpdateEntry(
	ctx context.Context, request *registration.UpdateEntryRequest) (
	response *common.RegistrationEntry, err error) {
	return response, err
}

//Returns all the Entries associated with the ParentID value
func (s *registrationServer) ListByParentID(
	ctx context.Context, request *registration.ParentID) (
	response *common.RegistrationEntries, err error) {

	dataStore := s.catalog.DataStores()[0]
	listResponse, err := dataStore.ListParentIDEntries(
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

//TODO
func (s *registrationServer) ListBySelector(
	ctx context.Context, request *common.Selector) (
	response *common.RegistrationEntries, err error) {
	return response, err
}

//TODO
func (s *registrationServer) ListBySpiffeID(
	ctx context.Context, request *registration.SpiffeID) (
	response *common.RegistrationEntries, err error) {
	return
}

//TODO
func (s *registrationServer) CreateFederatedBundle(
	ctx context.Context, request *registration.CreateFederatedBundleRequest) (
	response *common.Empty, err error) {
	return response, err
}

//TODO
func (s *registrationServer) ListFederatedBundles(
	ctx context.Context, request *common.Empty) (
	response *registration.ListFederatedBundlesReply, err error) {
	return response, err
}

//TODO
func (s *registrationServer) UpdateFederatedBundle(
	ctx context.Context, request *registration.FederatedBundle) (
	response *common.Empty, err error) {
	return response, err
}

//TODO
func (s *registrationServer) DeleteFederatedBundle(
	ctx context.Context, request *registration.FederatedSpiffeID) (
	response *common.Empty, err error) {
	return response, err
}
