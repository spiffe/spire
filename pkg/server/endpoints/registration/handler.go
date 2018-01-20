package registration

import (
	"errors"
	"time"

	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
	"golang.org/x/net/context"
)

//Service is used to register SPIFFE IDs, and the attestation logic that should
//be performed on a workload before those IDs can be issued.
type Handler struct {
	Log     logrus.FieldLogger
	Catalog catalog.Catalog
}

//Creates an entry in the Registration table,
//used to assign SPIFFE IDs to nodes and workloads.
func (h *Handler) CreateEntry(
	ctx context.Context, request *common.RegistrationEntry) (
	response *registration.RegistrationEntryID, err error) {

	dataStore := h.Catalog.DataStores()[0]
	createResponse, err := dataStore.CreateRegistrationEntry(
		&datastore.CreateRegistrationEntryRequest{RegisteredEntry: request},
	)

	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to create entry")
	}

	return &registration.RegistrationEntryID{Id: createResponse.RegisteredEntryId}, nil
}

func (h *Handler) DeleteEntry(
	ctx context.Context, request *registration.RegistrationEntryID) (
	response *common.RegistrationEntry, err error) {

	ds := h.Catalog.DataStores()[0]
	req := &datastore.DeleteRegistrationEntryRequest{
		RegisteredEntryId: request.Id,
	}
	resp, err := ds.DeleteRegistrationEntry(req)
	if err != nil {
		return &common.RegistrationEntry{}, err
	}

	response = resp.RegisteredEntry
	return response, nil
}

//Retrieves a specific registered entry
func (h *Handler) FetchEntry(
	ctx context.Context, request *registration.RegistrationEntryID) (
	response *common.RegistrationEntry, err error) {

	dataStore := h.Catalog.DataStores()[0]
	fetchResponse, err := dataStore.FetchRegistrationEntry(
		&datastore.FetchRegistrationEntryRequest{RegisteredEntryId: request.Id},
	)
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to fetch entry")
	}
	return fetchResponse.RegisteredEntry, nil
}

func (h *Handler) FetchEntries(
	ctx context.Context, request *common.Empty) (
	response *common.RegistrationEntries, err error) {

	dataStore := h.Catalog.DataStores()[0]
	fetchResponse, err := dataStore.FetchRegistrationEntries(&common.Empty{})
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to fetch entries")
	}
	return fetchResponse.RegisteredEntries, nil
}

//TODO
func (h *Handler) UpdateEntry(
	ctx context.Context, request *registration.UpdateEntryRequest) (
	response *common.RegistrationEntry, err error) {
	return response, err
}

//Returns all the Entries associated with the ParentID value
func (h *Handler) ListByParentID(
	ctx context.Context, request *registration.ParentID) (
	response *common.RegistrationEntries, err error) {

	dataStore := h.Catalog.DataStores()[0]
	listResponse, err := dataStore.ListParentIDEntries(
		&datastore.ListParentIDEntriesRequest{ParentId: request.Id},
	)
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to list entries by parent ID")
	}

	return &common.RegistrationEntries{
		Entries: listResponse.RegisteredEntryList,
	}, nil
}

func (h *Handler) ListBySelector(
	ctx context.Context, request *common.Selector) (
	response *common.RegistrationEntries, err error) {

	ds := h.Catalog.DataStores()[0]
	req := &datastore.ListSelectorEntriesRequest{
		Selectors: []*common.Selector{request},
	}
	resp, err := ds.ListSelectorEntries(req)
	if err != nil {
		return &common.RegistrationEntries{}, err
	}

	response = &common.RegistrationEntries{
		Entries: resp.RegisteredEntryList,
	}
	return response, nil
}

func (h *Handler) ListBySpiffeID(
	ctx context.Context, request *registration.SpiffeID) (
	response *common.RegistrationEntries, err error) {

	ds := h.Catalog.DataStores()[0]
	req := &datastore.ListSpiffeEntriesRequest{
		SpiffeId: request.Id,
	}
	resp, err := ds.ListSpiffeEntries(req)
	if err != nil {
		return &common.RegistrationEntries{}, err
	}

	response = &common.RegistrationEntries{
		Entries: resp.RegisteredEntryList,
	}
	return response, nil
}

//TODO
func (h *Handler) CreateFederatedBundle(
	ctx context.Context, request *registration.CreateFederatedBundleRequest) (
	response *common.Empty, err error) {
	return response, err
}

//TODO
func (h *Handler) ListFederatedBundles(
	ctx context.Context, request *common.Empty) (
	response *registration.ListFederatedBundlesReply, err error) {
	return response, err
}

//TODO
func (h *Handler) UpdateFederatedBundle(
	ctx context.Context, request *registration.FederatedBundle) (
	response *common.Empty, err error) {
	return response, err
}

//TODO
func (h *Handler) DeleteFederatedBundle(
	ctx context.Context, request *registration.FederatedSpiffeID) (
	response *common.Empty, err error) {
	return response, err
}

func (h *Handler) CreateJoinToken(
	ctx context.Context, request *registration.JoinToken) (
	*registration.JoinToken, error) {

	if request.Ttl < 1 {
		return nil, errors.New("Ttl is required, you must provide one")
	}

	// Generate a token if one wasn't specified
	if request.Token == "" {
		request.Token = uuid.NewV4().String()
	}

	ds := h.Catalog.DataStores()[0]
	expiry := time.Now().Unix() + int64(request.Ttl)
	req := &datastore.JoinToken{
		Token:  request.Token,
		Expiry: expiry,
	}

	_, err := ds.RegisterToken(req)
	if err != nil {
		h.Log.Error(err)
		return nil, errors.New("Error trying to register your token")
	}

	return request, nil
}
