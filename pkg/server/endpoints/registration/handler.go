package registration

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
	"golang.org/x/net/context"
)

//Service is used to register SPIFFE IDs, and the attestation logic that should
//be performed on a workload before those IDs can be issued.
type Handler struct {
	Log         logrus.FieldLogger
	Catalog     catalog.Catalog
	TrustDomain url.URL
}

//Creates an entry in the Registration table,
//used to assign SPIFFE IDs to nodes and workloads.
func (h *Handler) CreateEntry(
	ctx context.Context, request *common.RegistrationEntry) (
	response *registration.RegistrationEntryID, err error) {

	// Validate Spiffe ID
	err = idutil.ValidateSpiffeID(request.SpiffeId, idutil.AllowTrustDomainWorkload(h.TrustDomain.Host))
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error while validating provided Spiffe ID")
	}

	ds := h.getDataStore()

	unique, err := h.isEntryUnique(ctx, ds, request)
	if err != nil {
		h.Log.Error(err)
		return nil, errors.New("Error trying to create entry")
	}

	if !unique {
		err = errors.New("Entry already exists")
		h.Log.Error(err)
		return nil, err
	}

	createResponse, err := ds.CreateRegistrationEntry(ctx,
		&datastore.CreateRegistrationEntryRequest{Entry: request},
	)
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to create entry")
	}

	return &registration.RegistrationEntryID{Id: createResponse.Entry.EntryId}, nil
}

func (h *Handler) DeleteEntry(
	ctx context.Context, request *registration.RegistrationEntryID) (
	response *common.RegistrationEntry, err error) {

	ds := h.getDataStore()
	req := &datastore.DeleteRegistrationEntryRequest{
		EntryId: request.Id,
	}
	resp, err := ds.DeleteRegistrationEntry(ctx, req)
	if err != nil {
		return &common.RegistrationEntry{}, err
	}

	response = resp.Entry
	return response, nil
}

//Retrieves a specific registered entry
func (h *Handler) FetchEntry(
	ctx context.Context, request *registration.RegistrationEntryID) (
	response *common.RegistrationEntry, err error) {

	ds := h.getDataStore()
	fetchResponse, err := ds.FetchRegistrationEntry(ctx,
		&datastore.FetchRegistrationEntryRequest{EntryId: request.Id},
	)
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to fetch entry")
	}
	return fetchResponse.Entry, nil
}

func (h *Handler) FetchEntries(
	ctx context.Context, request *common.Empty) (
	response *common.RegistrationEntries, err error) {

	ds := h.getDataStore()
	fetchResponse, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to fetch entries")
	}
	return &common.RegistrationEntries{
		Entries: fetchResponse.Entries,
	}, nil
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

	ds := h.getDataStore()
	listResponse, err := ds.ListRegistrationEntries(ctx,
		&datastore.ListRegistrationEntriesRequest{
			ByParentId: &wrappers.StringValue{
				Value: request.Id,
			},
		})
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to list entries by parent ID")
	}

	return &common.RegistrationEntries{
		Entries: listResponse.Entries,
	}, nil
}

func (h *Handler) ListBySelector(
	ctx context.Context, request *common.Selector) (
	response *common.RegistrationEntries, err error) {

	ds := h.getDataStore()
	req := &datastore.ListRegistrationEntriesRequest{
		BySelectors: &datastore.BySelectors{
			Selectors: []*common.Selector{request},
		},
	}
	resp, err := ds.ListRegistrationEntries(ctx, req)
	if err != nil {
		return &common.RegistrationEntries{}, err
	}

	return &common.RegistrationEntries{
		Entries: resp.Entries,
	}, nil
}

func (h *Handler) ListBySpiffeID(
	ctx context.Context, request *registration.SpiffeID) (
	response *common.RegistrationEntries, err error) {

	ds := h.getDataStore()
	req := &datastore.ListRegistrationEntriesRequest{
		BySpiffeId: &wrappers.StringValue{
			Value: request.Id,
		},
	}
	resp, err := ds.ListRegistrationEntries(ctx, req)
	if err != nil {
		return &common.RegistrationEntries{}, err
	}

	return &common.RegistrationEntries{
		Entries: resp.Entries,
	}, nil
}

func (h *Handler) CreateFederatedBundle(
	ctx context.Context, request *registration.FederatedBundle) (
	response *common.Empty, err error) {

	if request.SpiffeId == h.TrustDomain.String() {
		return nil, errors.New("federated bundle id cannot match server trust domain")
	}

	if err := idutil.ValidateSpiffeID(request.SpiffeId, idutil.AllowAnyTrustDomain()); err != nil {
		return nil, err
	}

	ds := h.getDataStore()
	if _, err := ds.CreateBundle(ctx, &datastore.CreateBundleRequest{
		Bundle: &datastore.Bundle{
			TrustDomain: request.SpiffeId,
			CaCerts:     request.CaCerts,
		},
	}); err != nil {
		return nil, err
	}

	return &common.Empty{}, nil
}

func (h *Handler) FetchFederatedBundle(
	ctx context.Context, request *registration.FederatedBundleID) (
	response *registration.FederatedBundle, err error) {

	if request.Id == h.TrustDomain.String() {
		return nil, errors.New("federated bundle id cannot match server trust domain")
	}

	if err := idutil.ValidateSpiffeID(request.Id, idutil.AllowAnyTrustDomain()); err != nil {
		return nil, err
	}

	ds := h.getDataStore()
	resp, err := ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomain: request.Id,
	})
	if err != nil {
		return nil, err
	}
	if resp.Bundle == nil {
		return nil, errors.New("no bundle in response")
	}

	return &registration.FederatedBundle{
		SpiffeId: resp.Bundle.TrustDomain,
		CaCerts:  resp.Bundle.CaCerts,
	}, nil
}

func (h *Handler) ListFederatedBundles(request *common.Empty, stream registration.Registration_ListFederatedBundlesServer) (err error) {
	ds := h.getDataStore()
	resp, err := ds.ListBundles(stream.Context(), &datastore.ListBundlesRequest{})
	if err != nil {
		return err
	}

	for _, bundle := range resp.Bundles {
		if bundle.TrustDomain == h.TrustDomain.String() {
			continue
		}
		if err := stream.Send(&registration.FederatedBundle{
			SpiffeId: bundle.TrustDomain,
			CaCerts:  bundle.CaCerts,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (h *Handler) UpdateFederatedBundle(
	ctx context.Context, request *registration.FederatedBundle) (
	response *common.Empty, err error) {

	if request.SpiffeId == h.TrustDomain.String() {
		return nil, errors.New("federated bundle id cannot match server trust domain")
	}

	if err := idutil.ValidateSpiffeID(request.SpiffeId, idutil.AllowAnyTrustDomain()); err != nil {
		return nil, err
	}

	ds := h.getDataStore()
	if _, err := ds.UpdateBundle(ctx, &datastore.UpdateBundleRequest{
		Bundle: &datastore.Bundle{
			TrustDomain: request.SpiffeId,
			CaCerts:     request.CaCerts,
		},
	}); err != nil {
		return nil, err
	}

	return &common.Empty{}, err
}

func (h *Handler) DeleteFederatedBundle(
	ctx context.Context, request *registration.FederatedBundleID) (
	response *common.Empty, err error) {

	if request.Id == h.TrustDomain.String() {
		return nil, errors.New("federated bundle id cannot match server trust domain")
	}

	if err := idutil.ValidateSpiffeID(request.Id, idutil.AllowAnyTrustDomain()); err != nil {
		return nil, err
	}

	ds := h.getDataStore()
	if _, err := ds.DeleteBundle(ctx, &datastore.DeleteBundleRequest{
		TrustDomain: request.Id,
	}); err != nil {
		return nil, err
	}

	return &common.Empty{}, nil
}

func (h *Handler) CreateJoinToken(
	ctx context.Context, request *registration.JoinToken) (
	*registration.JoinToken, error) {

	if request.Ttl < 1 {
		return nil, errors.New("Ttl is required, you must provide one")
	}

	// Generate a token if one wasn't specified
	if request.Token == "" {
		token, err := uuid.NewV4()
		if err != nil {
			return nil, fmt.Errorf("unable to generate new token: %v", err)
		}

		request.Token = token.String()
	}

	ds := h.getDataStore()
	expiry := time.Now().Unix() + int64(request.Ttl)

	_, err := ds.CreateJoinToken(ctx, &datastore.CreateJoinTokenRequest{
		JoinToken: &datastore.JoinToken{
			Token:  request.Token,
			Expiry: expiry,
		},
	})
	if err != nil {
		h.Log.Error(err)
		return nil, errors.New("Error trying to register your token")
	}

	return request, nil
}

// FetchBundle retrieves the CA bundle.
func (h *Handler) FetchBundle(
	ctx context.Context, request *common.Empty) (
	response *registration.Bundle, err error) {
	ds := h.getDataStore()
	resp, err := ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomain: h.TrustDomain.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("get bundle from datastore: %v", err)
	}
	if resp.Bundle == nil {
		return nil, errors.New("response has no bundle")
	}

	return &registration.Bundle{CaCerts: resp.Bundle.CaCerts}, nil
}

func (h *Handler) isEntryUnique(ctx context.Context, ds datastore.DataStore, entry *common.RegistrationEntry) (bool, error) {
	// First we get all the entries that matches the entry's spiffe id.
	req := &datastore.ListRegistrationEntriesRequest{
		BySpiffeId: &wrappers.StringValue{
			Value: entry.SpiffeId,
		},
	}
	res, err := ds.ListRegistrationEntries(ctx, req)
	if err != nil {
		return false, err
	}

	for _, re := range res.Entries {
		// If an existing entry matches the new entry's parent id also, we must check its
		// selectors...
		if re.ParentId == entry.ParentId {
			reSelSet := selector.NewSetFromRaw(re.Selectors)
			entrySelSet := selector.NewSetFromRaw(entry.Selectors)
			if reSelSet.Equal(entrySelSet) {
				return false, nil
			}
		}
	}

	return true, nil
}

func (h *Handler) getDataStore() datastore.DataStore {
	return h.Catalog.DataStores()[0]
}
