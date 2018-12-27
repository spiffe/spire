package registration

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/gofrs/uuid/v3"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/pkg/common/telemetry"
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
	Metrics     telemetry.Metrics
	Catalog     catalog.Catalog
	TrustDomain url.URL
}

//Creates an entry in the Registration table,
//used to assign SPIFFE IDs to nodes and workloads.
func (h *Handler) CreateEntry(
	ctx context.Context, request *common.RegistrationEntry) (
	response *registration.RegistrationEntryID, err error) {

	defer telemetry.CountCall(h.Metrics, "registration_api", "entry", "create")(&err)

	request, err = h.prepareRegistrationEntry(request, false)
	if err != nil {
		h.Log.Error(err)
		return nil, err
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
		return nil, errors.New("Error trying to create entry")
	}

	return &registration.RegistrationEntryID{Id: createResponse.Entry.EntryId}, nil
}

func (h *Handler) DeleteEntry(
	ctx context.Context, request *registration.RegistrationEntryID) (
	response *common.RegistrationEntry, err error) {

	defer telemetry.CountCall(h.Metrics, "registration_api", "entry", "delete")(&err)

	ds := h.getDataStore()
	req := &datastore.DeleteRegistrationEntryRequest{
		EntryId: request.Id,
	}
	resp, err := ds.DeleteRegistrationEntry(ctx, req)
	if err != nil {
		return &common.RegistrationEntry{}, err
	}

	return resp.Entry, nil
}

//Retrieves a specific registered entry
func (h *Handler) FetchEntry(
	ctx context.Context, request *registration.RegistrationEntryID) (
	response *common.RegistrationEntry, err error) {

	defer telemetry.CountCall(h.Metrics, "registration_api", "entry", "fetch")(&err)

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

	defer telemetry.CountCall(h.Metrics, "registration_api", "entry", "list")(&err)

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

func (h *Handler) UpdateEntry(
	ctx context.Context, request *registration.UpdateEntryRequest) (
	response *common.RegistrationEntry, err error) {

	defer telemetry.CountCall(h.Metrics, "registration_api", "entry", "update")(&err)

	if request.Entry == nil {
		return nil, errors.New("Request is missing entry to update")
	}

	request.Entry, err = h.prepareRegistrationEntry(request.Entry, true)
	if err != nil {
		h.Log.Error(err)
		return nil, err
	}

	ds := h.getDataStore()
	resp, err := ds.UpdateRegistrationEntry(ctx, &datastore.UpdateRegistrationEntryRequest{
		Entry: request.Entry,
	})
	if err != nil {
		h.Log.Error(err)
		return nil, fmt.Errorf("Failed to update registration entry: %v", err)
	}

	h.Metrics.IncrCounter([]string{"registration_api", "entry", "updated"}, 1)

	return resp.Entry, nil
}

//Returns all the Entries associated with the ParentID value
func (h *Handler) ListByParentID(
	ctx context.Context, request *registration.ParentID) (
	response *common.RegistrationEntries, err error) {

	counter := telemetry.StartCall(h.Metrics, "registration_api", "entry", "list")
	defer counter.Done(&err)

	request.Id, err = idutil.NormalizeSpiffeID(request.Id, idutil.AllowAny())
	if err != nil {
		h.Log.Error(err)
		return nil, err
	}

	counter.AddLabel("parent_id", request.Id)

	ds := h.getDataStore()
	listResponse, err := ds.ListRegistrationEntries(ctx,
		&datastore.ListRegistrationEntriesRequest{
			ByParentId: &wrappers.StringValue{
				Value: request.Id,
			},
		})
	if err != nil {
		h.Log.Error(err)
		return nil, errors.New("Error trying to list entries by parent ID")
	}

	return &common.RegistrationEntries{
		Entries: listResponse.Entries,
	}, nil
}

func (h *Handler) ListBySelector(
	ctx context.Context, request *common.Selector) (
	response *common.RegistrationEntries, err error) {

	counter := telemetry.StartCall(h.Metrics, "registration_api", "entry", "list")
	defer counter.Done(&err)

	counter.AddLabel("selector", fmt.Sprintf("%s:%s", request.Type, request.Value))

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

	counter := telemetry.StartCall(h.Metrics, "registration_api", "entry", "list")
	defer counter.Done(&err)

	request.Id, err = idutil.NormalizeSpiffeID(request.Id, idutil.AllowAny())
	if err != nil {
		h.Log.Error(err)
		return nil, err
	}

	counter.AddLabel("spiffe_id", request.Id)

	ds := h.getDataStore()
	req := &datastore.ListRegistrationEntriesRequest{
		BySpiffeId: &wrappers.StringValue{
			Value: request.Id,
		},
	}
	resp, err := ds.ListRegistrationEntries(ctx, req)
	if err != nil {
		return nil, err
	}

	return &common.RegistrationEntries{
		Entries: resp.Entries,
	}, nil
}

func (h *Handler) CreateFederatedBundle(
	ctx context.Context, request *registration.FederatedBundle) (
	response *common.Empty, err error) {

	counter := telemetry.StartCall(h.Metrics, "registration_api", "federated_bundle", "create")
	defer counter.Done(&err)

	bundle := request.Bundle
	if bundle != nil {
		bundle.TrustDomainId, err = idutil.NormalizeSpiffeID(bundle.TrustDomainId, idutil.AllowAnyTrustDomain())
		if err != nil {
			return nil, err
		}
	} else {
		trustDomainID, err := idutil.NormalizeSpiffeID(request.DEPRECATEDSpiffeId, idutil.AllowAnyTrustDomain())
		if err != nil {
			return nil, err
		}
		bundle, err = bundleutil.BundleProtoFromRootCAsDER(trustDomainID, request.DEPRECATEDCaCerts)
		if err != nil {
			return nil, err
		}
	}

	counter.AddLabel("trust_domain_id", bundle.TrustDomainId)

	if bundle.TrustDomainId == h.TrustDomain.String() {
		return nil, errors.New("federated bundle id cannot match server trust domain")
	}

	ds := h.getDataStore()
	if _, err := ds.CreateBundle(ctx, &datastore.CreateBundleRequest{
		Bundle: bundle,
	}); err != nil {
		return nil, err
	}

	return &common.Empty{}, nil
}

func (h *Handler) FetchFederatedBundle(
	ctx context.Context, request *registration.FederatedBundleID) (
	response *registration.FederatedBundle, err error) {

	defer telemetry.CountCall(h.Metrics, "registration_api", "federated_bundle", "fetch")(&err)

	request.Id, err = idutil.NormalizeSpiffeID(request.Id, idutil.AllowAnyTrustDomain())
	if err != nil {
		return nil, err
	}

	if request.Id == h.TrustDomain.String() {
		return nil, errors.New("federated bundle id cannot match server trust domain")
	}

	ds := h.getDataStore()
	resp, err := ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: request.Id,
	})
	if err != nil {
		return nil, err
	}
	if resp.Bundle == nil {
		return nil, errors.New("bundle not found")
	}

	return &registration.FederatedBundle{
		DEPRECATEDSpiffeId: resp.Bundle.TrustDomainId,
		DEPRECATEDCaCerts:  bundleutil.RootCAsDERFromBundleProto(resp.Bundle),
		Bundle:             resp.Bundle,
	}, nil
}

func (h *Handler) ListFederatedBundles(request *common.Empty, stream registration.Registration_ListFederatedBundlesServer) (err error) {
	defer telemetry.CountCall(h.Metrics, "registration_api", "federated_bundle", "list")(&err)

	ds := h.getDataStore()
	resp, err := ds.ListBundles(stream.Context(), &datastore.ListBundlesRequest{})
	if err != nil {
		return err
	}

	for _, bundle := range resp.Bundles {
		if bundle.TrustDomainId == h.TrustDomain.String() {
			continue
		}
		if err := stream.Send(&registration.FederatedBundle{
			DEPRECATEDSpiffeId: bundle.TrustDomainId,
			DEPRECATEDCaCerts:  bundleutil.RootCAsDERFromBundleProto(bundle),
			Bundle:             bundle,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (h *Handler) UpdateFederatedBundle(
	ctx context.Context, request *registration.FederatedBundle) (
	response *common.Empty, err error) {

	counter := telemetry.StartCall(h.Metrics, "registration_api", "federated_bundle", "update")
	defer counter.Done(&err)

	bundle := request.Bundle
	if bundle != nil {
		bundle.TrustDomainId, err = idutil.NormalizeSpiffeID(bundle.TrustDomainId, idutil.AllowAnyTrustDomain())
		if err != nil {
			return nil, err
		}
	} else {
		trustDomainID, err := idutil.NormalizeSpiffeID(request.DEPRECATEDSpiffeId, idutil.AllowAnyTrustDomain())
		if err != nil {
			return nil, err
		}
		bundle, err = bundleutil.BundleProtoFromRootCAsDER(trustDomainID, request.DEPRECATEDCaCerts)
		if err != nil {
			return nil, err
		}
	}

	counter.AddLabel("trust_domain_id", bundle.TrustDomainId)

	if bundle.TrustDomainId == h.TrustDomain.String() {
		return nil, errors.New("federated bundle id cannot match server trust domain")
	}

	ds := h.getDataStore()
	if _, err := ds.UpdateBundle(ctx, &datastore.UpdateBundleRequest{
		Bundle: bundle,
	}); err != nil {
		return nil, err
	}

	return &common.Empty{}, err
}

func (h *Handler) DeleteFederatedBundle(
	ctx context.Context, request *registration.DeleteFederatedBundleRequest) (
	response *common.Empty, err error) {

	counter := telemetry.StartCall(h.Metrics, "registration_api", "federated_bundle", "delete")
	defer counter.Done(&err)

	request.Id, err = idutil.NormalizeSpiffeID(request.Id, idutil.AllowAnyTrustDomain())
	if err != nil {
		return nil, err
	}

	counter.AddLabel("trust_domain_id", request.Id)

	if request.Id == h.TrustDomain.String() {
		return nil, errors.New("federated bundle id cannot match server trust domain")
	}

	mode, err := convertDeleteBundleMode(request.Mode)
	if err != nil {
		return nil, err
	}

	ds := h.getDataStore()
	if _, err := ds.DeleteBundle(ctx, &datastore.DeleteBundleRequest{
		TrustDomainId: request.Id,
		Mode:          mode,
	}); err != nil {
		return nil, err
	}

	return &common.Empty{}, nil
}

func (h *Handler) CreateJoinToken(
	ctx context.Context, request *registration.JoinToken) (
	token *registration.JoinToken, err error) {

	defer telemetry.CountCall(h.Metrics, "registration_api", "join_token", "create")(&err)

	if request.Ttl < 1 {
		return nil, errors.New("Ttl is required, you must provide one")
	}

	// Generate a token if one wasn't specified
	if request.Token == "" {
		u, err := uuid.NewV4()
		if err != nil {
			return nil, errors.New("Error generating uuid token: %v")
		}
		request.Token = u.String()
	}

	ds := h.getDataStore()
	expiry := time.Now().Unix() + int64(request.Ttl)

	_, err = ds.CreateJoinToken(ctx, &datastore.CreateJoinTokenRequest{
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

	defer telemetry.CountCall(h.Metrics, "registration_api", "bundle", "fetch")(&err)

	ds := h.getDataStore()
	resp, err := ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: h.TrustDomain.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("get bundle from datastore: %v", err)
	}
	if resp.Bundle == nil {
		return nil, errors.New("bundle not found")
	}

	return &registration.Bundle{
		DEPRECATEDCaCerts: bundleutil.RootCAsDERFromBundleProto(resp.Bundle),
		Bundle:            resp.Bundle,
	}, nil
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

func (h *Handler) prepareRegistrationEntry(entry *common.RegistrationEntry, forUpdate bool) (*common.RegistrationEntry, error) {
	entry = cloneRegistrationEntry(entry)
	if forUpdate && entry.EntryId == "" {
		return nil, errors.New("missing registration entry id")
	}

	var err error
	entry.ParentId, err = idutil.NormalizeSpiffeID(entry.ParentId, idutil.AllowAnyInTrustDomain(h.TrustDomain.Host))
	if err != nil {
		return nil, err
	}

	// Validate Spiffe ID
	entry.SpiffeId, err = idutil.NormalizeSpiffeID(entry.SpiffeId, idutil.AllowTrustDomainWorkload(h.TrustDomain.Host))
	if err != nil {
		return nil, err
	}

	return entry, nil
}

func cloneRegistrationEntry(entry *common.RegistrationEntry) *common.RegistrationEntry {
	return proto.Clone(entry).(*common.RegistrationEntry)
}

func convertDeleteBundleMode(in registration.DeleteFederatedBundleRequest_Mode) (datastore.DeleteBundleRequest_Mode, error) {
	switch in {
	case registration.DeleteFederatedBundleRequest_RESTRICT:
		return datastore.DeleteBundleRequest_RESTRICT, nil
	case registration.DeleteFederatedBundleRequest_DISSOCIATE:
		return datastore.DeleteBundleRequest_DISSOCIATE, nil
	case registration.DeleteFederatedBundleRequest_DELETE:
		return datastore.DeleteBundleRequest_DELETE, nil
	}
	return datastore.DeleteBundleRequest_RESTRICT, fmt.Errorf("unhandled delete mode %q", in)
}
