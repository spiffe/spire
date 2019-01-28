package registration

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/gofrs/uuid/v3"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/auth"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
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

	counter, err := h.startCall(ctx, "registration_api", "entry", "create")
	if err != nil {
		return nil, err
	}
	defer counter.Done(&err)

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

	counter, err := h.startCall(ctx, "registration_api", "entry", "delete")
	if err != nil {
		return nil, err
	}
	defer counter.Done(&err)

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

	counter, err := h.startCall(ctx, "registration_api", "entry", "fetch")
	if err != nil {
		return nil, err
	}
	defer counter.Done(&err)

	ds := h.getDataStore()
	fetchResponse, err := ds.FetchRegistrationEntry(ctx,
		&datastore.FetchRegistrationEntryRequest{EntryId: request.Id},
	)
	if err != nil {
		h.Log.Error(err)
		return response, errors.New("Error trying to fetch entry")
	}
	if fetchResponse.Entry == nil {
		return nil, errors.New("no such registration entry")
	}
	return fetchResponse.Entry, nil
}

func (h *Handler) FetchEntries(
	ctx context.Context, request *common.Empty) (
	response *common.RegistrationEntries, err error) {

	counter, err := h.startCall(ctx, "registration_api", "entry", "list")
	if err != nil {
		return nil, err
	}
	defer counter.Done(&err)

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

	counter, err := h.startCall(ctx, "registration_api", "entry", "update")
	if err != nil {
		return nil, err
	}
	defer counter.Done(&err)

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

	counter, err := h.startCall(ctx, "registration_api", "entry", "list")
	if err != nil {
		return nil, err
	}
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

	counter, err := h.startCall(ctx, "registration_api", "entry", "list")
	if err != nil {
		return nil, err
	}
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

	counter, err := h.startCall(ctx, "registration_api", "entry", "list")
	if err != nil {
		return nil, err
	}
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

	counter, err := h.startCall(ctx, "registration_api", "federated_bundle", "create")
	if err != nil {
		return nil, err
	}
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

	counter, err := h.startCall(ctx, "registration_api", "federated_bundle", "fetch")
	if err != nil {
		return nil, err
	}
	defer counter.Done(&err)

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
	counter, err := h.startCall(stream.Context(), "registration_api", "federated_bundle", "list")
	if err != nil {
		return err
	}
	defer counter.Done(&err)

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

	counter, err := h.startCall(ctx, "registration_api", "federated_bundle", "update")
	if err != nil {
		return nil, err
	}
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

	counter, err := h.startCall(ctx, "registration_api", "federated_bundle", "delete")
	if err != nil {
		return nil, err
	}
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

	counter, err := h.startCall(ctx, "registration_api", "join_token", "create")
	if err != nil {
		return nil, err
	}
	defer counter.Done(&err)

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
		return nil, errors.New("Failed to register token")
	}

	return request, nil
}

// FetchBundle retrieves the CA bundle.
func (h *Handler) FetchBundle(
	ctx context.Context, request *common.Empty) (
	response *registration.Bundle, err error) {

	counter, err := h.startCall(ctx, "registration_api", "bundle", "fetch")
	if err != nil {
		return nil, err
	}
	defer counter.Done(&err)

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

//Evict removes (de-attest) node from attested nodes store
func (h *Handler) EvictAgent(ctx context.Context, evictRequest *registration.EvictAgentRequest) (*registration.EvictAgentResponse, error) {
	spiffeID := evictRequest.GetSpiffeID()
	err := h.deleteAttestationEntry(ctx, spiffeID)
	if err != nil {
		h.Log.Warnf("Fail to de-attested agent with ID: %q", spiffeID)
		return &registration.EvictAgentResponse{
			DeleteSucceed: false,
		}, err
	}

	h.Log.Infof("Successfully de-attested agent with ID: %q", spiffeID)
	return &registration.EvictAgentResponse{
		DeleteSucceed: true,
	}, nil
}

//List returns the list of attested nodes
func (h *Handler) ListAgents(ctx context.Context, empty *common.Empty) (*registration.ListAgentsResponse, error) {
	dataStore := h.Catalog.DataStores()[0]
	listAttestedNodesRequest := &datastore.ListAttestedNodesRequest{}
	listAttestedNodesResponse, err := dataStore.ListAttestedNodes(ctx, listAttestedNodesRequest)
	if err != nil {
		return nil, err
	}
	return &registration.ListAgentsResponse{Nodes: listAttestedNodesResponse.Nodes}, nil
}

func (h *Handler) deleteAttestationEntry(ctx context.Context, baseSPIFFEID string) error {
	dataStore := h.Catalog.DataStores()[0]
	deleteRequest := &datastore.DeleteAttestedNodeRequest{
		SpiffeId: baseSPIFFEID,
	}

	if _, err := dataStore.DeleteAttestedNode(ctx, deleteRequest); err != nil {
		return err
	}
	return nil
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

func (h *Handler) startCall(ctx context.Context, key string, keyn ...string) (*telemetry.CallCounter, error) {
	counter := telemetry.StartCall(h.Metrics, key, keyn...)
	if callerID := getCallerID(ctx); callerID != "" {
		counter.AddLabel("caller_id", callerID)
	}
	return counter, nil
}

func (h *Handler) AuthorizeCall(ctx context.Context, fullMethod string) (context.Context, error) {
	// For the time being, authorization is not per-method. In other words, all or nothing.
	callerID, err := authorizeCaller(ctx, h.Catalog.DataStores()[0])
	if err != nil {
		return nil, err
	}
	if callerID != "" {
		ctx = withCallerID(ctx, callerID)
	}
	return ctx, nil
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

func getSpiffeIDFromCert(cert *x509.Certificate) (string, error) {
	if len(cert.URIs) == 0 {
		return "", errors.New("no SPIFFE ID in certificate")
	}
	spiffeID, err := idutil.NormalizeSpiffeIDURL(cert.URIs[0], idutil.AllowAny())
	if err != nil {
		return "", err
	}
	return spiffeID.String(), nil
}

func authorizeCaller(ctx context.Context, ds datastore.DataStore) (spiffeID string, err error) {
	ctxPeer, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.PermissionDenied, "no peer information for caller")
	}

	switch authInfo := ctxPeer.AuthInfo.(type) {
	case credentials.TLSInfo:
		// The caller came over TLS and must present an authorized SPIFFE ID
		if len(authInfo.State.VerifiedChains) == 0 {
			return "", status.Errorf(codes.PermissionDenied, "no verified client certificate")
		}
		chain := authInfo.State.VerifiedChains[0]
		if len(chain) == 0 {
			// the tls package should never supply an empty verified chain, but
			// we'll just be defensive here.
			return "", status.Errorf(codes.PermissionDenied, "verified chain is empty")
		}
		cert := chain[0]
		spiffeID, err = getSpiffeIDFromCert(cert)
		if err != nil {
			return "", status.Error(codes.PermissionDenied, err.Error())
		}
	case auth.CallerInfo:
		// The caller came over UDS and is therefore authorized but does not
		// provide a spiffeID. The file permissions on the UDS are restricted to
		// processes belonging to the same user or group as the server.
		return "", nil
	default:
		// The caller came over an unknown transport
		return "", status.Errorf(codes.PermissionDenied, "unsupported peer auth info type (%T)", authInfo)
	}

	resp, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		BySpiffeId: &wrappers.StringValue{
			Value: spiffeID,
		},
	})
	if err != nil {
		return "", err
	}

	for _, entry := range resp.Entries {
		if entry.Admin {
			return spiffeID, nil
		}
	}

	return "", status.Errorf(codes.PermissionDenied, "SPIFFE ID %q is not authorized", spiffeID)
}

type callerIDKey struct{}

func withCallerID(ctx context.Context, callerID string) context.Context {
	return context.WithValue(ctx, callerIDKey{}, callerID)
}

func getCallerID(ctx context.Context) string {
	callerID, _ := ctx.Value(callerIDKey{}).(string)
	return callerID
}
