package registration

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_common "github.com/spiffe/spire/pkg/common/telemetry/common"
	telemetry_registrationapi "github.com/spiffe/spire/pkg/common/telemetry/server/registrationapi"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var isDNSLabel = regexp.MustCompile(`^[a-zA-Z0-9]([-]*[a-zA-Z0-9])+$`).MatchString

const defaultListEntriesPageSize = 50

//Handler service is used to register SPIFFE IDs, and the attestation logic that should
//be performed on a workload before those IDs can be issued.
type Handler struct {
	Log         logrus.FieldLogger
	Metrics     telemetry.Metrics
	Catalog     catalog.Catalog
	TrustDomain url.URL
	ServerCA    ca.ServerCA
}

//CreateEntry creates an entry in the Registration table,
//used to assign SPIFFE IDs to nodes and workloads.
func (h *Handler) CreateEntry(ctx context.Context, request *common.RegistrationEntry) (_ *registration.RegistrationEntryID, err error) {
	counter := telemetry_registrationapi.StartCreateEntryCall(h.Metrics)
	defer counter.Done(&err)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	l := h.Log.WithField(telemetry.Method, telemetry.CreateRegistrationEntry)

	request, err = h.prepareRegistrationEntry(request, false)
	if err != nil {
		err = status.Error(codes.InvalidArgument, err.Error())
		l.WithError(err).Error("Request parameter validation error")
		return nil, err
	}

	ds := h.getDataStore()

	unique, err := h.isEntryUnique(ctx, ds, request)
	if err != nil {
		l.WithError(err).Error("Error trying to create entry")
		return nil, status.Errorf(codes.Internal, "error trying to create entry: %v", err)
	}

	if !unique {
		l.Error("Entry already exists")
		return nil, status.Error(codes.AlreadyExists, "entry already exists")
	}

	if err := validateRelationshipsOfRegistration(ctx, request.ParentId, request.SpiffeId, request.Type, ds, l); err != nil {
		return nil, err
	}

	createResponse, err := ds.CreateRegistrationEntry(ctx,
		&datastore.CreateRegistrationEntryRequest{Entry: request},
	)
	if err != nil {
		l.WithError(err).Error("Error trying to create entry")
		return nil, status.Errorf(codes.Internal, "error trying to create entry: %v", err)
	}

	return &registration.RegistrationEntryID{Id: createResponse.Entry.EntryId}, nil
}

//DeleteEntry deletes an entry in the Registration table
func (h *Handler) DeleteEntry(ctx context.Context, request *registration.RegistrationEntryID) (_ *common.RegistrationEntry, err error) {
	counter := telemetry_registrationapi.StartDeleteEntryCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.DeleteRegistrationEntry)

	ds := h.getDataStore()
	req := &datastore.DeleteRegistrationEntryRequest{
		EntryId: request.Id,
	}
	resp, err := ds.DeleteRegistrationEntry(ctx, req)
	if err != nil {
		log.WithError(err).Error("Error deleting registration entry")
		return &common.RegistrationEntry{}, status.Error(codes.Internal, err.Error())
	}

	return resp.Entry, nil
}

//FetchEntry Retrieves a specific registered entry
func (h *Handler) FetchEntry(ctx context.Context, request *registration.RegistrationEntryID) (_ *common.RegistrationEntry, err error) {
	counter := telemetry_registrationapi.StartFetchEntryCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.FetchRegistrationEntry)

	ds := h.getDataStore()
	fetchResponse, err := ds.FetchRegistrationEntry(ctx,
		&datastore.FetchRegistrationEntryRequest{EntryId: request.Id},
	)
	if err != nil {
		log.WithError(err).Error("Error trying to fetch entry")
		return nil, status.Errorf(codes.Internal, "error trying to fetch entry: %v", err)
	}
	if fetchResponse.Entry == nil {
		log.Error("No such registration entry")
		return nil, status.Error(codes.NotFound, "no such registration entry")
	}
	return fetchResponse.Entry, nil
}

//FetchEntries retrieves all registered entries
func (h *Handler) FetchEntries(ctx context.Context, request *common.Empty) (_ *common.RegistrationEntries, err error) {
	counter := telemetry_registrationapi.StartListEntriesCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.FetchRegistrationEntries)

	ds := h.getDataStore()
	fetchResponse, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	if err != nil {
		log.WithError(err).Error("Error trying to fetch entries")
		return nil, status.Errorf(codes.Internal, "error trying to fetch entries: %v", err)
	}
	return &common.RegistrationEntries{
		Entries: fetchResponse.Entries,
	}, nil
}

//UpdateEntry updates a specific registered entry
func (h *Handler) UpdateEntry(ctx context.Context, request *registration.UpdateEntryRequest) (_ *common.RegistrationEntry, err error) {
	counter := telemetry_registrationapi.StartUpdateEntryCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.UpdateRegistrationEntry)

	if request.Entry == nil {
		log.Error("Request is missing entry to update")
		return nil, status.Error(codes.InvalidArgument, "request is missing entry to update")
	}

	request.Entry, err = h.prepareRegistrationEntry(request.Entry, true)
	if err != nil {
		log.WithError(err).Error("Error validating request parameters")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	ds := h.getDataStore()
	resp, err := ds.UpdateRegistrationEntry(ctx, &datastore.UpdateRegistrationEntryRequest{
		Entry: request.Entry,
	})
	if err != nil {
		log.WithError(err).Error("Failed to update registration entry")
		return nil, status.Errorf(codes.Internal, "failed to update registration entry: %v", err)
	}

	telemetry_registrationapi.IncrRegistrationAPIUpdatedEntryCounter(h.Metrics)
	log.WithFields(logrus.Fields{
		telemetry.ParentID: resp.Entry.ParentId,
		telemetry.SPIFFEID: resp.Entry.SpiffeId,
	}).Debug("Workload registration successfully updated")

	return resp.Entry, nil
}

//ListByParentID Returns all the Entries associated with the ParentID value
func (h *Handler) ListByParentID(ctx context.Context, request *registration.ParentID) (_ *common.RegistrationEntries, err error) {
	counter := telemetry_registrationapi.StartListEntriesCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	l := h.Log.WithField(telemetry.Method, telemetry.ListRegistrationsByParentID)

	request.Id, err = idutil.NormalizeSpiffeID(request.Id, idutil.AllowAny())
	if err != nil {
		l.WithError(err).Error("Failed to normalize SPIFFE ID")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	ds := h.getDataStore()
	listResponse, err := listByParentID(ctx, request.Id, ds, l)
	if err != nil {
		return nil, err
	}

	return &common.RegistrationEntries{
		Entries: listResponse.Entries,
	}, nil
}

//ListBySelector returns all the Entries associated with the Selector
func (h *Handler) ListBySelector(ctx context.Context, request *common.Selector) (_ *common.RegistrationEntries, err error) {
	counter := telemetry_registrationapi.StartListEntriesCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.ListRegistrationsBySelector)

	ds := h.getDataStore()
	req := &datastore.ListRegistrationEntriesRequest{
		BySelectors: &datastore.BySelectors{
			Selectors: []*common.Selector{request},
		},
	}
	resp, err := ds.ListRegistrationEntries(ctx, req)
	if err != nil {
		log.WithError(err).Error("Failed to list entries by selector")
		return nil, status.Errorf(codes.Internal, "error trying to list entries by selector: %v", err)
	}

	return &common.RegistrationEntries{
		Entries: resp.Entries,
	}, nil
}

//ListBySelectors returns all the Entries associated with the Selectors
func (h *Handler) ListBySelectors(ctx context.Context, request *common.Selectors) (_ *common.RegistrationEntries, err error) {
	counter := telemetry_registrationapi.StartListEntriesCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.ListRegistrationsBySelectors)

	ds := h.getDataStore()
	req := &datastore.ListRegistrationEntriesRequest{
		BySelectors: &datastore.BySelectors{
			Selectors: request.Entries,
		},
	}
	resp, err := ds.ListRegistrationEntries(ctx, req)
	if err != nil {
		log.WithError(err).Error("Failed to list entries by selectors")
		return nil, status.Errorf(codes.Internal, "error trying to list entries by selectors: %v", err)
	}

	return &common.RegistrationEntries{
		Entries: resp.Entries,
	}, nil
}

//ListBySpiffeID returns all the Entries associated with the SPIFFE ID
func (h *Handler) ListBySpiffeID(ctx context.Context, request *registration.SpiffeID) (_ *common.RegistrationEntries, err error) {
	counter := telemetry_registrationapi.StartListEntriesCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)

	l := h.Log.WithField(telemetry.Method, telemetry.ListRegistrationsBySPIFFEID)

	spiffeID, err := idutil.NormalizeSpiffeID(request.Id, idutil.AllowAny())
	if err != nil {
		l.WithError(err).Error("Failed to normalize SPIFFE ID")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	ds := h.getDataStore()
	resp, err := listBySpiffeID(ctx, spiffeID, ds, l)
	if err != nil {
		return nil, err
	}

	return &common.RegistrationEntries{
		Entries: resp.Entries,
	}, nil
}

//ListAllEntriesWithPages retrieves all registered entries with pagination.
func (h *Handler) ListAllEntriesWithPages(ctx context.Context, request *registration.ListAllEntriesRequest) (_ *registration.ListAllEntriesResponse, err error) {
	counter := telemetry_registrationapi.StartListEntriesCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.ListAllEntriesWithPages)

	ds := h.getDataStore()
	var pageSize int32 = defaultListEntriesPageSize
	var token string

	if request.Pagination != nil {
		if request.Pagination.PageSize != 0 {
			pageSize = request.Pagination.PageSize
		}
		token = request.Pagination.Token
	}
	fetchResponse, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		Pagination: &datastore.Pagination{
			Token:    token,
			PageSize: pageSize,
		},
	})
	if err != nil {
		log.WithError(err).Error("Error trying to fetch entries")
		return nil, status.Errorf(codes.Internal, "error trying to fetch entries: %v", err)
	}
	return &registration.ListAllEntriesResponse{
		Entries: fetchResponse.Entries,
		Pagination: &registration.Pagination{
			Token:    fetchResponse.Pagination.Token,
			PageSize: fetchResponse.Pagination.PageSize,
		},
	}, nil
}

func (h *Handler) CreateFederatedBundle(ctx context.Context, request *registration.FederatedBundle) (_ *common.Empty, err error) {
	counter := telemetry_registrationapi.StartCreateFedBundleCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.CreateFederatedBundle)

	bundle := request.Bundle
	if bundle == nil {
		log.Error("Bundle field is required")
		return nil, status.Error(codes.InvalidArgument, "bundle field is required")
	}
	bundle.TrustDomainId, err = idutil.NormalizeSpiffeID(bundle.TrustDomainId, idutil.AllowAnyTrustDomain())
	if err != nil {
		log.WithError(err).Error("Failed to normalize SPIFFE ID")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if bundle.TrustDomainId == h.TrustDomain.String() {
		log.Error("Federated bundle id cannot match server trust domain")
		return nil, status.Error(codes.InvalidArgument, "federated bundle id cannot match server trust domain")
	}

	ds := h.getDataStore()
	if _, err := ds.CreateBundle(ctx, &datastore.CreateBundleRequest{
		Bundle: bundle,
	}); err != nil {
		log.WithError(err).Error("Failed to create bundle")
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &common.Empty{}, nil
}

func (h *Handler) FetchFederatedBundle(ctx context.Context, request *registration.FederatedBundleID) (_ *registration.FederatedBundle, err error) {
	counter := telemetry_registrationapi.StartFetchFedBundleCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.FetchFederatedBundle)

	request.Id, err = idutil.NormalizeSpiffeID(request.Id, idutil.AllowAnyTrustDomain())
	if err != nil {
		log.WithError(err).Error("Failed to normalize SPIFFE ID")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if request.Id == h.TrustDomain.String() {
		log.Error("Federated bundle id cannot match server trust domain")
		return nil, status.Error(codes.InvalidArgument, "federated bundle id cannot match server trust domain")
	}

	ds := h.getDataStore()
	resp, err := ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: request.Id,
	})
	if err != nil {
		log.WithError(err).Error("Failed to fetch bundle")
		return nil, status.Error(codes.Internal, err.Error())
	}
	if resp.Bundle == nil {
		log.Error("Bundle not found")
		return nil, status.Error(codes.NotFound, "bundle not found")
	}

	return &registration.FederatedBundle{
		Bundle: resp.Bundle,
	}, nil
}

func (h *Handler) ListFederatedBundles(request *common.Empty, stream registration.Registration_ListFederatedBundlesServer) (err error) {
	counter := telemetry_registrationapi.StartListFedBundlesCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(stream.Context()))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.ListFederatedBundles)

	ds := h.getDataStore()
	resp, err := ds.ListBundles(stream.Context(), &datastore.ListBundlesRequest{})
	if err != nil {
		log.WithError(err).Error("Failed to list bundles")
		return status.Error(codes.Internal, err.Error())
	}

	for _, bundle := range resp.Bundles {
		if bundle.TrustDomainId == h.TrustDomain.String() {
			continue
		}
		if err := stream.Send(&registration.FederatedBundle{
			Bundle: bundle,
		}); err != nil {
			log.WithError(err).Error("Failed to send response over stream")
			return status.Error(codes.Internal, err.Error())
		}
	}

	return nil
}

func (h *Handler) UpdateFederatedBundle(ctx context.Context, request *registration.FederatedBundle) (_ *common.Empty, err error) {
	counter := telemetry_registrationapi.StartUpdateFedBundleCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.UpdateFederatedBundle)

	bundle := request.Bundle
	if bundle == nil {
		log.Error("Bundle field is required")
		return nil, status.Error(codes.InvalidArgument, "bundle field is required")
	}
	bundle.TrustDomainId, err = idutil.NormalizeSpiffeID(bundle.TrustDomainId, idutil.AllowAnyTrustDomain())
	if err != nil {
		log.WithError(err).Error("Failed to normalize SPIFFE ID")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if bundle.TrustDomainId == h.TrustDomain.String() {
		log.Error("Federated bundle ID cannot match server trust domain")
		return nil, status.Error(codes.InvalidArgument, "federated bundle id cannot match server trust domain")
	}

	ds := h.getDataStore()
	if _, err := ds.UpdateBundle(ctx, &datastore.UpdateBundleRequest{
		Bundle: bundle,
	}); err != nil {
		log.WithError(err).Error("Failed to update federated bundle")
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &common.Empty{}, err
}

func (h *Handler) DeleteFederatedBundle(ctx context.Context, request *registration.DeleteFederatedBundleRequest) (_ *common.Empty, err error) {
	counter := telemetry_registrationapi.StartDeleteFedBundleCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.DeleteFederatedBundle)

	request.Id, err = idutil.NormalizeSpiffeID(request.Id, idutil.AllowAnyTrustDomain())
	if err != nil {
		log.WithError(err).Error("Failed to normalize SPIFFE ID")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if request.Id == h.TrustDomain.String() {
		log.Error("Federated bundle ID cannot match server trust domain")
		return nil, status.Error(codes.InvalidArgument, "federated bundle id cannot match server trust domain")
	}

	mode, err := convertDeleteBundleMode(request.Mode)
	if err != nil {
		log.WithError(err).Error("Unknown delete bundle mode in request")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	ds := h.getDataStore()
	if _, err := ds.DeleteBundle(ctx, &datastore.DeleteBundleRequest{
		TrustDomainId: request.Id,
		Mode:          mode,
	}); err != nil {
		log.WithError(err).Error("Failed to delete federated bundle")
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &common.Empty{}, nil
}

func (h *Handler) CreateJoinToken(ctx context.Context, request *registration.JoinToken) (_ *registration.JoinToken, err error) {
	counter := telemetry_registrationapi.StartCreateJoinTokenCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.CreateJoinToken)

	if request.Ttl < 1 {
		log.Error("TTL is required")
		return nil, status.Error(codes.InvalidArgument, "ttl is required, you must provide one")
	}

	// Generate a token if one wasn't specified
	if request.Token == "" {
		u, err := uuid.NewV4()
		if err != nil {
			log.WithError(err).Error("Failed to generate UUID token")
			return nil, status.Errorf(codes.Internal, "error generating uuid token: %v", err)
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
		log.WithError(err).Error("Failed to register token")
		return nil, status.Errorf(codes.Internal, "Failed to register token: %v", err)
	}

	return request, nil
}

// FetchBundle retrieves the CA bundle.
func (h *Handler) FetchBundle(ctx context.Context, request *common.Empty) (_ *registration.Bundle, err error) {
	counter := telemetry_registrationapi.StartFetchBundleCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.FetchBundle)

	ds := h.getDataStore()
	resp, err := ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: h.TrustDomain.String(),
	})
	if err != nil {
		log.WithError(err).Error("Failed to get bundle from datastore")
		return nil, status.Errorf(codes.Internal, "get bundle from datastore: %v", err)
	}
	if resp.Bundle == nil {
		log.Error("Bundle not found")
		return nil, status.Error(codes.NotFound, "bundle not found")
	}

	return &registration.Bundle{
		Bundle: resp.Bundle,
	}, nil
}

//EvictAgent removes a node from the attested nodes store
func (h *Handler) EvictAgent(ctx context.Context, evictRequest *registration.EvictAgentRequest) (*registration.EvictAgentResponse, error) {
	spiffeID := evictRequest.GetSpiffeID()
	log := h.Log.WithFields(logrus.Fields{
		telemetry.Method:   telemetry.EvictAgent,
		telemetry.SPIFFEID: spiffeID,
	})

	deletedNode, err := h.deleteAttestedNode(ctx, spiffeID)
	if err != nil {
		log.WithError(err).Warn("Failed to evict agent")
		return nil, err
	}

	log.Debug("Successfully evicted agent")
	return &registration.EvictAgentResponse{
		Node: deletedNode,
	}, nil
}

//ListAgents returns the list of attested nodes
func (h *Handler) ListAgents(ctx context.Context, listReq *registration.ListAgentsRequest) (*registration.ListAgentsResponse, error) {
	log := h.Log.WithField(telemetry.Method, telemetry.ListAgents)
	ds := h.Catalog.GetDataStore()
	req := &datastore.ListAttestedNodesRequest{}
	resp, err := ds.ListAttestedNodes(ctx, req)
	if err != nil {
		log.WithError(err).Error("Failed to list attested nodes")
		return nil, err
	}
	return &registration.ListAgentsResponse{Nodes: resp.Nodes}, nil
}

func (h *Handler) MintX509SVID(ctx context.Context, req *registration.MintX509SVIDRequest) (_ *registration.MintX509SVIDResponse, err error) {
	counter := telemetry_registrationapi.StartMintX509SVIDCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.MintX509SVID)

	spiffeID, err := h.normalizeSPIFFEIDForMinting(req.SpiffeId)
	if err != nil {
		log.WithError(err).Error("Failed to normalize SPIFFE ID for minting")
		return nil, err
	}

	if len(req.Csr) == 0 {
		log.Error("Request missing CSR")
		return nil, status.Error(codes.InvalidArgument, "request missing CSR")
	}

	for _, dnsName := range req.DnsNames {
		if err := validateDNS(dnsName); err != nil {
			log.WithField(telemetry.DNSName, dnsName).Error("Invalid DNS name")
			return nil, status.Errorf(codes.InvalidArgument, "invalid DNS name: %v", err)
		}
	}

	csr, err := x509.ParseCertificateRequest(req.Csr)
	if err != nil {
		log.WithError(err).Error("Invalid CSR")
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		log.WithError(err).Error("Invalid CSR: signature verification failed")
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: signature verify failed")
	}

	svid, err := h.ServerCA.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  spiffeID,
		PublicKey: csr.PublicKey,
		TTL:       time.Duration(req.Ttl) * time.Second,
		DNSList:   req.DnsNames,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign X.509 SVID")
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp, err := h.getDataStore().FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: h.TrustDomain.String(),
	})
	if err != nil {
		log.WithError(err).Error("Failed to fetch bundle from datastore")
		return nil, status.Error(codes.Internal, err.Error())
	}
	if resp.Bundle == nil {
		log.Error("Bundle not found")
		return nil, status.Error(codes.FailedPrecondition, "bundle not found")
	}

	svidChain := make([][]byte, 0, len(svid))
	for _, cert := range svid {
		svidChain = append(svidChain, cert.Raw)
	}

	var rootCAs [][]byte
	for _, rootCA := range resp.Bundle.RootCas {
		rootCAs = append(rootCAs, rootCA.DerBytes)
	}

	return &registration.MintX509SVIDResponse{
		SvidChain: svidChain,
		RootCas:   rootCAs,
	}, nil
}

func (h *Handler) MintJWTSVID(ctx context.Context, req *registration.MintJWTSVIDRequest) (_ *registration.MintJWTSVIDResponse, err error) {
	counter := telemetry_registrationapi.StartMintJWTSVIDCall(h.Metrics)
	telemetry_common.AddCallerID(counter, getCallerID(ctx))
	defer counter.Done(&err)
	log := h.Log.WithField(telemetry.Method, telemetry.MintJWTSVID)

	spiffeID, err := h.normalizeSPIFFEIDForMinting(req.SpiffeId)
	if err != nil {
		log.WithError(err).Error("Failed to normalize SPIFFE ID for minting")
		return nil, err
	}

	if len(req.Audience) == 0 {
		log.Error("Request must specify at least one audience")
		return nil, status.Error(codes.InvalidArgument, "request must specify at least one audience")
	}

	token, err := h.ServerCA.SignJWTSVID(ctx, ca.JWTSVIDParams{
		SpiffeID: spiffeID,
		TTL:      time.Duration(req.Ttl) * time.Second,
		Audience: req.Audience,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign JWT-SVID")
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &registration.MintJWTSVIDResponse{
		Token: token,
	}, nil
}

// GetNodeSelectors returns node (agent) selectors
func (h *Handler) GetNodeSelectors(ctx context.Context, req *registration.GetNodeSelectorsRequest) (*registration.GetNodeSelectorsResponse, error) {
	log := h.Log.WithField(telemetry.Method, telemetry.GetNodeSelectors)
	ds := h.Catalog.GetDataStore()
	r := &datastore.GetNodeSelectorsRequest{
		SpiffeId: req.SpiffeId,
	}
	resp, err := ds.GetNodeSelectors(ctx, r)
	if err != nil {
		log.WithError(err).Error("Failed to get node selectors")
		return nil, err
	}
	return &registration.GetNodeSelectorsResponse{
		Selectors: &registration.NodeSelectors{
			SpiffeId:  resp.Selectors.SpiffeId,
			Selectors: resp.Selectors.Selectors,
		},
	}, nil
}

func (h *Handler) deleteAttestedNode(ctx context.Context, agentID string) (*common.AttestedNode, error) {
	if agentID == "" {
		return nil, errors.New("empty agent ID")
	}

	ds := h.Catalog.GetDataStore()
	req := &datastore.DeleteAttestedNodeRequest{
		SpiffeId: agentID,
	}

	resp, err := ds.DeleteAttestedNode(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.Node, nil
}

func (h *Handler) normalizeSPIFFEIDForMinting(spiffeID string) (string, error) {
	if spiffeID == "" {
		return "", status.Error(codes.InvalidArgument, "request missing SPIFFE ID")
	}

	spiffeID, err := idutil.NormalizeSpiffeID(spiffeID, idutil.AllowTrustDomainWorkload(h.TrustDomain.Host))
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, err.Error())
	}

	return spiffeID, nil
}

func (h *Handler) isEntryUnique(ctx context.Context, ds datastore.DataStore, entry *common.RegistrationEntry) (bool, error) {
	// First we get all the entries that matches the entry's spiffe id.
	req := &datastore.ListRegistrationEntriesRequest{
		BySpiffeId: &wrappers.StringValue{
			Value: entry.SpiffeId,
		},
		ByParentId: &wrappers.StringValue{
			Value: entry.ParentId,
		},
		BySelectors: &datastore.BySelectors{
			Match:     datastore.BySelectors_MATCH_EXACT,
			Selectors: entry.Selectors,
		},
	}
	res, err := ds.ListRegistrationEntries(ctx, req)
	if err != nil {
		return false, err
	}

	return len(res.Entries) == 0, nil
}

func (h *Handler) getDataStore() datastore.DataStore {
	return h.Catalog.GetDataStore()
}

func (h *Handler) prepareRegistrationEntry(entry *common.RegistrationEntry, forUpdate bool) (*common.RegistrationEntry, error) {
	entry = cloneRegistrationEntry(entry)
	if forUpdate && entry.EntryId == "" {
		return nil, errors.New("missing registration entry id")
	}

	var err error
	for _, dns := range entry.DnsNames {
		err = validateDNS(dns)
		if err != nil {
			return nil, fmt.Errorf("dns name %v failed validation: %v", dns, err)
		}
	}

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

func (h *Handler) AuthorizeCall(ctx context.Context, fullMethod string) (context.Context, error) {
	// For the time being, authorization is not per-method. In other words, all or nothing.
	callerID, err := authorizeCaller(ctx, h.getDataStore())
	if err != nil {
		h.Log.WithError(err).Error("Failed to authorize caller")
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
	case peertracker.AuthInfo:
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

func validateDNS(dns string) error {
	// follow https://tools.ietf.org/html/rfc5280#section-4.2.1.6
	// do not allow empty or the technically valid DNS " "
	dns = strings.TrimSpace(dns)
	if len(dns) == 0 {
		return errors.New("empty or only whitespace")
	}

	// handle up to 255 characters
	if len(dns) > 255 {
		return errors.New("length exceeded")
	}

	// a DNS is split into labels by "."
	splitDNS := strings.Split(dns, ".")
	for _, label := range splitDNS {
		if err := validateDNSLabel(label); err != nil {
			return err
		}
	}

	return nil
}

func validateDNSLabel(label string) error {
	// follow https://tools.ietf.org/html/rfc5280#section-4.2.1.6 guidance
	// <label> ::= <let-dig> [ [ <ldh-str> ] <let-dig> ]
	// <ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>
	if len(label) == 0 {
		return errors.New("label is empty")
	}
	if len(label) > 63 {
		return fmt.Errorf("label length exceeded: %v", label)
	}

	if match := isDNSLabel(label); !match {
		return fmt.Errorf("label does not match regex: %v", label)
	}

	return nil
}

func listBySpiffeID(ctx context.Context, spiffeID string, ds datastore.DataStore, l logrus.FieldLogger) (*datastore.ListRegistrationEntriesResponse, error) {
	req := &datastore.ListRegistrationEntriesRequest{
		BySpiffeId: &wrappers.StringValue{
			Value: spiffeID,
		},
	}
	resp, err := ds.ListRegistrationEntries(ctx, req)
	if err != nil {
		l.WithError(err).Error("Failed to list entries by SPIFFE ID")
		return nil, status.Errorf(codes.Internal, "error trying to list entries by SPIFFE ID: %v", err)
	}

	return resp, nil
}

func listByParentID(ctx context.Context, parentID string, ds datastore.DataStore, l logrus.FieldLogger) (*datastore.ListRegistrationEntriesResponse, error) {
	listResponse, err := ds.ListRegistrationEntries(ctx,
		&datastore.ListRegistrationEntriesRequest{
			ByParentId: &wrappers.StringValue{
				Value: parentID,
			},
		})
	if err != nil {
		l.WithError(err).Error("Failed to list entries by parent ID")
		return nil, status.Errorf(codes.Internal, "error trying to list entries by parent ID: %v", err)
	}

	return listResponse, nil
}

func validateRelationshipsOfRegistration(ctx context.Context, parentID, spiffeID string, regType common.RegistrationEntryType, ds datastore.DataStore, l logrus.FieldLogger) error {
	// We want to prevent registrations whose parent registration is also of type WORKLOAD.
	// In order to enforce that, we need to evaluate the possible relationships of parent and children
	// that this registration would introduce.
	if err := validateParentOfRegistration(ctx, parentID, ds, l); err != nil {
		return err
	}
	if err := validateChildrenOfRegistration(ctx, spiffeID, regType, ds, l); err != nil {
		return err
	}
	return nil
}

func validateParentOfRegistration(ctx context.Context, parentID string, ds datastore.DataStore, l logrus.FieldLogger) error {
	// If this requested registration's parent ID maps to an existing registration's SPIFFE ID,
	// validate that the parent registration is of type NODE or UNKNOWN.
	// Example: There exists a Workload registration A with SPIFFE ID "spiffe://foo".
	//          This requested Workload registration B specifies "spiffe://foo" as its parent.
	parentEntryResp, err := listBySpiffeID(ctx, parentID, ds, l)
	if err != nil {
		return fmt.Errorf("error looking up parent entry: %v", err)
	}

	if len(parentEntryResp.Entries) == 1 {
		parentEntry := parentEntryResp.Entries[0]
		if parentEntry.Type == common.RegistrationEntryType_WORKLOAD {
			l.Error("Registration cannot have a parent registration of type WORKLOAD")
			return status.Errorf(codes.InvalidArgument, "registration cannot have a parent registration of type WORKLOAD")
		}
	}

	return nil
}

func validateChildrenOfRegistration(ctx context.Context, spiffeID string, regType common.RegistrationEntryType, ds datastore.DataStore, l logrus.FieldLogger) error {
	// If there are already registrations who specify this requested registration's SPIFFE ID as their parent ID,
	// validate that this requested registration is of type NODE or UNKNOWN.
	// Example: There exists a Workload registration A
	//          whose parent ID "spiffe://foo" does not correspond with an existing registration.
	//          This requested Workload registration B has a SPIFFE ID of "spiffe://foo".
	if regType != common.RegistrationEntryType_WORKLOAD {
		return nil
	}

	childEntriesResp, err := listByParentID(ctx, spiffeID, ds, l)
	if err != nil {
		return status.Errorf(codes.Internal, "error looking up children entries: %v", err)
	}

	if len(childEntriesResp.Entries) > 0 {
		l.Error("Workload registration cannot be a parent of other existing workload registrations")
		return status.Errorf(codes.InvalidArgument, "workload registration cannot be a parent of other existing workload registrations")
	}

	return nil
}
