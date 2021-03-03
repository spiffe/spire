package entry

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Config defines the service configuration.
type Config struct {
	TrustDomain  spiffeid.TrustDomain
	EntryFetcher api.AuthorizedEntryFetcher
	DataStore    datastore.DataStore
}

// Service defines the v1 entry service.
type Service struct {
	entry.UnsafeEntryServer

	td spiffeid.TrustDomain
	ds datastore.DataStore
	ef api.AuthorizedEntryFetcher
}

// New creates a new v1 entry service.
func New(config Config) *Service {
	return &Service{
		td: config.TrustDomain,
		ds: config.DataStore,
		ef: config.EntryFetcher,
	}
}

// RegisterService registers the entry service on the gRPC server.
func RegisterService(s *grpc.Server, service *Service) {
	entry.RegisterEntryServer(s, service)
}

// CountEntries returns the total number of entries.
func (s *Service) CountEntries(ctx context.Context, req *entry.CountEntriesRequest) (*entry.CountEntriesResponse, error) {
	dsResp, err := s.ds.CountRegistrationEntries(ctx, &datastore.CountRegistrationEntriesRequest{})
	if err != nil {
		log := rpccontext.Logger(ctx)
		return nil, api.MakeErr(log, codes.Internal, "failed to count entries", err)
	}

	return &entry.CountEntriesResponse{Count: dsResp.Entries}, nil
}

// ListEntries returns the optionally filtered and/or paginated list of entries.
func (s *Service) ListEntries(ctx context.Context, req *entry.ListEntriesRequest) (*entry.ListEntriesResponse, error) {
	log := rpccontext.Logger(ctx)

	listReq := &datastore.ListRegistrationEntriesRequest{}

	if req.PageSize > 0 {
		listReq.Pagination = &datastore.Pagination{
			PageSize: req.PageSize,
			Token:    req.PageToken,
		}
	}

	if req.Filter != nil {
		if req.Filter.ByParentId != nil {
			parentID, err := api.TrustDomainMemberIDFromProto(s.td, req.Filter.ByParentId)
			if err != nil {
				return nil, api.MakeErr(log, codes.InvalidArgument, "malformed parent ID filter", err)
			}
			listReq.ByParentId = &wrapperspb.StringValue{
				Value: parentID.String(),
			}
		}

		if req.Filter.BySpiffeId != nil {
			spiffeID, err := api.TrustDomainWorkloadIDFromProto(s.td, req.Filter.BySpiffeId)
			if err != nil {
				return nil, api.MakeErr(log, codes.InvalidArgument, "malformed SPIFFE ID filter", err)
			}
			listReq.BySpiffeId = &wrapperspb.StringValue{
				Value: spiffeID.String(),
			}
		}

		if req.Filter.BySelectors != nil {
			dsSelectors, err := api.SelectorsFromProto(req.Filter.BySelectors.Selectors)
			if err != nil {
				return nil, api.MakeErr(log, codes.InvalidArgument, "malformed selectors filter", err)
			}
			if len(dsSelectors) == 0 {
				return nil, api.MakeErr(log, codes.InvalidArgument, "malformed selectors filter", errors.New("empty selector set"))
			}
			listReq.BySelectors = &datastore.BySelectors{
				Match:     datastore.BySelectors_MatchBehavior(req.Filter.BySelectors.Match),
				Selectors: dsSelectors,
			}
		}

		if req.Filter.ByFederatesWith != nil {
			trustDomains := make([]string, 0, len(req.Filter.ByFederatesWith.TrustDomains))
			for _, tdStr := range req.Filter.ByFederatesWith.TrustDomains {
				td, err := spiffeid.TrustDomainFromString(tdStr)
				if err != nil {
					return nil, api.MakeErr(log, codes.InvalidArgument, "malformed federates with filter", err)
				}
				trustDomains = append(trustDomains, td.IDString())
			}
			if len(trustDomains) == 0 {
				return nil, api.MakeErr(log, codes.InvalidArgument, "malformed federates with filter", errors.New("empty trust domain set"))
			}
			listReq.ByFederatesWith = &datastore.ByFederatesWith{
				Match:        datastore.ByFederatesWith_MatchBehavior(req.Filter.ByFederatesWith.Match),
				TrustDomains: trustDomains,
			}
		}
	}

	dsResp, err := s.ds.ListRegistrationEntries(ctx, listReq)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to list entries", err)
	}

	resp := &entry.ListEntriesResponse{}
	if dsResp.Pagination != nil {
		resp.NextPageToken = dsResp.Pagination.Token
	}

	for _, regEntry := range dsResp.Entries {
		entry, err := api.RegistrationEntryToProto(regEntry)
		if err != nil {
			log.WithError(err).Errorf("Failed to convert entry: %q", regEntry.EntryId)
			continue
		}
		applyMask(entry, req.OutputMask)
		resp.Entries = append(resp.Entries, entry)
	}

	return resp, nil
}

// GetEntry returns the registration entry associated with the given SpiffeID
func (s *Service) GetEntry(ctx context.Context, req *entry.GetEntryRequest) (*types.Entry, error) {
	log := rpccontext.Logger(ctx)

	if req.Id == "" {
		return nil, api.MakeErr(log, codes.InvalidArgument, "missing ID", nil)
	}
	log = log.WithField(telemetry.RegistrationID, req.Id)
	dsResp, err := s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{
		EntryId: req.Id,
	})
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to fetch entry", err)
	}

	if dsResp.Entry == nil {
		return nil, api.MakeErr(log, codes.NotFound, "entry not found", nil)
	}

	entry, err := api.RegistrationEntryToProto(dsResp.Entry)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to convert entry", err)
	}
	applyMask(entry, req.OutputMask)

	return entry, nil
}

// BatchCreateEntry adds one or more entries to the server.
func (s *Service) BatchCreateEntry(ctx context.Context, req *entry.BatchCreateEntryRequest) (*entry.BatchCreateEntryResponse, error) {
	var results []*entry.BatchCreateEntryResponse_Result
	for _, eachEntry := range req.Entries {
		results = append(results, s.createEntry(ctx, eachEntry, req.OutputMask))
	}

	return &entry.BatchCreateEntryResponse{
		Results: results,
	}, nil
}

func (s *Service) createEntry(ctx context.Context, e *types.Entry, outputMask *types.EntryMask) *entry.BatchCreateEntryResponse_Result {
	log := rpccontext.Logger(ctx)

	cEntry, err := api.ProtoToRegistrationEntry(s.td, e)
	if err != nil {
		return &entry.BatchCreateEntryResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "failed to convert entry", err),
		}
	}

	log = log.WithField(telemetry.SPIFFEID, cEntry.SpiffeId)

	existingEntry, err := s.getExistingEntry(ctx, cEntry)
	if err != nil {
		return &entry.BatchCreateEntryResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "failed to list entries", err),
		}
	}

	resultStatus := api.OK()
	regEntry := existingEntry

	if existingEntry == nil {
		// Create entry
		resp, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
			Entry: cEntry,
		})
		if err != nil {
			return &entry.BatchCreateEntryResponse_Result{
				Status: api.MakeStatus(log, codes.Internal, "failed to create entry", err),
			}
		}
		regEntry = resp.Entry
	} else {
		resultStatus = api.CreateStatus(codes.AlreadyExists, "similar entry already exists")
	}

	tEntry, err := api.RegistrationEntryToProto(regEntry)
	if err != nil {
		return &entry.BatchCreateEntryResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "failed to convert entry", err),
		}
	}

	applyMask(tEntry, outputMask)

	return &entry.BatchCreateEntryResponse_Result{
		Status: resultStatus,
		Entry:  tEntry,
	}
}

// BatchUpdateEntry updates one or more entries in the server.
func (s *Service) BatchUpdateEntry(ctx context.Context, req *entry.BatchUpdateEntryRequest) (*entry.BatchUpdateEntryResponse, error) {
	var results []*entry.BatchUpdateEntryResponse_Result

	for _, eachEntry := range req.Entries {
		e := s.updateEntry(ctx, eachEntry, req.InputMask, req.OutputMask)
		results = append(results, e)
	}

	return &entry.BatchUpdateEntryResponse{
		Results: results,
	}, nil
}

// BatchDeleteEntry removes one or more entries from the server.
func (s *Service) BatchDeleteEntry(ctx context.Context, req *entry.BatchDeleteEntryRequest) (*entry.BatchDeleteEntryResponse, error) {
	var results []*entry.BatchDeleteEntryResponse_Result
	for _, id := range req.Ids {
		results = append(results, s.deleteEntry(ctx, id))
	}

	return &entry.BatchDeleteEntryResponse{
		Results: results,
	}, nil
}

func (s *Service) deleteEntry(ctx context.Context, id string) *entry.BatchDeleteEntryResponse_Result {
	log := rpccontext.Logger(ctx)

	if id == "" {
		return &entry.BatchDeleteEntryResponse_Result{
			Id:     id,
			Status: api.MakeStatus(log, codes.InvalidArgument, "missing entry ID", nil),
		}
	}

	log = log.WithField(telemetry.RegistrationID, id)

	_, err := s.ds.DeleteRegistrationEntry(ctx, &datastore.DeleteRegistrationEntryRequest{
		EntryId: id,
	})
	switch status.Code(err) {
	case codes.OK:
		return &entry.BatchDeleteEntryResponse_Result{
			Id:     id,
			Status: api.OK(),
		}
	case codes.NotFound:
		return &entry.BatchDeleteEntryResponse_Result{
			Id:     id,
			Status: api.MakeStatus(log, codes.NotFound, "entry not found", nil),
		}
	default:
		return &entry.BatchDeleteEntryResponse_Result{
			Id:     id,
			Status: api.MakeStatus(log, codes.Internal, "failed to delete entry", err),
		}
	}
}

// GetAuthorizedEntries returns the list of entries authorized for the caller ID in the context.
func (s *Service) GetAuthorizedEntries(ctx context.Context, req *entry.GetAuthorizedEntriesRequest) (*entry.GetAuthorizedEntriesResponse, error) {
	log := rpccontext.Logger(ctx)

	entries, err := s.fetchEntries(ctx, log)
	if err != nil {
		return nil, err
	}
	for i, entry := range entries {
		applyMask(entry, req.OutputMask)
		entries[i] = entry
	}

	resp := &entry.GetAuthorizedEntriesResponse{
		Entries: entries,
	}

	return resp, nil
}

// fetchEntries fetches authorized entries using caller ID from context
func (s *Service) fetchEntries(ctx context.Context, log logrus.FieldLogger) ([]*types.Entry, error) {
	callerID, ok := rpccontext.CallerID(ctx)
	if !ok {
		return nil, api.MakeErr(log, codes.Internal, "caller ID missing from request context", nil)
	}

	entries, err := s.ef.FetchAuthorizedEntries(ctx, callerID)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to fetch entries", err)
	}

	return entries, nil
}

func applyMask(e *types.Entry, mask *types.EntryMask) {
	if mask == nil {
		return
	}

	if !mask.SpiffeId {
		e.SpiffeId = nil
	}

	if !mask.ParentId {
		e.ParentId = nil
	}

	if !mask.Selectors {
		e.Selectors = nil
	}

	if !mask.Ttl {
		e.Ttl = 0
	}

	if !mask.FederatesWith {
		e.FederatesWith = nil
	}

	if !mask.Admin {
		e.Admin = false
	}

	if !mask.Downstream {
		e.Downstream = false
	}

	if !mask.ExpiresAt {
		e.ExpiresAt = 0
	}

	if !mask.DnsNames {
		e.DnsNames = nil
	}

	if !mask.RevisionNumber {
		e.RevisionNumber = 0
	}
}

func (s *Service) getExistingEntry(ctx context.Context, e *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	resp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		BySpiffeId: &wrapperspb.StringValue{
			Value: e.SpiffeId,
		},
		ByParentId: &wrapperspb.StringValue{
			Value: e.ParentId,
		},
		BySelectors: &datastore.BySelectors{
			Match:     datastore.BySelectors_MATCH_EXACT,
			Selectors: e.Selectors,
		},
	})

	if err != nil {
		return nil, err
	}

	if len(resp.Entries) > 0 {
		return resp.Entries[0], nil
	}
	return nil, nil
}

func (s *Service) updateEntry(ctx context.Context, e *types.Entry, inputMask *types.EntryMask, outputMask *types.EntryMask) *entry.BatchUpdateEntryResponse_Result {
	log := rpccontext.Logger(ctx)
	log = log.WithField(telemetry.RegistrationID, e.Id)

	convEntry, err := api.ProtoToRegistrationEntryWithMask(s.td, e, inputMask)
	if err != nil {
		return &entry.BatchUpdateEntryResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "failed to convert entry", err),
		}
	}

	var resp *datastore.UpdateRegistrationEntryResponse
	if inputMask != nil {
		resp, err = s.ds.UpdateRegistrationEntry(ctx, &datastore.UpdateRegistrationEntryRequest{
			Entry: convEntry,
			Mask: &common.RegistrationEntryMask{
				SpiffeId:      inputMask.SpiffeId,
				ParentId:      inputMask.ParentId,
				Ttl:           inputMask.Ttl,
				FederatesWith: inputMask.FederatesWith,
				Admin:         inputMask.Admin,
				Downstream:    inputMask.Downstream,
				EntryExpiry:   inputMask.ExpiresAt,
				DnsNames:      inputMask.DnsNames,
				Selectors:     inputMask.Selectors,
			}})
	} else {
		resp, err = s.ds.UpdateRegistrationEntry(ctx, &datastore.UpdateRegistrationEntryRequest{Entry: convEntry})
	}

	if err != nil {
		return &entry.BatchUpdateEntryResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "failed to update entry", err),
		}
	}

	tEntry, err := api.RegistrationEntryToProto(resp.Entry)
	if err != nil {
		return &entry.BatchUpdateEntryResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "failed to convert entry in updateEntry", err),
		}
	}

	applyMask(tEntry, outputMask)

	return &entry.BatchUpdateEntryResponse_Result{
		Status: api.OK(),
		Entry:  tEntry,
	}
}
