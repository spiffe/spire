package entry

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire-next/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterService registers the entry service on the gRPC server.
func RegisterService(s *grpc.Server, service *Service) {
	entry.RegisterEntryServer(s, service)
}

// Config is the service configuration
type Config struct {
	EntryFetcher api.AuthorizedEntryFetcher
	DataStore    datastore.DataStore
}

// New creates a new entry service
func New(config Config) *Service {
	return &Service{
		ds: config.DataStore,
		ef: config.EntryFetcher,
	}
}

// Service implements the v1 entry service
type Service struct {
	ds datastore.DataStore
	ef api.AuthorizedEntryFetcher
}

func (s *Service) ListEntries(ctx context.Context, req *entry.ListEntriesRequest) (*entry.ListEntriesResponse, error) {
	log := rpccontext.Logger(ctx)

	listReq, err := buildListEntriesRequest(req)
	if err != nil {
		log.WithError(err).Error("Invalid request")
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	dsResp, err := s.ds.ListRegistrationEntries(ctx, listReq)
	if err != nil {
		log.WithError(err).Error("Failed to list entries")
		return nil, status.Errorf(codes.Internal, "failed to list entries: %v", err)
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

func (s *Service) GetEntry(ctx context.Context, req *entry.GetEntryRequest) (*types.Entry, error) {
	log := rpccontext.Logger(ctx)

	if req.Id == "" {
		log.Error("Invalid request: missing ID")
		return nil, status.Error(codes.InvalidArgument, "missing ID")
	}
	log = log.WithField(telemetry.RegistrationID, req.Id)
	dsResp, err := s.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{
		EntryId: req.Id,
	})
	if err != nil {
		log.WithError(err).Error("Failed to fetch entry")
		return nil, status.Errorf(codes.Internal, "failed to fetch entry: %v", err)
	}

	if dsResp.Entry == nil {
		log.Error("Entry not found")
		return nil, status.Error(codes.NotFound, "entry not found")
	}

	entry, err := api.RegistrationEntryToProto(dsResp.Entry)
	if err != nil {
		log.WithError(err).Error("Failed to convert entry")
		return nil, status.Errorf(codes.Internal, "failed to convert entry: %v", err)
	}
	applyMask(entry, req.OutputMask)

	return entry, nil
}

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

	cEntry, err := api.ProtoToRegistrationEntry(e)
	if err != nil {
		log.WithError(err).Error("Invalid request: failed to convert entry")
		return &entry.BatchCreateEntryResponse_Result{
			Status: api.CreateStatus(codes.InvalidArgument, "failed to convert entry: %v", err),
		}
	}

	log = log.WithField(telemetry.SPIFFEID, cEntry.SpiffeId)

	// Validates that there is no similar entry
	if isUniqueStatus := s.isEntryUnique(ctx, cEntry); isUniqueStatus != nil {
		return &entry.BatchCreateEntryResponse_Result{
			Status: isUniqueStatus,
		}
	}

	// Create entry
	resp, err := s.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
		Entry: cEntry,
	})
	if err != nil {
		log.WithError(err).Error("Failed to create entry")
		return &entry.BatchCreateEntryResponse_Result{
			Status: api.CreateStatus(codes.Internal, "failed to create entry: %v", err),
		}
	}

	tEntry, err := api.RegistrationEntryToProto(resp.Entry)
	if err != nil {
		log.WithError(err).Error("Unable to convert registration entry")
		return &entry.BatchCreateEntryResponse_Result{
			Status: api.CreateStatus(codes.Internal, "unable to convert registration entry: %v", err),
		}
	}

	applyMask(tEntry, outputMask)

	return &entry.BatchCreateEntryResponse_Result{
		Status: api.OK(),
		Entry:  tEntry,
	}
}

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
		log.Error("Invalid request: missing entry ID")
		return &entry.BatchDeleteEntryResponse_Result{
			Id:     id,
			Status: api.CreateStatus(codes.InvalidArgument, "missing entry ID"),
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
			Status: api.CreateStatus(codes.NotFound, "entry not found"),
		}
	default:
		log.WithError(err).Error("Failed to delete entry")
		return &entry.BatchDeleteEntryResponse_Result{
			Id:     id,
			Status: api.CreateStatus(codes.Internal, "failed to delete entry: %v", err),
		}
	}
}

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
		log.Error("Caller ID missing from request context")
		return nil, status.Error(codes.Internal, "caller ID missing from request context")
	}

	entries, err := s.ef.FetchAuthorizedEntries(ctx, callerID)
	if err != nil {
		log.WithError(err).Error("Failed to fetch registration entries")
		return nil, status.Error(codes.Internal, "failed to fetch registration entries")
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
}

func buildListEntriesRequest(req *entry.ListEntriesRequest) (*datastore.ListRegistrationEntriesRequest, error) {
	listReq := &datastore.ListRegistrationEntriesRequest{}

	if req.PageSize > 0 {
		listReq.Pagination = &datastore.Pagination{
			PageSize: req.PageSize,
			Token:    req.PageToken,
		}
	}

	if req.Filter != nil {
		if req.Filter.ByParentId != nil {
			var err error
			listReq.ByParentId, err = api.StringValueFromSPIFFEID(req.Filter.ByParentId)
			if err != nil {
				return nil, fmt.Errorf("malformed ByParentId: %v", err)
			}
		}

		if req.Filter.BySpiffeId != nil {
			var err error
			listReq.BySpiffeId, err = api.StringValueFromSPIFFEID(req.Filter.BySpiffeId)
			if err != nil {
				return nil, fmt.Errorf("malformed BySpiffeId: %v", err)
			}
		}

		if req.Filter.BySelectors != nil {
			dsSelectors, err := api.SelectorsFromProto(req.Filter.BySelectors.Selectors)
			if err != nil {
				return nil, fmt.Errorf("malformed BySelectors: %v", err)
			}
			if len(dsSelectors) == 0 {
				return nil, fmt.Errorf("malformed BySelectors: empty selector set")
			}
			listReq.BySelectors = &datastore.BySelectors{
				Match:     datastore.BySelectors_MatchBehavior(req.Filter.BySelectors.Match),
				Selectors: dsSelectors,
			}
		}
	}

	return listReq, nil
}

func (s *Service) isEntryUnique(ctx context.Context, e *common.RegistrationEntry) *types.Status {
	resp, err := s.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		BySpiffeId: &wrappers.StringValue{
			Value: e.SpiffeId,
		},
		ByParentId: &wrappers.StringValue{
			Value: e.ParentId,
		},
		BySelectors: &datastore.BySelectors{
			Match:     datastore.BySelectors_MATCH_EXACT,
			Selectors: e.Selectors,
		},
	})
	if err != nil {
		return api.CreateStatus(codes.Internal, "failed to list entries: %v", err)
	}
	if len(resp.Entries) != 0 {
		return api.CreateStatus(codes.AlreadyExists, "entry already exists")
	}

	return nil
}

func (s *Service) updateEntry(ctx context.Context, e *types.Entry, inputMask *types.EntryMask, outputMask *types.EntryMask) *entry.BatchUpdateEntryResponse_Result {
	log := rpccontext.Logger(ctx)
	log = log.WithField(telemetry.RegistrationID, e.Id)

	convEntry, err := api.ProtoToRegistrationEntryWithMask(e, inputMask)
	if err != nil {
		log.WithError(err).Error("Failed to convert entry")
		return &entry.BatchUpdateEntryResponse_Result{
			Status: api.CreateStatus(codes.InvalidArgument, "failed to convert entry: %v", err),
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
		log.WithError(err).Error("failed to update entry")
		return &entry.BatchUpdateEntryResponse_Result{
			Status: api.CreateStatus(codes.Internal, "failed to update entry: %v", err),
		}
	}

	tEntry, err := api.RegistrationEntryToProto(resp.Entry)
	if err != nil {
		log.WithError(err).Error("unable to convert registration entry to proto")
		return &entry.BatchUpdateEntryResponse_Result{
			Status: api.CreateStatus(codes.Internal, "unable to convert registration entry in updateEntry: %v", err),
		}
	}

	applyMask(tEntry, outputMask)

	return &entry.BatchUpdateEntryResponse_Result{
		Status: api.OK(),
		Entry:  tEntry,
	}
}
