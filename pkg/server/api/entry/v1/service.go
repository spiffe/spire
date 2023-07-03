package entry

import (
	"context"
	"errors"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Config defines the service configuration.
type Config struct {
	TrustDomain  spiffeid.TrustDomain
	EntryFetcher api.AuthorizedEntryFetcher
	DataStore    datastore.DataStore
}

// Service defines the v1 entry service.
type Service struct {
	entryv1.UnsafeEntryServer

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
	entryv1.RegisterEntryServer(s, service)
}

// CountEntries returns the total number of entries.
func (s *Service) CountEntries(ctx context.Context, _ *entryv1.CountEntriesRequest) (*entryv1.CountEntriesResponse, error) {
	count, err := s.ds.CountRegistrationEntries(ctx)
	if err != nil {
		log := rpccontext.Logger(ctx)
		return nil, api.MakeErr(log, codes.Internal, "failed to count entries", err)
	}
	rpccontext.AuditRPC(ctx)

	return &entryv1.CountEntriesResponse{Count: count}, nil
}

// ListEntries returns the optionally filtered and/or paginated list of entries.
func (s *Service) ListEntries(ctx context.Context, req *entryv1.ListEntriesRequest) (*entryv1.ListEntriesResponse, error) {
	log := rpccontext.Logger(ctx)

	listReq := &datastore.ListRegistrationEntriesRequest{}

	if req.PageSize > 0 {
		listReq.Pagination = &datastore.Pagination{
			PageSize: req.PageSize,
			Token:    req.PageToken,
		}
	}

	if req.Filter != nil {
		rpccontext.AddRPCAuditFields(ctx, fieldsFromListEntryFilter(ctx, s.td, req.Filter))

		if req.Filter.ByHint != nil {
			listReq.ByHint = req.Filter.ByHint.GetValue()
		}

		if req.Filter.ByParentId != nil {
			parentID, err := api.TrustDomainMemberIDFromProto(ctx, s.td, req.Filter.ByParentId)
			if err != nil {
				return nil, api.MakeErr(log, codes.InvalidArgument, "malformed parent ID filter", err)
			}
			listReq.ByParentID = parentID.String()
		}

		if req.Filter.BySpiffeId != nil {
			spiffeID, err := api.TrustDomainWorkloadIDFromProto(ctx, s.td, req.Filter.BySpiffeId)
			if err != nil {
				return nil, api.MakeErr(log, codes.InvalidArgument, "malformed SPIFFE ID filter", err)
			}
			listReq.BySpiffeID = spiffeID.String()
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
				Match:     datastore.MatchBehavior(req.Filter.BySelectors.Match),
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
				Match:        datastore.MatchBehavior(req.Filter.ByFederatesWith.Match),
				TrustDomains: trustDomains,
			}
		}
	}

	dsResp, err := s.ds.ListRegistrationEntries(ctx, listReq)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to list entries", err)
	}

	resp := &entryv1.ListEntriesResponse{}
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
	rpccontext.AuditRPC(ctx)

	return resp, nil
}

// GetEntry returns the registration entry associated with the given SpiffeID
func (s *Service) GetEntry(ctx context.Context, req *entryv1.GetEntryRequest) (*types.Entry, error) {
	log := rpccontext.Logger(ctx)

	if req.Id == "" {
		return nil, api.MakeErr(log, codes.InvalidArgument, "missing ID", nil)
	}
	rpccontext.AddRPCAuditFields(ctx, logrus.Fields{telemetry.RegistrationID: req.Id})
	log = log.WithField(telemetry.RegistrationID, req.Id)
	registrationEntry, err := s.ds.FetchRegistrationEntry(ctx, req.Id)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to fetch entry", err)
	}

	if registrationEntry == nil {
		return nil, api.MakeErr(log, codes.NotFound, "entry not found", nil)
	}

	entry, err := api.RegistrationEntryToProto(registrationEntry)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to convert entry", err)
	}
	applyMask(entry, req.OutputMask)
	rpccontext.AuditRPC(ctx)

	return entry, nil
}

// BatchCreateEntry adds one or more entries to the server.
func (s *Service) BatchCreateEntry(ctx context.Context, req *entryv1.BatchCreateEntryRequest) (*entryv1.BatchCreateEntryResponse, error) {
	var results []*entryv1.BatchCreateEntryResponse_Result
	for _, eachEntry := range req.Entries {
		r := s.createEntry(ctx, eachEntry, req.OutputMask)
		results = append(results, r)
		rpccontext.AuditRPCWithTypesStatus(ctx, r.Status, func() logrus.Fields {
			return fieldsFromEntryProto(ctx, eachEntry, nil)
		})
	}

	return &entryv1.BatchCreateEntryResponse{
		Results: results,
	}, nil
}

func (s *Service) createEntry(ctx context.Context, e *types.Entry, outputMask *types.EntryMask) *entryv1.BatchCreateEntryResponse_Result {
	log := rpccontext.Logger(ctx)

	cEntry, err := api.ProtoToRegistrationEntry(ctx, s.td, e)
	if err != nil {
		return &entryv1.BatchCreateEntryResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "failed to convert entry", err),
		}
	}

	log = log.WithField(telemetry.SPIFFEID, cEntry.SpiffeId)

	resultStatus := api.OK()
	regEntry, existing, err := s.ds.CreateOrReturnRegistrationEntry(ctx, cEntry)
	switch {
	case err != nil:
		return &entryv1.BatchCreateEntryResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "failed to create entry", err),
		}
	case existing:
		resultStatus = api.CreateStatus(codes.AlreadyExists, "similar entry already exists")
	}

	tEntry, err := api.RegistrationEntryToProto(regEntry)
	if err != nil {
		return &entryv1.BatchCreateEntryResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "failed to convert entry", err),
		}
	}

	applyMask(tEntry, outputMask)

	return &entryv1.BatchCreateEntryResponse_Result{
		Status: resultStatus,
		Entry:  tEntry,
	}
}

// BatchUpdateEntry updates one or more entries in the server.
func (s *Service) BatchUpdateEntry(ctx context.Context, req *entryv1.BatchUpdateEntryRequest) (*entryv1.BatchUpdateEntryResponse, error) {
	var results []*entryv1.BatchUpdateEntryResponse_Result

	for _, eachEntry := range req.Entries {
		e := s.updateEntry(ctx, eachEntry, req.InputMask, req.OutputMask)
		results = append(results, e)
		rpccontext.AuditRPCWithTypesStatus(ctx, e.Status, func() logrus.Fields {
			return fieldsFromEntryProto(ctx, eachEntry, req.InputMask)
		})
	}

	return &entryv1.BatchUpdateEntryResponse{
		Results: results,
	}, nil
}

// BatchDeleteEntry removes one or more entries from the server.
func (s *Service) BatchDeleteEntry(ctx context.Context, req *entryv1.BatchDeleteEntryRequest) (*entryv1.BatchDeleteEntryResponse, error) {
	var results []*entryv1.BatchDeleteEntryResponse_Result
	for _, id := range req.Ids {
		r := s.deleteEntry(ctx, id)
		results = append(results, r)
		rpccontext.AuditRPCWithTypesStatus(ctx, r.Status, func() logrus.Fields {
			return logrus.Fields{telemetry.RegistrationID: id}
		})
	}

	return &entryv1.BatchDeleteEntryResponse{
		Results: results,
	}, nil
}

func (s *Service) deleteEntry(ctx context.Context, id string) *entryv1.BatchDeleteEntryResponse_Result {
	log := rpccontext.Logger(ctx)

	if id == "" {
		return &entryv1.BatchDeleteEntryResponse_Result{
			Id:     id,
			Status: api.MakeStatus(log, codes.InvalidArgument, "missing entry ID", nil),
		}
	}

	log = log.WithField(telemetry.RegistrationID, id)

	_, err := s.ds.DeleteRegistrationEntry(ctx, id)
	switch status.Code(err) {
	case codes.OK:
		return &entryv1.BatchDeleteEntryResponse_Result{
			Id:     id,
			Status: api.OK(),
		}
	case codes.NotFound:
		return &entryv1.BatchDeleteEntryResponse_Result{
			Id:     id,
			Status: api.MakeStatus(log, codes.NotFound, "entry not found", nil),
		}
	default:
		return &entryv1.BatchDeleteEntryResponse_Result{
			Id:     id,
			Status: api.MakeStatus(log, codes.Internal, "failed to delete entry", err),
		}
	}
}

// GetAuthorizedEntries returns the list of entries authorized for the caller ID in the context.
func (s *Service) GetAuthorizedEntries(ctx context.Context, req *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
	log := rpccontext.Logger(ctx)

	entries, err := s.fetchEntries(ctx, log)
	if err != nil {
		return nil, err
	}
	for i, entry := range entries {
		applyMask(entry, req.OutputMask)
		entries[i] = entry
	}

	resp := &entryv1.GetAuthorizedEntriesResponse{
		Entries: entries,
	}
	rpccontext.AuditRPC(ctx)

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

	if !mask.StoreSvid {
		e.StoreSvid = false
	}

	if !mask.X509SvidTtl {
		e.X509SvidTtl = 0
	}

	if !mask.JwtSvidTtl {
		e.JwtSvidTtl = 0
	}

	if !mask.Hint {
		e.Hint = ""
	}

	if !mask.CreatedAt {
		e.CreatedAt = 0
	}
}

func (s *Service) updateEntry(ctx context.Context, e *types.Entry, inputMask *types.EntryMask, outputMask *types.EntryMask) *entryv1.BatchUpdateEntryResponse_Result {
	log := rpccontext.Logger(ctx)
	log = log.WithField(telemetry.RegistrationID, e.Id)

	convEntry, err := api.ProtoToRegistrationEntryWithMask(ctx, s.td, e, inputMask)
	if err != nil {
		return &entryv1.BatchUpdateEntryResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "failed to convert entry", err),
		}
	}

	var mask *common.RegistrationEntryMask
	if inputMask != nil {
		mask = &common.RegistrationEntryMask{
			SpiffeId:      inputMask.SpiffeId,
			ParentId:      inputMask.ParentId,
			FederatesWith: inputMask.FederatesWith,
			Admin:         inputMask.Admin,
			Downstream:    inputMask.Downstream,
			EntryExpiry:   inputMask.ExpiresAt,
			DnsNames:      inputMask.DnsNames,
			Selectors:     inputMask.Selectors,
			StoreSvid:     inputMask.StoreSvid,
			X509SvidTtl:   inputMask.X509SvidTtl,
			JwtSvidTtl:    inputMask.JwtSvidTtl,
			Hint:          inputMask.Hint,
		}
	}
	dsEntry, err := s.ds.UpdateRegistrationEntry(ctx, convEntry, mask)
	if err != nil {
		return &entryv1.BatchUpdateEntryResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "failed to update entry", err),
		}
	}

	tEntry, err := api.RegistrationEntryToProto(dsEntry)
	if err != nil {
		return &entryv1.BatchUpdateEntryResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "failed to convert entry in updateEntry", err),
		}
	}

	applyMask(tEntry, outputMask)

	return &entryv1.BatchUpdateEntryResponse_Result{
		Status: api.OK(),
		Entry:  tEntry,
	}
}

func fieldsFromEntryProto(ctx context.Context, proto *types.Entry, inputMask *types.EntryMask) logrus.Fields {
	fields := logrus.Fields{}

	if proto == nil {
		return fields
	}

	if proto.Id != "" {
		fields[telemetry.RegistrationID] = proto.Id
	}

	if (inputMask == nil || inputMask.SpiffeId) && proto.SpiffeId != nil {
		id, err := api.IDFromProto(ctx, proto.SpiffeId)
		if err == nil {
			fields[telemetry.SPIFFEID] = id.String()
		}
	}

	if (inputMask == nil || inputMask.ParentId) && proto.ParentId != nil {
		id, err := api.IDFromProto(ctx, proto.ParentId)
		if err == nil {
			fields[telemetry.ParentID] = id.String()
		}
	}

	if inputMask == nil || inputMask.Selectors {
		if selectors := api.SelectorFieldFromProto(proto.Selectors); selectors != "" {
			fields[telemetry.Selectors] = selectors
		}
	}

	if inputMask == nil || inputMask.X509SvidTtl {
		fields[telemetry.X509SVIDTTL] = proto.X509SvidTtl
	}

	if inputMask == nil || inputMask.JwtSvidTtl {
		fields[telemetry.JWTSVIDTTL] = proto.JwtSvidTtl
	}

	if inputMask == nil || inputMask.FederatesWith {
		if federatesWith := strings.Join(proto.FederatesWith, ","); federatesWith != "" {
			fields[telemetry.FederatesWith] = federatesWith
		}
	}

	if inputMask == nil || inputMask.Admin {
		fields[telemetry.Admin] = proto.Admin
	}

	if inputMask == nil || inputMask.Downstream {
		fields[telemetry.Downstream] = proto.Downstream
	}

	if inputMask == nil || inputMask.ExpiresAt {
		fields[telemetry.ExpiresAt] = proto.ExpiresAt
	}

	if inputMask == nil || inputMask.DnsNames {
		if dnsNames := strings.Join(proto.DnsNames, ","); dnsNames != "" {
			fields[telemetry.DNSName] = dnsNames
		}
	}

	if inputMask == nil || inputMask.RevisionNumber {
		fields[telemetry.RevisionNumber] = proto.RevisionNumber
	}

	if inputMask == nil || inputMask.StoreSvid {
		fields[telemetry.StoreSvid] = proto.StoreSvid
	}

	if inputMask == nil || inputMask.Hint {
		fields[telemetry.Hint] = proto.Hint
	}

	if inputMask == nil || inputMask.CreatedAt {
		fields[telemetry.CreatedAt] = proto.CreatedAt
	}

	return fields
}

func fieldsFromListEntryFilter(ctx context.Context, td spiffeid.TrustDomain, filter *entryv1.ListEntriesRequest_Filter) logrus.Fields {
	fields := logrus.Fields{}

	if filter.ByHint != nil {
		fields[telemetry.Hint] = filter.ByHint.Value
	}

	if filter.ByParentId != nil {
		if parentID, err := api.TrustDomainMemberIDFromProto(ctx, td, filter.ByParentId); err == nil {
			fields[telemetry.ParentID] = parentID.String()
		}
	}

	if filter.BySpiffeId != nil {
		if id, err := api.TrustDomainWorkloadIDFromProto(ctx, td, filter.BySpiffeId); err == nil {
			fields[telemetry.SPIFFEID] = id.String()
		}
	}

	if filter.BySelectors != nil {
		fields[telemetry.BySelectorMatch] = filter.BySelectors.Match.String()
		fields[telemetry.BySelectors] = api.SelectorFieldFromProto(filter.BySelectors.Selectors)
	}

	if filter.ByFederatesWith != nil {
		fields[telemetry.FederatesWithMatch] = filter.ByFederatesWith.Match.String()
		fields[telemetry.FederatesWith] = strings.Join(filter.ByFederatesWith.TrustDomains, ",")
	}

	return fields
}
