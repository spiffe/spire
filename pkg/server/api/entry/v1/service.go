package entry

import (
	"context"
	"errors"
	"io"
	"slices"
	"sort"
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

const defaultEntryPageSize = 500

// Config defines the service configuration.
type Config struct {
	TrustDomain   spiffeid.TrustDomain
	EntryFetcher  api.AuthorizedEntryFetcher
	DataStore     datastore.DataStore
	EntryPageSize int
}

// Service defines the v1 entry service.
type Service struct {
	entryv1.UnsafeEntryServer

	td            spiffeid.TrustDomain
	ds            datastore.DataStore
	ef            api.AuthorizedEntryFetcher
	entryPageSize int
}

// New creates a new v1 entry service.
func New(config Config) *Service {
	if config.EntryPageSize == 0 {
		config.EntryPageSize = defaultEntryPageSize
	}
	return &Service{
		td:            config.TrustDomain,
		ds:            config.DataStore,
		ef:            config.EntryFetcher,
		entryPageSize: config.EntryPageSize,
	}
}

// RegisterService registers the entry service on the gRPC server.
func RegisterService(s grpc.ServiceRegistrar, service *Service) {
	entryv1.RegisterEntryServer(s, service)
}

// CountEntries returns the total number of entries.
func (s *Service) CountEntries(ctx context.Context, req *entryv1.CountEntriesRequest) (*entryv1.CountEntriesResponse, error) {
	log := rpccontext.Logger(ctx)
	countReq := &datastore.CountRegistrationEntriesRequest{}

	if req.Filter != nil {
		rpccontext.AddRPCAuditFields(ctx, fieldsFromCountEntryFilter(ctx, s.td, req.Filter))
		if req.Filter.ByHint != nil {
			countReq.ByHint = req.Filter.ByHint.GetValue()
		}

		if req.Filter.ByParentId != nil {
			parentID, err := api.TrustDomainMemberIDFromProto(ctx, s.td, req.Filter.ByParentId)
			if err != nil {
				return nil, api.MakeErr(log, codes.InvalidArgument, "malformed parent ID filter", err)
			}
			countReq.ByParentID = parentID.String()
		}

		if req.Filter.BySpiffeId != nil {
			spiffeID, err := api.TrustDomainWorkloadIDFromProto(ctx, s.td, req.Filter.BySpiffeId)
			if err != nil {
				return nil, api.MakeErr(log, codes.InvalidArgument, "malformed SPIFFE ID filter", err)
			}
			countReq.BySpiffeID = spiffeID.String()
		}

		if req.Filter.BySelectors != nil {
			dsSelectors, err := api.SelectorsFromProto(req.Filter.BySelectors.Selectors)
			if err != nil {
				return nil, api.MakeErr(log, codes.InvalidArgument, "malformed selectors filter", err)
			}
			if len(dsSelectors) == 0 {
				return nil, api.MakeErr(log, codes.InvalidArgument, "malformed selectors filter", errors.New("empty selector set"))
			}
			countReq.BySelectors = &datastore.BySelectors{
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
			countReq.ByFederatesWith = &datastore.ByFederatesWith{
				Match:        datastore.MatchBehavior(req.Filter.ByFederatesWith.Match),
				TrustDomains: trustDomains,
			}
		}

		if req.Filter.ByDownstream != nil {
			countReq.ByDownstream = &req.Filter.ByDownstream.Value
		}
	}

	count, err := s.ds.CountRegistrationEntries(ctx, countReq)
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

		if req.Filter.ByDownstream != nil {
			listReq.ByDownstream = &req.Filter.ByDownstream.Value
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
		statusCode := status.Code(err)
		if statusCode == codes.Unknown {
			statusCode = codes.Internal
		}
		return &entryv1.BatchCreateEntryResponse_Result{
			Status: api.MakeStatus(log, statusCode, "failed to create entry", err),
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

// SyncAuthorizedEntries returns the list of entries authorized for the caller ID in the context.
func (s *Service) SyncAuthorizedEntries(stream entryv1.Entry_SyncAuthorizedEntriesServer) (err error) {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	// Emit "success" auditing if we succeed.
	defer func() {
		if err == nil {
			rpccontext.AuditRPC(ctx)
		}
	}()

	entries, err := s.fetchEntries(ctx, log)
	if err != nil {
		return err
	}

	return SyncAuthorizedEntries(stream, entries, s.entryPageSize)
}

func SyncAuthorizedEntries(stream entryv1.Entry_SyncAuthorizedEntriesServer, entries []*types.Entry, entryPageSize int) (err error) {
	// Receive the initial request with the output mask.
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	// There is no reason we couldn't support filtering by ID on the initial
	// response but there doesn't seem to be a reason to. For now, fail if
	// the initial request has IDs set.
	if len(req.Ids) > 0 {
		return status.Error(codes.InvalidArgument, "specifying IDs on initial request is not supported")
	}

	// The revision number should probably have never been included in the
	// entry mask. In any case, it is required to allow the caller to determine
	// if it needs to ask for the full entry, so disallow masking here.
	if req.OutputMask != nil && !req.OutputMask.RevisionNumber {
		return status.Error(codes.InvalidArgument, "revision number cannot be masked")
	}

	// Apply output mask to entries. The output mask field will be
	// intentionally ignored on subsequent requests.
	for i, entry := range entries {
		applyMask(entry, req.OutputMask)
		entries[i] = entry
	}

	// If the number of entries is less than or equal to the entry page size,
	// then just send the full list back. Otherwise, we'll send a sparse list
	// and then stream back full entries as requested.
	if len(entries) <= entryPageSize {
		return stream.Send(&entryv1.SyncAuthorizedEntriesResponse{
			Entries: entries,
		})
	}

	// Prepopulate the entry page used in the response with empty entry structs.
	// These will be reused for each sparse entry response.
	entryRevisions := make([]*entryv1.EntryRevision, entryPageSize)
	for i := range entryRevisions {
		entryRevisions[i] = &entryv1.EntryRevision{}
	}
	for i := 0; i < len(entries); {
		more := false
		n := len(entries) - i
		if n > entryPageSize {
			n = entryPageSize
			more = true
		}
		for j, entry := range entries[i : i+n] {
			entryRevisions[j].Id = entry.Id
			entryRevisions[j].RevisionNumber = entry.RevisionNumber
		}

		if err := stream.Send(&entryv1.SyncAuthorizedEntriesResponse{
			EntryRevisions: entryRevisions[:n],
			More:           more,
		}); err != nil {
			return err
		}
		i += n
	}

	// Now wait for the client to request IDs that they need the full copy of.
	// Each request is treated independently. Entries are paged back fully
	// before the next request is received, using the More field as a flag to
	// signal to the caller when all requested entries have been streamed back.
	resp := &entryv1.SyncAuthorizedEntriesResponse{}
	entriesSorted := false
	for {
		req, err := stream.Recv()
		if err != nil {
			// EOF is normal and happens when the server processes the
			// CloseSend sent by the client. If the client closes the stream
			// before that point, then Canceled is expected. Either way, these
			// conditions are normal and not an error.
			if errors.Is(err, io.EOF) || status.Code(err) == codes.Canceled {
				return nil
			}
			return err
		}

		if !entriesSorted {
			// Sort the entries by ID for efficient lookups. This is done
			// lazily since we only need these lookups if full copies are
			// being requested.
			sortEntriesByID(entries)
			entriesSorted = true
		}

		// Sort the requested IDs for efficient lookups into the sorted entry
		// list. Agents SHOULD already send the list sorted, but we need to
		// make sure they are sorted for correctness of the search loop below.
		// The go stdlib sorting algorithm performs well on pre-sorted data.
		slices.Sort(req.Ids)

		// Page back the requested entries. The slice for the entries in the response
		// is reused to reduce memory pressure. Since both the entries and
		// requested IDs are sorted, we can reduce the amount of entries we
		// need to search as we iteratively move through the requested IDs.
		resp.Entries = resp.Entries[:0]
		entriesToSearch := entries
		for _, id := range req.Ids {
			i, found := sort.Find(len(entriesToSearch), func(i int) int {
				return strings.Compare(id, entriesToSearch[i].Id)
			})
			if found {
				if len(resp.Entries) == entryPageSize {
					// Adding the entry just found will exceed our page size.
					// Ship the pageful of entries first and signal that there
					// is more to follow.
					resp.More = true
					if err := stream.Send(resp); err != nil {
						return err
					}
					resp.Entries = resp.Entries[:0]
				}
				resp.Entries = append(resp.Entries, entriesToSearch[i])
			}
			entriesToSearch = entriesToSearch[i:]
			if len(entriesToSearch) == 0 {
				break
			}
		}
		// The response is either empty or contains a partial page. Either way
		// we need to send what we have and signal there is no more to follow.
		resp.More = false
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
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
		statusCode := status.Code(err)
		if statusCode == codes.Unknown {
			statusCode = codes.Internal
		}
		return &entryv1.BatchUpdateEntryResponse_Result{
			Status: api.MakeStatus(log, statusCode, "failed to update entry", err),
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

	if filter.ByDownstream != nil {
		fields[telemetry.Downstream] = &filter.ByDownstream.Value
	}

	return fields
}

func fieldsFromCountEntryFilter(ctx context.Context, td spiffeid.TrustDomain, filter *entryv1.CountEntriesRequest_Filter) logrus.Fields {
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

	if filter.ByDownstream != nil {
		fields[telemetry.Downstream] = &filter.ByDownstream.Value
	}

	return fields
}

func sortEntriesByID(entries []*types.Entry) {
	sort.Slice(entries, func(a, b int) bool {
		return entries[a].Id < entries[b].Id
	})
}
