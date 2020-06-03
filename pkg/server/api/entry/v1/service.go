package entry

import (
	"context"

	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire-next/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
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
	Datastore datastore.DataStore
}

// New creates a new entry service
func New(config Config) *Service {
	return &Service{
		ds: config.Datastore,
	}
}

// Service implements the v1 entry service
type Service struct {
	ds datastore.DataStore
}

func (s *Service) ListEntries(ctx context.Context, req *entry.ListEntriesRequest) (*entry.ListEntriesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method ListEntries not implemented")
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
	return nil, status.Error(codes.Unimplemented, "method BatchCreateEntry not implemented")
}

func (s *Service) BatchUpdateEntry(ctx context.Context, req *entry.BatchUpdateEntryRequest) (*entry.BatchUpdateEntryResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method BatchUpdateEntry not implemented")
}

func (s *Service) BatchDeleteEntry(ctx context.Context, req *entry.BatchDeleteEntryRequest) (*entry.BatchDeleteEntryResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method BatchDeleteEntry not implemented")
}

func (s *Service) GetAuthorizedEntries(ctx context.Context, req *entry.GetAuthorizedEntriesRequest) (*entry.GetAuthorizedEntriesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method GetAuthorizedEntries not implemented")
}

func applyMask(e *types.Entry, mask *types.EntryMask) { //nolint: unused,deadcode
	if mask == nil {
		return
	}

	if !mask.Id {
		e.Id = ""
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
