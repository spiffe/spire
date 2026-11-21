package sqlstorev2

import (
	"context"
	"time"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errNotImplemented is returned by the datastore.DataStore methods this
// datastore does not implement.
var errNotImplemented = status.Error(codes.Unimplemented, "datastore-sql: not implemented")

func (ds *Plugin) CountRegistrationEntries(_ context.Context, _ *datastore.CountRegistrationEntriesRequest) (int32, error) {
	return 0, errNotImplemented
}

func (ds *Plugin) CreateRegistrationEntry(_ context.Context, _ *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) CreateOrReturnRegistrationEntry(_ context.Context, _ *common.RegistrationEntry) (*common.RegistrationEntry, bool, error) {
	return nil, false, errNotImplemented
}

func (ds *Plugin) DeleteRegistrationEntry(_ context.Context, _ string) (*common.RegistrationEntry, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) FetchRegistrationEntries(_ context.Context, _ []string) (map[string]*common.RegistrationEntry, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) ListRegistrationEntries(_ context.Context, _ *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) PruneRegistrationEntries(_ context.Context, _ time.Time) error {
	return errNotImplemented
}

func (ds *Plugin) UpdateRegistrationEntry(_ context.Context, _ *common.RegistrationEntry, _ *common.RegistrationEntryMask) (*common.RegistrationEntry, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) ListRegistrationEntryEvents(_ context.Context, _ *datastore.ListRegistrationEntryEventsRequest) (*datastore.ListRegistrationEntryEventsResponse, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) PruneRegistrationEntryEvents(_ context.Context, _ time.Duration) error {
	return errNotImplemented
}

func (ds *Plugin) FetchRegistrationEntryEvent(_ context.Context, _ uint) (*datastore.RegistrationEntryEvent, error) {
	return nil, errNotImplemented
}
