package sqlstorev2

import (
	"context"
	"time"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errNotImplemented is returned by the datastore.DataStore methods that have
// not been ported to this datastore yet.
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

func (ds *Plugin) CountAttestedNodes(_ context.Context, _ *datastore.CountAttestedNodesRequest) (int32, error) {
	return 0, errNotImplemented
}

func (ds *Plugin) CreateAttestedNode(_ context.Context, _ *common.AttestedNode) (*common.AttestedNode, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) DeleteAttestedNode(_ context.Context, _ string) (*common.AttestedNode, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) FetchAttestedNode(_ context.Context, _ string) (*common.AttestedNode, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) ListAttestedNodes(_ context.Context, _ *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) UpdateAttestedNode(_ context.Context, _ *common.AttestedNode, _ *common.AttestedNodeMask) (*common.AttestedNode, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) PruneAttestedExpiredNodes(_ context.Context, _ time.Time, _ bool, _ int) error {
	return errNotImplemented
}

func (ds *Plugin) ListAttestedNodeEvents(_ context.Context, _ *datastore.ListAttestedNodeEventsRequest) (*datastore.ListAttestedNodeEventsResponse, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) PruneAttestedNodeEvents(_ context.Context, _ time.Duration) error {
	return errNotImplemented
}

func (ds *Plugin) FetchAttestedNodeEvent(_ context.Context, _ uint) (*datastore.AttestedNodeEvent, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) GetNodeSelectors(_ context.Context, _ string, _ datastore.DataConsistency) ([]*common.Selector, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) ListNodeSelectors(_ context.Context, _ *datastore.ListNodeSelectorsRequest) (*datastore.ListNodeSelectorsResponse, error) {
	return nil, errNotImplemented
}

func (ds *Plugin) SetNodeSelectors(_ context.Context, _ string, _ []*common.Selector) error {
	return errNotImplemented
}
