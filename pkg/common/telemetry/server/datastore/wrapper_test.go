package datastore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestWithMetrics(t *testing.T) {
	m := fakemetrics.New()
	ds := &fakeDataStore{}
	w := WithMetrics(ds, m)

	// This map ensures that a unit-test is added for any additional
	// datastore methods that are added.
	methodNames := make(map[string]struct{})
	wv := reflect.ValueOf(w)
	wt := reflect.TypeOf(w)
	for i := range wt.NumMethod() {
		methodNames[wt.Method(i).Name] = struct{}{}
	}

	for _, tt := range []struct {
		key        string
		methodName string
	}{
		{
			key:        "datastore.bundle.append",
			methodName: "AppendBundle",
		},
		{
			key:        "datastore.node.count",
			methodName: "CountAttestedNodes",
		},
		{
			key:        "datastore.bundle.count",
			methodName: "CountBundles",
		},
		{
			key:        "datastore.registration_entry.count",
			methodName: "CountRegistrationEntries",
		},
		{
			key:        "datastore.node.create",
			methodName: "CreateAttestedNode",
		},
		{
			key:        "datastore.node_event.create",
			methodName: "CreateAttestedNodeEventForTesting",
		},
		{
			key:        "datastore.bundle.create",
			methodName: "CreateBundle",
		},
		{
			key:        "datastore.federation_relationship.create",
			methodName: "CreateFederationRelationship",
		},
		{
			key:        "datastore.join_token.create",
			methodName: "CreateJoinToken",
		},
		{
			key:        "datastore.registration_entry.create",
			methodName: "CreateRegistrationEntry",
		},
		{
			key:        "datastore.registration_entry.create",
			methodName: "CreateOrReturnRegistrationEntry",
		},
		{
			key:        "datastore.registration_entry_event.create",
			methodName: "CreateRegistrationEntryEventForTesting",
		},
		{
			key:        "datastore.node.delete",
			methodName: "DeleteAttestedNode",
		},
		{
			key:        "datastore.node_event.delete",
			methodName: "DeleteAttestedNodeEventForTesting",
		},
		{
			key:        "datastore.bundle.delete",
			methodName: "DeleteBundle",
		},
		{
			key:        "datastore.federation_relationship.delete",
			methodName: "DeleteFederationRelationship",
		},
		{
			key:        "datastore.join_token.delete",
			methodName: "DeleteJoinToken",
		},
		{
			key:        "datastore.registration_entry.delete",
			methodName: "DeleteRegistrationEntry",
		},
		{
			key:        "datastore.registration_entry_event.delete",
			methodName: "DeleteRegistrationEntryEventForTesting",
		},
		{
			key:        "datastore.node.fetch",
			methodName: "FetchAttestedNode",
		},
		{
			key:        "datastore.node_event.fetch",
			methodName: "FetchAttestedNodeEvent",
		},
		{
			key:        "datastore.bundle.fetch",
			methodName: "FetchBundle",
		},
		{
			key:        "datastore.join_token.fetch",
			methodName: "FetchJoinToken",
		},
		{
			key:        "datastore.registration_entry.fetch",
			methodName: "FetchRegistrationEntry",
		},
		{
			key:        "datastore.registration_entry.fetch",
			methodName: "FetchRegistrationEntries",
		},
		{
			key:        "datastore.registration_entry_event.fetch",
			methodName: "FetchRegistrationEntryEvent",
		},
		{
			key:        "datastore.federation_relationship.fetch",
			methodName: "FetchFederationRelationship",
		},
		{
			key:        "datastore.node.selectors.fetch",
			methodName: "GetNodeSelectors",
		},
		{
			key:        "datastore.node.list",
			methodName: "ListAttestedNodes",
		},
		{
			key:        "datastore.node_event.list",
			methodName: "ListAttestedNodeEvents",
		},
		{
			key:        "datastore.bundle.list",
			methodName: "ListBundles",
		},
		{
			key:        "datastore.node.selectors.list",
			methodName: "ListNodeSelectors",
		},
		{
			key:        "datastore.registration_entry.list",
			methodName: "ListRegistrationEntries",
		},
		{
			key:        "datastore.registration_entry_event.list",
			methodName: "ListRegistrationEntryEvents",
		},
		{
			key:        "datastore.federation_relationship.list",
			methodName: "ListFederationRelationships",
		},
		{
			key:        "datastore.node.prune",
			methodName: "PruneAttestedExpiredNodes",
		},
		{
			key:        "datastore.node_event.prune",
			methodName: "PruneAttestedNodeEvents",
		},
		{
			key:        "datastore.bundle.prune",
			methodName: "PruneBundle",
		},
		{
			key:        "datastore.join_token.prune",
			methodName: "PruneJoinTokens",
		},
		{
			key:        "datastore.registration_entry.prune",
			methodName: "PruneRegistrationEntries",
		},
		{
			key:        "datastore.registration_entry_event.prune",
			methodName: "PruneRegistrationEntryEvents",
		},
		{
			key:        "datastore.bundle.set",
			methodName: "SetBundle",
		},
		{
			key:        "datastore.bundle.x509.taint",
			methodName: "TaintX509CA",
		},
		{
			key:        "datastore.bundle.jwt.revoke",
			methodName: "RevokeJWTKey",
		},
		{
			key:        "datastore.bundle.x509.revoke",
			methodName: "RevokeX509CA",
		},
		{
			key:        "datastore.bundle.jwt.taint",
			methodName: "TaintJWTKey",
		},
		{
			key:        "datastore.node.selectors.set",
			methodName: "SetNodeSelectors",
		},
		{
			key:        "datastore.node.update",
			methodName: "UpdateAttestedNode",
		},
		{
			key:        "datastore.bundle.update",
			methodName: "UpdateBundle",
		},
		{
			key:        "datastore.federation_relationship.update",
			methodName: "UpdateFederationRelationship",
		},
		{
			key:        "datastore.registration_entry.update",
			methodName: "UpdateRegistrationEntry",
		},
		{
			key:        "datastore.ca_journal.set",
			methodName: "SetCAJournal",
		},
		{
			key:        "datastore.ca_journal.fetch",
			methodName: "FetchCAJournal",
		},
		{
			key:        "datastore.ca_journal.prune",
			methodName: "PruneCAJournals",
		},
		{
			key:        "datastore.ca_journal.list",
			methodName: "ListCAJournalsForTesting",
		},
	} {
		methodType, ok := wt.MethodByName(tt.methodName)
		require.True(t, ok, "method %q does not exist on DataStore interface", tt.methodName)
		methodValue := wv.Method(methodType.Index)

		// Record that the method was tested. Methods that aren't tested
		// will fail the test below.
		delete(methodNames, methodType.Name)

		doCall := func(err error) any {
			m.Reset()
			ds.SetError(err)
			numIn := methodValue.Type().NumIn()
			numOut := methodValue.Type().NumOut()
			args := []reflect.Value{reflect.ValueOf(context.Background())}
			for i := 1; i < numIn; i++ {
				args = append(args, reflect.New(methodValue.Type().In(i)).Elem())
			}
			out := methodValue.Call(args)
			require.Len(t, out, numOut)
			for i := range numOut - 1 {
				mv := methodValue.Type().Out(i)
				switch v := reflect.ValueOf(mv); v.Kind() {
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
					require.True(t, out[i].IsZero())
				default:
					require.NotNil(t, mv)
				}
			}
			return out[numOut-1].Interface()
		}

		expectedMetrics := func(code codes.Code) []fakemetrics.MetricItem {
			key := strings.Split(tt.key, ".")
			return []fakemetrics.MetricItem{
				{
					Type: fakemetrics.IncrCounterWithLabelsType,
					Key:  key,
					Labels: []telemetry.Label{
						{Name: "status", Value: code.String()},
					},
					Val: 1,
				},
				{
					Type: fakemetrics.MeasureSinceWithLabelsType,
					Key:  append(key, "elapsed_time"),
					Labels: []telemetry.Label{
						{Name: "status", Value: code.String()},
					},
				},
			}
		}

		t.Run(tt.key+"(success)", func(t *testing.T) {
			err := doCall(nil)
			assert.Nil(t, err, "error should be nil")
			assert.Equal(t, expectedMetrics(codes.OK), m.AllMetrics())
		})

		t.Run(tt.key+"(failure)", func(t *testing.T) {
			err := doCall(errors.New("ohno"))
			assert.NotNil(t, err, "error should be not nil")
			assert.Equal(t, expectedMetrics(codes.Unknown), m.AllMetrics())
		})
	}

	for methodName := range methodNames {
		t.Errorf("DataStore method %q was not tested", methodName)
	}
}

type fakeDataStore struct {
	err error
}

func (ds *fakeDataStore) SetError(err error) {
	ds.err = err
}

func (ds *fakeDataStore) AppendBundle(context.Context, *common.Bundle) (*common.Bundle, error) {
	return &common.Bundle{}, ds.err
}

func (ds *fakeDataStore) CountAttestedNodes(context.Context, *datastore.CountAttestedNodesRequest) (int32, error) {
	return 0, ds.err
}

func (ds *fakeDataStore) CountBundles(context.Context) (int32, error) {
	return 0, ds.err
}

func (ds *fakeDataStore) CountRegistrationEntries(context.Context, *datastore.CountRegistrationEntriesRequest) (int32, error) {
	return 0, ds.err
}

func (ds *fakeDataStore) CreateAttestedNode(context.Context, *common.AttestedNode) (*common.AttestedNode, error) {
	return &common.AttestedNode{}, ds.err
}

func (ds *fakeDataStore) CreateAttestedNodeEventForTesting(context.Context, *datastore.AttestedNodeEvent) error {
	return ds.err
}

func (ds *fakeDataStore) CreateBundle(context.Context, *common.Bundle) (*common.Bundle, error) {
	return &common.Bundle{}, ds.err
}

func (ds *fakeDataStore) CreateFederationRelationship(context.Context, *datastore.FederationRelationship) (*datastore.FederationRelationship, error) {
	return &datastore.FederationRelationship{}, ds.err
}

func (ds *fakeDataStore) ListFederationRelationships(context.Context, *datastore.ListFederationRelationshipsRequest) (*datastore.ListFederationRelationshipsResponse, error) {
	return &datastore.ListFederationRelationshipsResponse{}, ds.err
}

func (ds *fakeDataStore) CreateJoinToken(context.Context, *datastore.JoinToken) error {
	return ds.err
}

func (ds *fakeDataStore) CreateRegistrationEntry(context.Context, *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	return &common.RegistrationEntry{}, ds.err
}

func (ds *fakeDataStore) CreateOrReturnRegistrationEntry(context.Context, *common.RegistrationEntry) (*common.RegistrationEntry, bool, error) {
	return &common.RegistrationEntry{}, true, ds.err
}

func (ds *fakeDataStore) CreateRegistrationEntryEventForTesting(context.Context, *datastore.RegistrationEntryEvent) error {
	return ds.err
}

func (ds *fakeDataStore) DeleteAttestedNode(context.Context, string) (*common.AttestedNode, error) {
	return &common.AttestedNode{}, ds.err
}

func (ds *fakeDataStore) PruneAttestedExpiredNodes(context.Context, time.Time, bool) error {
	return ds.err
}

func (ds *fakeDataStore) DeleteAttestedNodeEventForTesting(context.Context, uint) error {
	return ds.err
}

func (ds *fakeDataStore) DeleteBundle(context.Context, string, datastore.DeleteMode) error {
	return ds.err
}

func (ds *fakeDataStore) DeleteFederationRelationship(context.Context, spiffeid.TrustDomain) error {
	return ds.err
}

func (ds *fakeDataStore) DeleteJoinToken(context.Context, string) error {
	return ds.err
}

func (ds *fakeDataStore) DeleteRegistrationEntry(context.Context, string) (*common.RegistrationEntry, error) {
	return &common.RegistrationEntry{}, ds.err
}

func (ds *fakeDataStore) DeleteRegistrationEntryEventForTesting(context.Context, uint) error {
	return ds.err
}

func (ds *fakeDataStore) FetchAttestedNode(context.Context, string) (*common.AttestedNode, error) {
	return &common.AttestedNode{}, ds.err
}

func (ds *fakeDataStore) FetchAttestedNodeEvent(context.Context, uint) (*datastore.AttestedNodeEvent, error) {
	return &datastore.AttestedNodeEvent{}, ds.err
}

func (ds *fakeDataStore) FetchBundle(context.Context, string) (*common.Bundle, error) {
	return &common.Bundle{}, ds.err
}

func (ds *fakeDataStore) FetchFederationRelationship(context.Context, spiffeid.TrustDomain) (*datastore.FederationRelationship, error) {
	return &datastore.FederationRelationship{}, ds.err
}

func (ds *fakeDataStore) FetchJoinToken(context.Context, string) (*datastore.JoinToken, error) {
	return &datastore.JoinToken{}, ds.err
}

func (ds *fakeDataStore) FetchRegistrationEntry(context.Context, string) (*common.RegistrationEntry, error) {
	return &common.RegistrationEntry{}, ds.err
}

func (ds *fakeDataStore) FetchRegistrationEntries(context.Context, []string) (map[string]*common.RegistrationEntry, error) {
	return map[string]*common.RegistrationEntry{}, ds.err
}

func (ds *fakeDataStore) FetchRegistrationEntryEvent(context.Context, uint) (*datastore.RegistrationEntryEvent, error) {
	return &datastore.RegistrationEntryEvent{}, ds.err
}

func (ds *fakeDataStore) GetNodeSelectors(context.Context, string, datastore.DataConsistency) ([]*common.Selector, error) {
	return []*common.Selector{}, ds.err
}

func (ds *fakeDataStore) ListAttestedNodes(context.Context, *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
	return &datastore.ListAttestedNodesResponse{}, ds.err
}

func (ds *fakeDataStore) ListAttestedNodeEvents(context.Context, *datastore.ListAttestedNodeEventsRequest) (*datastore.ListAttestedNodeEventsResponse, error) {
	return &datastore.ListAttestedNodeEventsResponse{}, ds.err
}

func (ds *fakeDataStore) ListBundles(context.Context, *datastore.ListBundlesRequest) (*datastore.ListBundlesResponse, error) {
	return &datastore.ListBundlesResponse{}, ds.err
}

func (ds *fakeDataStore) ListNodeSelectors(context.Context, *datastore.ListNodeSelectorsRequest) (*datastore.ListNodeSelectorsResponse, error) {
	return &datastore.ListNodeSelectorsResponse{}, ds.err
}

func (ds *fakeDataStore) ListRegistrationEntries(context.Context, *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	return &datastore.ListRegistrationEntriesResponse{}, ds.err
}

func (ds *fakeDataStore) ListRegistrationEntryEvents(context.Context, *datastore.ListRegistrationEntryEventsRequest) (*datastore.ListRegistrationEntryEventsResponse, error) {
	return &datastore.ListRegistrationEntryEventsResponse{}, ds.err
}

func (ds *fakeDataStore) PruneAttestedNodeEvents(context.Context, time.Duration) error {
	return ds.err
}

func (ds *fakeDataStore) PruneBundle(context.Context, string, time.Time) (bool, error) {
	return false, ds.err
}

func (ds *fakeDataStore) PruneJoinTokens(context.Context, time.Time) error {
	return ds.err
}

func (ds *fakeDataStore) PruneRegistrationEntries(context.Context, time.Time) error {
	return ds.err
}

func (ds *fakeDataStore) PruneRegistrationEntryEvents(context.Context, time.Duration) error {
	return ds.err
}

func (ds *fakeDataStore) SetBundle(context.Context, *common.Bundle) (*common.Bundle, error) {
	return &common.Bundle{}, ds.err
}

func (ds *fakeDataStore) TaintX509CA(context.Context, string, string) error {
	return ds.err
}

func (ds *fakeDataStore) RevokeX509CA(context.Context, string, string) error {
	return ds.err
}

func (ds *fakeDataStore) TaintJWTKey(context.Context, string, string) (*common.PublicKey, error) {
	return &common.PublicKey{}, ds.err
}

func (ds *fakeDataStore) RevokeJWTKey(context.Context, string, string) (*common.PublicKey, error) {
	return &common.PublicKey{}, ds.err
}

func (ds *fakeDataStore) SetNodeSelectors(context.Context, string, []*common.Selector) error {
	return ds.err
}

func (ds *fakeDataStore) UpdateAttestedNode(context.Context, *common.AttestedNode, *common.AttestedNodeMask) (*common.AttestedNode, error) {
	return &common.AttestedNode{}, ds.err
}

func (ds *fakeDataStore) UpdateBundle(context.Context, *common.Bundle, *common.BundleMask) (*common.Bundle, error) {
	return &common.Bundle{}, ds.err
}

func (ds *fakeDataStore) UpdateRegistrationEntry(context.Context, *common.RegistrationEntry, *common.RegistrationEntryMask) (*common.RegistrationEntry, error) {
	return &common.RegistrationEntry{}, ds.err
}

func (ds *fakeDataStore) UpdateFederationRelationship(context.Context, *datastore.FederationRelationship, *types.FederationRelationshipMask) (*datastore.FederationRelationship, error) {
	return &datastore.FederationRelationship{}, ds.err
}

func (ds *fakeDataStore) SetCAJournal(context.Context, *datastore.CAJournal) (*datastore.CAJournal, error) {
	return &datastore.CAJournal{}, ds.err
}

func (ds *fakeDataStore) FetchCAJournal(context.Context, string) (*datastore.CAJournal, error) {
	return &datastore.CAJournal{}, ds.err
}

func (ds *fakeDataStore) ListCAJournalsForTesting(context.Context) ([]*datastore.CAJournal, error) {
	return []*datastore.CAJournal{}, ds.err
}

func (ds *fakeDataStore) PruneCAJournals(context.Context, int64) error {
	return ds.err
}
