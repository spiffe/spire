package datastore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
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
	for i := 0; i < wt.NumMethod(); i++ {
		methodNames[wt.Method(i).Name] = struct{}{}
	}

	for _, tt := range []struct {
		key         string
		methodName  string
		returnCount int
	}{
		{
			key:         "datastore.bundle.append",
			methodName:  "AppendBundle",
			returnCount: 2,
		},
		{
			key:         "datastore.node.count",
			methodName:  "CountAttestedNodes",
			returnCount: 2,
		},
		{
			key:         "datastore.bundle.count",
			methodName:  "CountBundles",
			returnCount: 2,
		},
		{
			key:         "datastore.registration_entry.count",
			methodName:  "CountRegistrationEntries",
			returnCount: 2,
		},
		{
			key:         "datastore.node.create",
			methodName:  "CreateAttestedNode",
			returnCount: 2,
		},
		{
			key:         "datastore.bundle.create",
			methodName:  "CreateBundle",
			returnCount: 2,
		},
		{
			key:         "datastore.join_token.create",
			methodName:  "CreateJoinToken",
			returnCount: 2,
		},
		{
			key:         "datastore.registration_entry.create",
			methodName:  "CreateRegistrationEntry",
			returnCount: 2,
		},
		{
			key:         "datastore.node.delete",
			methodName:  "DeleteAttestedNode",
			returnCount: 2,
		},
		{
			key:         "datastore.bundle.delete",
			methodName:  "DeleteBundle",
			returnCount: 2,
		},
		{
			key:         "datastore.join_token.delete",
			methodName:  "DeleteJoinToken",
			returnCount: 2,
		},
		{
			key:         "datastore.registration_entry.delete",
			methodName:  "DeleteRegistrationEntry",
			returnCount: 2,
		},
		{
			key:         "datastore.node.fetch",
			methodName:  "FetchAttestedNode",
			returnCount: 2,
		},
		{
			key:         "datastore.bundle.fetch",
			methodName:  "FetchBundle",
			returnCount: 2,
		},
		{
			key:         "datastore.join_token.fetch",
			methodName:  "FetchJoinToken",
			returnCount: 2,
		},
		{
			key:         "datastore.registration_entry.fetch",
			methodName:  "FetchRegistrationEntry",
			returnCount: 2,
		},
		{
			key:         "datastore.node.selectors.fetch",
			methodName:  "GetNodeSelectors",
			returnCount: 2,
		},
		{
			key:         "datastore.node.list",
			methodName:  "ListAttestedNodes",
			returnCount: 2,
		},
		{
			key:         "datastore.bundle.list",
			methodName:  "ListBundles",
			returnCount: 2,
		},
		{
			key:         "datastore.node.selectors.list",
			methodName:  "ListNodeSelectors",
			returnCount: 2,
		},
		{
			key:         "datastore.registration_entry.list",
			methodName:  "ListRegistrationEntries",
			returnCount: 2,
		},
		{
			key:         "datastore.bundle.prune",
			methodName:  "PruneBundle",
			returnCount: 2,
		},
		{
			key:         "datastore.join_token.prune",
			methodName:  "PruneJoinTokens",
			returnCount: 1,
		},
		{
			key:         "datastore.registration_entry.prune",
			methodName:  "PruneRegistrationEntries",
			returnCount: 2,
		},
		{
			key:         "datastore.bundle.set",
			methodName:  "SetBundle",
			returnCount: 2,
		},
		{
			key:         "datastore.node.selectors.set",
			methodName:  "SetNodeSelectors",
			returnCount: 2,
		},
		{
			key:         "datastore.node.update",
			methodName:  "UpdateAttestedNode",
			returnCount: 2,
		},
		{
			key:         "datastore.bundle.update",
			methodName:  "UpdateBundle",
			returnCount: 2,
		},
		{
			key:         "datastore.registration_entry.update",
			methodName:  "UpdateRegistrationEntry",
			returnCount: 2,
		},
	} {
		tt := tt
		methodType, ok := wt.MethodByName(tt.methodName)
		require.True(t, ok, "method %q does not exist on DataStore interface", tt.methodName)
		methodValue := wv.Method(methodType.Index)

		// Record that the method was tested. Methods that aren't tested
		// will fail the test below.
		delete(methodNames, methodType.Name)

		doCall := func(err error) interface{} {
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
			for i := 0; i < numOut-1; i++ {
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

func (ds *fakeDataStore) AppendBundle(context.Context, *datastore.AppendBundleRequest) (*datastore.AppendBundleResponse, error) {
	return &datastore.AppendBundleResponse{}, ds.err
}

func (ds *fakeDataStore) CountAttestedNodes(context.Context) (int32, error) {
	return 0, ds.err
}

func (ds *fakeDataStore) CountBundles(context.Context) (int32, error) {
	return 0, ds.err
}

func (ds *fakeDataStore) CountRegistrationEntries(context.Context) (int32, error) {
	return 0, ds.err
}

func (ds *fakeDataStore) CreateAttestedNode(context.Context, *datastore.CreateAttestedNodeRequest) (*datastore.CreateAttestedNodeResponse, error) {
	return &datastore.CreateAttestedNodeResponse{}, ds.err
}

func (ds *fakeDataStore) CreateBundle(context.Context, *datastore.CreateBundleRequest) (*datastore.CreateBundleResponse, error) {
	return &datastore.CreateBundleResponse{}, ds.err
}

func (ds *fakeDataStore) CreateJoinToken(context.Context, *datastore.JoinToken) error {
	return ds.err
}

func (ds *fakeDataStore) CreateRegistrationEntry(context.Context, *datastore.CreateRegistrationEntryRequest) (*datastore.CreateRegistrationEntryResponse, error) {
	return &datastore.CreateRegistrationEntryResponse{}, ds.err
}

func (ds *fakeDataStore) DeleteAttestedNode(context.Context, *datastore.DeleteAttestedNodeRequest) (*datastore.DeleteAttestedNodeResponse, error) {
	return &datastore.DeleteAttestedNodeResponse{}, ds.err
}

func (ds *fakeDataStore) DeleteBundle(context.Context, *datastore.DeleteBundleRequest) (*datastore.DeleteBundleResponse, error) {
	return &datastore.DeleteBundleResponse{}, ds.err
}

func (ds *fakeDataStore) DeleteJoinToken(context.Context, string) error {
	return ds.err
}

func (ds *fakeDataStore) DeleteRegistrationEntry(context.Context, *datastore.DeleteRegistrationEntryRequest) (*datastore.DeleteRegistrationEntryResponse, error) {
	return &datastore.DeleteRegistrationEntryResponse{}, ds.err
}

func (ds *fakeDataStore) FetchAttestedNode(context.Context, *datastore.FetchAttestedNodeRequest) (*datastore.FetchAttestedNodeResponse, error) {
	return &datastore.FetchAttestedNodeResponse{}, ds.err
}

func (ds *fakeDataStore) FetchBundle(context.Context, *datastore.FetchBundleRequest) (*datastore.FetchBundleResponse, error) {
	return &datastore.FetchBundleResponse{}, ds.err
}

func (ds *fakeDataStore) FetchJoinToken(context.Context, string) (*datastore.JoinToken, error) {
	return &datastore.JoinToken{}, ds.err
}

func (ds *fakeDataStore) FetchRegistrationEntry(context.Context, *datastore.FetchRegistrationEntryRequest) (*datastore.FetchRegistrationEntryResponse, error) {
	return &datastore.FetchRegistrationEntryResponse{}, ds.err
}

func (ds *fakeDataStore) GetNodeSelectors(context.Context, *datastore.GetNodeSelectorsRequest) (*datastore.GetNodeSelectorsResponse, error) {
	return &datastore.GetNodeSelectorsResponse{}, ds.err
}

func (ds *fakeDataStore) ListAttestedNodes(context.Context, *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
	return &datastore.ListAttestedNodesResponse{}, ds.err
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

func (ds *fakeDataStore) PruneBundle(context.Context, *datastore.PruneBundleRequest) (*datastore.PruneBundleResponse, error) {
	return &datastore.PruneBundleResponse{}, ds.err
}

func (ds *fakeDataStore) PruneJoinTokens(context.Context, time.Time) error {
	return ds.err
}

func (ds *fakeDataStore) PruneRegistrationEntries(context.Context, *datastore.PruneRegistrationEntriesRequest) (*datastore.PruneRegistrationEntriesResponse, error) {
	return &datastore.PruneRegistrationEntriesResponse{}, ds.err
}

func (ds *fakeDataStore) SetBundle(context.Context, *datastore.SetBundleRequest) (*datastore.SetBundleResponse, error) {
	return &datastore.SetBundleResponse{}, ds.err
}

func (ds *fakeDataStore) SetNodeSelectors(context.Context, *datastore.SetNodeSelectorsRequest) (*datastore.SetNodeSelectorsResponse, error) {
	return &datastore.SetNodeSelectorsResponse{}, ds.err
}

func (ds *fakeDataStore) UpdateAttestedNode(context.Context, *datastore.UpdateAttestedNodeRequest) (*datastore.UpdateAttestedNodeResponse, error) {
	return &datastore.UpdateAttestedNodeResponse{}, ds.err
}

func (ds *fakeDataStore) UpdateBundle(context.Context, *datastore.UpdateBundleRequest) (*datastore.UpdateBundleResponse, error) {
	return &datastore.UpdateBundleResponse{}, ds.err
}

func (ds *fakeDataStore) UpdateRegistrationEntry(context.Context, *datastore.UpdateRegistrationEntryRequest) (*datastore.UpdateRegistrationEntryResponse, error) {
	return &datastore.UpdateRegistrationEntryResponse{}, ds.err
}
