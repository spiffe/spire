package datastore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

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
		key        string
		methodName string
	}{
		{
			key:        "datastore.bundle.append",
			methodName: "AppendBundle",
		},
		{
			key:        "datastore.node.create",
			methodName: "CreateAttestedNode",
		},
		{
			key:        "datastore.bundle.create",
			methodName: "CreateBundle",
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
			key:        "datastore.node.delete",
			methodName: "DeleteAttestedNode",
		},
		{
			key:        "datastore.bundle.delete",
			methodName: "DeleteBundle",
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
			key:        "datastore.node.fetch",
			methodName: "FetchAttestedNode",
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
			key:        "datastore.node.selectors.fetch",
			methodName: "GetNodeSelectors",
		},
		{
			key:        "datastore.node.list",
			methodName: "ListAttestedNodes",
		},
		{
			key:        "datastore.bundle.list",
			methodName: "ListBundles",
		},
		{
			key:        "datastore.registration_entry.list",
			methodName: "ListRegistrationEntries",
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
			key:        "datastore.bundle.set",
			methodName: "SetBundle",
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
			key:        "datastore.registration_entry.update",
			methodName: "UpdateRegistrationEntry",
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
			out := methodValue.Call([]reflect.Value{
				reflect.ValueOf(context.Background()),
				reflect.New(methodValue.Type().In(1)).Elem(),
			})
			require.Len(t, out, 2)
			// Our fake always returns a response even on failure, which
			// our metrics shim should not be concerned about.
			require.NotNil(t, out[0].Interface(), "response should not be nil")
			return out[1].Interface()
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

func (ds *fakeDataStore) CreateAttestedNode(context.Context, *datastore.CreateAttestedNodeRequest) (*datastore.CreateAttestedNodeResponse, error) {
	return &datastore.CreateAttestedNodeResponse{}, ds.err
}

func (ds *fakeDataStore) CreateBundle(context.Context, *datastore.CreateBundleRequest) (*datastore.CreateBundleResponse, error) {
	return &datastore.CreateBundleResponse{}, ds.err
}

func (ds *fakeDataStore) CreateJoinToken(context.Context, *datastore.CreateJoinTokenRequest) (*datastore.CreateJoinTokenResponse, error) {
	return &datastore.CreateJoinTokenResponse{}, ds.err
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

func (ds *fakeDataStore) DeleteJoinToken(context.Context, *datastore.DeleteJoinTokenRequest) (*datastore.DeleteJoinTokenResponse, error) {
	return &datastore.DeleteJoinTokenResponse{}, ds.err
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

func (ds *fakeDataStore) FetchJoinToken(context.Context, *datastore.FetchJoinTokenRequest) (*datastore.FetchJoinTokenResponse, error) {
	return &datastore.FetchJoinTokenResponse{}, ds.err
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

func (ds *fakeDataStore) ListRegistrationEntries(context.Context, *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	return &datastore.ListRegistrationEntriesResponse{}, ds.err
}

func (ds *fakeDataStore) PruneBundle(context.Context, *datastore.PruneBundleRequest) (*datastore.PruneBundleResponse, error) {
	return &datastore.PruneBundleResponse{}, ds.err
}

func (ds *fakeDataStore) PruneJoinTokens(context.Context, *datastore.PruneJoinTokensRequest) (*datastore.PruneJoinTokensResponse, error) {
	return &datastore.PruneJoinTokensResponse{}, ds.err
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
