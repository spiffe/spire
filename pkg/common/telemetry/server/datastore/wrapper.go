package datastore

import (
	"context"

	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
)

func WithMetrics(ds datastore.DataStore, metrics telemetry.Metrics) datastore.DataStore {
	return metricsWrapper{ds: ds, m: metrics}
}

type metricsWrapper struct {
	ds datastore.DataStore
	m  telemetry.Metrics
}

func (w metricsWrapper) AppendBundle(ctx context.Context, req *datastore.AppendBundleRequest) (_ *datastore.AppendBundleResponse, err error) {
	callCounter := StartAppendBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.AppendBundle(ctx, req)
}

func (w metricsWrapper) CreateAttestedNode(ctx context.Context, req *datastore.CreateAttestedNodeRequest) (_ *datastore.CreateAttestedNodeResponse, err error) {
	callCounter := StartCreateNodeCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.CreateAttestedNode(ctx, req)
}

func (w metricsWrapper) CreateBundle(ctx context.Context, req *datastore.CreateBundleRequest) (_ *datastore.CreateBundleResponse, err error) {
	callCounter := StartCreateBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.CreateBundle(ctx, req)
}

func (w metricsWrapper) CreateJoinToken(ctx context.Context, req *datastore.CreateJoinTokenRequest) (_ *datastore.CreateJoinTokenResponse, err error) {
	callCounter := StartCreateJoinTokenCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.CreateJoinToken(ctx, req)
}

func (w metricsWrapper) CreateRegistrationEntry(ctx context.Context, req *datastore.CreateRegistrationEntryRequest) (_ *datastore.CreateRegistrationEntryResponse, err error) {
	callCounter := StartCreateRegistrationCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.CreateRegistrationEntry(ctx, req)
}

func (w metricsWrapper) DeleteAttestedNode(ctx context.Context, req *datastore.DeleteAttestedNodeRequest) (_ *datastore.DeleteAttestedNodeResponse, err error) {
	callCounter := StartDeleteNodeCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.DeleteAttestedNode(ctx, req)
}

func (w metricsWrapper) DeleteBundle(ctx context.Context, req *datastore.DeleteBundleRequest) (_ *datastore.DeleteBundleResponse, err error) {
	callCounter := StartDeleteBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.DeleteBundle(ctx, req)
}

func (w metricsWrapper) DeleteJoinToken(ctx context.Context, req *datastore.DeleteJoinTokenRequest) (_ *datastore.DeleteJoinTokenResponse, err error) {
	callCounter := StartDeleteJoinTokenCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.DeleteJoinToken(ctx, req)
}

func (w metricsWrapper) DeleteRegistrationEntry(ctx context.Context, req *datastore.DeleteRegistrationEntryRequest) (_ *datastore.DeleteRegistrationEntryResponse, err error) {
	callCounter := StartDeleteRegistrationCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.DeleteRegistrationEntry(ctx, req)
}

func (w metricsWrapper) FetchAttestedNode(ctx context.Context, req *datastore.FetchAttestedNodeRequest) (_ *datastore.FetchAttestedNodeResponse, err error) {
	callCounter := StartFetchNodeCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.FetchAttestedNode(ctx, req)
}

func (w metricsWrapper) FetchBundle(ctx context.Context, req *datastore.FetchBundleRequest) (_ *datastore.FetchBundleResponse, err error) {
	callCounter := StartFetchBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.FetchBundle(ctx, req)
}

func (w metricsWrapper) FetchJoinToken(ctx context.Context, req *datastore.FetchJoinTokenRequest) (_ *datastore.FetchJoinTokenResponse, err error) {
	callCounter := StartFetchJoinTokenCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.FetchJoinToken(ctx, req)
}

func (w metricsWrapper) FetchRegistrationEntry(ctx context.Context, req *datastore.FetchRegistrationEntryRequest) (_ *datastore.FetchRegistrationEntryResponse, err error) {
	callCounter := StartFetchRegistrationCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.FetchRegistrationEntry(ctx, req)
}

func (w metricsWrapper) GetNodeSelectors(ctx context.Context, req *datastore.GetNodeSelectorsRequest) (_ *datastore.GetNodeSelectorsResponse, err error) {
	callCounter := StartGetNodeSelectorsCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.GetNodeSelectors(ctx, req)
}

func (w metricsWrapper) ListAttestedNodes(ctx context.Context, req *datastore.ListAttestedNodesRequest) (_ *datastore.ListAttestedNodesResponse, err error) {
	callCounter := StartListNodeCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.ListAttestedNodes(ctx, req)
}

func (w metricsWrapper) ListBundles(ctx context.Context, req *datastore.ListBundlesRequest) (_ *datastore.ListBundlesResponse, err error) {
	callCounter := StartListBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.ListBundles(ctx, req)
}

func (w metricsWrapper) ListRegistrationEntries(ctx context.Context, req *datastore.ListRegistrationEntriesRequest) (_ *datastore.ListRegistrationEntriesResponse, err error) {
	callCounter := StartListRegistrationCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.ListRegistrationEntries(ctx, req)
}

func (w metricsWrapper) PruneBundle(ctx context.Context, req *datastore.PruneBundleRequest) (_ *datastore.PruneBundleResponse, err error) {
	callCounter := StartPruneBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.PruneBundle(ctx, req)
}

func (w metricsWrapper) PruneJoinTokens(ctx context.Context, req *datastore.PruneJoinTokensRequest) (_ *datastore.PruneJoinTokensResponse, err error) {
	callCounter := StartPruneJoinTokenCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.PruneJoinTokens(ctx, req)
}

func (w metricsWrapper) PruneRegistrationEntries(ctx context.Context, req *datastore.PruneRegistrationEntriesRequest) (_ *datastore.PruneRegistrationEntriesResponse, err error) {
	callCounter := StartPruneRegistrationCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.PruneRegistrationEntries(ctx, req)
}

func (w metricsWrapper) SetBundle(ctx context.Context, req *datastore.SetBundleRequest) (_ *datastore.SetBundleResponse, err error) {
	callCounter := StartSetBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.SetBundle(ctx, req)
}

func (w metricsWrapper) SetNodeSelectors(ctx context.Context, req *datastore.SetNodeSelectorsRequest) (_ *datastore.SetNodeSelectorsResponse, err error) {
	callCounter := StartSetNodeSelectorsCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.SetNodeSelectors(ctx, req)
}

func (w metricsWrapper) UpdateAttestedNode(ctx context.Context, req *datastore.UpdateAttestedNodeRequest) (_ *datastore.UpdateAttestedNodeResponse, err error) {
	callCounter := StartUpdateNodeCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.UpdateAttestedNode(ctx, req)
}

func (w metricsWrapper) UpdateBundle(ctx context.Context, req *datastore.UpdateBundleRequest) (_ *datastore.UpdateBundleResponse, err error) {
	callCounter := StartUpdateBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.UpdateBundle(ctx, req)
}

func (w metricsWrapper) UpdateRegistrationEntry(ctx context.Context, req *datastore.UpdateRegistrationEntryRequest) (_ *datastore.UpdateRegistrationEntryResponse, err error) {
	callCounter := StartUpdateRegistrationCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.UpdateRegistrationEntry(ctx, req)
}
