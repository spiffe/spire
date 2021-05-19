package datastore

import (
	"context"
	"time"

	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

// WithMetrics wraps a datastore interface and provides per-call metrics. The
// metrics produced include a call counter and elapsed time measurement with
// labels for the status code.
func WithMetrics(ds datastore.DataStore, metrics telemetry.Metrics) datastore.DataStore {
	return metricsWrapper{ds: ds, m: metrics}
}

type metricsWrapper struct {
	ds datastore.DataStore
	m  telemetry.Metrics
}

func (w metricsWrapper) AppendBundle(ctx context.Context, bundle *common.Bundle) (_ *common.Bundle, err error) {
	callCounter := StartAppendBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.AppendBundle(ctx, bundle)
}

func (w metricsWrapper) CreateAttestedNode(ctx context.Context, node *common.AttestedNode) (_ *common.AttestedNode, err error) {
	callCounter := StartCreateNodeCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.CreateAttestedNode(ctx, node)
}

func (w metricsWrapper) CreateBundle(ctx context.Context, bundle *common.Bundle) (_ *common.Bundle, err error) {
	callCounter := StartCreateBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.CreateBundle(ctx, bundle)
}

func (w metricsWrapper) CreateJoinToken(ctx context.Context, token *datastore.JoinToken) (err error) {
	callCounter := StartCreateJoinTokenCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.CreateJoinToken(ctx, token)
}

func (w metricsWrapper) CreateRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (_ *common.RegistrationEntry, err error) {
	callCounter := StartCreateRegistrationCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.CreateRegistrationEntry(ctx, entry)
}

func (w metricsWrapper) DeleteAttestedNode(ctx context.Context, spiffeID string) (_ *common.AttestedNode, err error) {
	callCounter := StartDeleteNodeCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.DeleteAttestedNode(ctx, spiffeID)
}

func (w metricsWrapper) DeleteBundle(ctx context.Context, trustDomain string, mode datastore.DeleteMode) (err error) {
	callCounter := StartDeleteBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.DeleteBundle(ctx, trustDomain, mode)
}

func (w metricsWrapper) DeleteJoinToken(ctx context.Context, token string) (err error) {
	callCounter := StartDeleteJoinTokenCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.DeleteJoinToken(ctx, token)
}

func (w metricsWrapper) DeleteRegistrationEntry(ctx context.Context, entryID string) (_ *common.RegistrationEntry, err error) {
	callCounter := StartDeleteRegistrationCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.DeleteRegistrationEntry(ctx, entryID)
}

func (w metricsWrapper) FetchAttestedNode(ctx context.Context, spiffeID string) (_ *common.AttestedNode, err error) {
	callCounter := StartFetchNodeCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.FetchAttestedNode(ctx, spiffeID)
}

func (w metricsWrapper) FetchBundle(ctx context.Context, trustDomain string) (_ *common.Bundle, err error) {
	callCounter := StartFetchBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.FetchBundle(ctx, trustDomain)
}

func (w metricsWrapper) FetchJoinToken(ctx context.Context, token string) (_ *datastore.JoinToken, err error) {
	callCounter := StartFetchJoinTokenCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.FetchJoinToken(ctx, token)
}

func (w metricsWrapper) FetchRegistrationEntry(ctx context.Context, entryID string) (_ *common.RegistrationEntry, err error) {
	callCounter := StartFetchRegistrationCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.FetchRegistrationEntry(ctx, entryID)
}

func (w metricsWrapper) GetNodeSelectors(ctx context.Context, spiffeID string, dbPreference datastore.DataConsistency) (_ []*common.Selector, err error) {
	callCounter := StartGetNodeSelectorsCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.GetNodeSelectors(ctx, spiffeID, dbPreference)
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

func (w metricsWrapper) ListNodeSelectors(ctx context.Context, req *datastore.ListNodeSelectorsRequest) (_ *datastore.ListNodeSelectorsResponse, err error) {
	callCounter := StartListNodeSelectorsCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.ListNodeSelectors(ctx, req)
}

func (w metricsWrapper) ListRegistrationEntries(ctx context.Context, req *datastore.ListRegistrationEntriesRequest) (_ *datastore.ListRegistrationEntriesResponse, err error) {
	callCounter := StartListRegistrationCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.ListRegistrationEntries(ctx, req)
}

func (w metricsWrapper) CountAttestedNodes(ctx context.Context) (_ int32, err error) {
	callCounter := StartCountNodeCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.CountAttestedNodes(ctx)
}

func (w metricsWrapper) CountBundles(ctx context.Context) (_ int32, err error) {
	callCounter := StartCountBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.CountBundles(ctx)
}

func (w metricsWrapper) CountRegistrationEntries(ctx context.Context) (_ int32, err error) {
	callCounter := StartCountRegistrationCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.CountRegistrationEntries(ctx)
}

func (w metricsWrapper) PruneBundle(ctx context.Context, trustDomainID string, expiresBefore time.Time) (_ bool, err error) {
	callCounter := StartPruneBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.PruneBundle(ctx, trustDomainID, expiresBefore)
}

func (w metricsWrapper) PruneJoinTokens(ctx context.Context, expiresBefore time.Time) (err error) {
	callCounter := StartPruneJoinTokenCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.PruneJoinTokens(ctx, expiresBefore)
}

func (w metricsWrapper) PruneRegistrationEntries(ctx context.Context, expiresBefore time.Time) (err error) {
	callCounter := StartPruneRegistrationCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.PruneRegistrationEntries(ctx, expiresBefore)
}

func (w metricsWrapper) SetBundle(ctx context.Context, bundle *common.Bundle) (_ *common.Bundle, err error) {
	callCounter := StartSetBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.SetBundle(ctx, bundle)
}

func (w metricsWrapper) SetNodeSelectors(ctx context.Context, spiffeID string, selectors []*common.Selector) (err error) {
	callCounter := StartSetNodeSelectorsCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.SetNodeSelectors(ctx, spiffeID, selectors)
}

func (w metricsWrapper) UpdateAttestedNode(ctx context.Context, node *common.AttestedNode, mask *common.AttestedNodeMask) (_ *common.AttestedNode, err error) {
	callCounter := StartUpdateNodeCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.UpdateAttestedNode(ctx, node, mask)
}

func (w metricsWrapper) UpdateBundle(ctx context.Context, bundle *common.Bundle, mask *common.BundleMask) (_ *common.Bundle, err error) {
	callCounter := StartUpdateBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.UpdateBundle(ctx, bundle, mask)
}

func (w metricsWrapper) UpdateRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry, mask *common.RegistrationEntryMask) (_ *common.RegistrationEntry, err error) {
	callCounter := StartUpdateRegistrationCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.UpdateRegistrationEntry(ctx, entry, mask)
}
