package datastore

import (
	"context"
	"crypto"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/datastore"
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

func (w metricsWrapper) CreateOrReturnRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (_ *common.RegistrationEntry, _ bool, err error) {
	callCounter := StartCreateRegistrationCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.CreateOrReturnRegistrationEntry(ctx, entry)
}

func (w metricsWrapper) CreateFederationRelationship(ctx context.Context, fr *datastore.FederationRelationship) (_ *datastore.FederationRelationship, err error) {
	callCounter := StartCreateFederationRelationshipCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.CreateFederationRelationship(ctx, fr)
}

func (w metricsWrapper) ListFederationRelationships(ctx context.Context, req *datastore.ListFederationRelationshipsRequest) (_ *datastore.ListFederationRelationshipsResponse, err error) {
	callCounter := StartListFederationRelationshipsCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.ListFederationRelationships(ctx, req)
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

func (w metricsWrapper) DeleteFederationRelationship(ctx context.Context, trustDomain spiffeid.TrustDomain) (err error) {
	callCounter := StartDeleteFederationRelationshipCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.DeleteFederationRelationship(ctx, trustDomain)
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

func (w metricsWrapper) FetchFederationRelationship(ctx context.Context, trustDomain spiffeid.TrustDomain) (_ *datastore.FederationRelationship, err error) {
	callCounter := StartFetchFederationRelationshipCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.FetchFederationRelationship(ctx, trustDomain)
}

func (w metricsWrapper) GetNodeSelectors(ctx context.Context, spiffeID string, dataConsistency datastore.DataConsistency) (_ []*common.Selector, err error) {
	callCounter := StartGetNodeSelectorsCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.GetNodeSelectors(ctx, spiffeID, dataConsistency)
}

func (w metricsWrapper) ListAttestedNodes(ctx context.Context, req *datastore.ListAttestedNodesRequest) (_ *datastore.ListAttestedNodesResponse, err error) {
	callCounter := StartListNodeCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.ListAttestedNodes(ctx, req)
}

func (w metricsWrapper) ListAttestedNodesEvents(ctx context.Context, req *datastore.ListAttestedNodesEventsRequest) (_ *datastore.ListAttestedNodesEventsResponse, err error) {
	callCounter := StartListAttestedNodesEventsCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.ListAttestedNodesEvents(ctx, req)
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

func (w metricsWrapper) ListRegistrationEntriesEvents(ctx context.Context, req *datastore.ListRegistrationEntriesEventsRequest) (_ *datastore.ListRegistrationEntriesEventsResponse, err error) {
	callCounter := StartListRegistrationEntriesEventsCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.ListRegistrationEntriesEvents(ctx, req)
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

func (w metricsWrapper) PruneAttestedNodesEvents(ctx context.Context, olderThan time.Duration) (err error) {
	callCounter := StartPruneAttestedNodesEventsCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.PruneAttestedNodesEvents(ctx, olderThan)
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

func (w metricsWrapper) PruneRegistrationEntriesEvents(ctx context.Context, olderThan time.Duration) (err error) {
	callCounter := StartPruneRegistrationEntriesEventsCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.PruneRegistrationEntriesEvents(ctx, olderThan)
}

func (w metricsWrapper) SetBundle(ctx context.Context, bundle *common.Bundle) (_ *common.Bundle, err error) {
	callCounter := StartSetBundleCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.SetBundle(ctx, bundle)
}

func (w metricsWrapper) TaintX509CA(ctx context.Context, trustDomainID string, publicKeyToTaint crypto.PublicKey) (err error) {
	callCounter := StartTaintX509CAByKeyCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.TaintX509CA(ctx, trustDomainID, publicKeyToTaint)
}

func (w metricsWrapper) RevokeX509CA(ctx context.Context, trustDomainID string, publicKeyToRevoke crypto.PublicKey) (err error) {
	callCounter := StartRevokeX509CACall(w.m)
	defer callCounter.Done(&err)
	return w.ds.RevokeX509CA(ctx, trustDomainID, publicKeyToRevoke)
}

func (w metricsWrapper) TaintJWTKey(ctx context.Context, trustDomainID string, authorityID string) (_ *common.PublicKey, err error) {
	callCounter := StartTaintJWTKeyCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.TaintJWTKey(ctx, trustDomainID, authorityID)
}

func (w metricsWrapper) RevokeJWTKey(ctx context.Context, trustDomainID string, authorityID string) (_ *common.PublicKey, err error) {
	callCounter := StartRevokeJWTKeyCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.RevokeJWTKey(ctx, trustDomainID, authorityID)
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

func (w metricsWrapper) UpdateFederationRelationship(ctx context.Context, fr *datastore.FederationRelationship, mask *types.FederationRelationshipMask) (_ *datastore.FederationRelationship, err error) {
	callCounter := StartUpdateFederationRelationshipCall(w.m)
	defer callCounter.Done(&err)
	return w.ds.UpdateFederationRelationship(ctx, fr, mask)
}
