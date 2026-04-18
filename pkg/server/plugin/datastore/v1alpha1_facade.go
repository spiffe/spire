package datastore

import (
	"context"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	"github.com/spiffe/spire/pkg/common/plugin"
	ds_types "github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// V1Alpha1 is a plugin facade for the v1alpha1 version of the datastore plugin API. It
// is responsible for translating between the internal SPIRE datastore types in the
// package github.com/spiffe/spire/pkg/server/datastore and the plugin wire types defined
// in the plugin SDK.
type V1Alpha1 struct {
	plugin.Facade
	datastorev1.DataStorePluginClient
}

func (v1 *V1Alpha1) AppendBundle(ctx context.Context, bundle *common.Bundle) (*common.Bundle, error) {
	pluginBundle, err := fromServerToPluginBundle(bundle)
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	resp, err := v1.DataStorePluginClient.AppendBundle(ctx, &datastorev1.AppendBundleRequest{
		Bundle: pluginBundle,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerBundle(resp.GetBundle())
}

func (v1 *V1Alpha1) CountBundles(ctx context.Context) (int32, error) {
	resp, err := v1.DataStorePluginClient.CountBundles(ctx, &datastorev1.CountBundlesRequest{})
	if err != nil {
		return 0, v1.WrapErr(err)
	}

	return resp.GetCount(), nil
}

func (v1 *V1Alpha1) CreateBundle(ctx context.Context, bundle *common.Bundle) (*common.Bundle, error) {
	pluginBundle, err := fromServerToPluginBundle(bundle)
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	resp, err := v1.DataStorePluginClient.CreateBundle(ctx, &datastorev1.CreateBundleRequest{
		Bundle: pluginBundle,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerBundle(resp.GetBundle())
}

func (v1 *V1Alpha1) DeleteBundle(ctx context.Context, trustDomainID string, mode ds_types.DeleteMode) error {
	pluginDeleteMode, err := fromServerToPluginDeleteMode(mode)
	if err != nil {
		return v1.WrapErr(err)
	}

	_, err = v1.DataStorePluginClient.DeleteBundle(ctx, &datastorev1.DeleteBundleRequest{
		TrustDomain: trustDomainID,
		Mode:        pluginDeleteMode,
	})
	return v1.WrapErr(err)
}

func (v1 *V1Alpha1) FetchBundle(ctx context.Context, trustDomainID string) (*common.Bundle, error) {
	resp, err := v1.DataStorePluginClient.FetchBundle(ctx, &datastorev1.FetchBundleRequest{
		TrustDomain: trustDomainID,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerBundle(resp.GetBundle())
}

func (v1 *V1Alpha1) ListBundles(ctx context.Context, req *ds_types.ListBundlesRequest) (*ds_types.ListBundlesResponse, error) {
	dsReq := &datastorev1.ListBundlesRequest{
		Pagination: fromServerToPluginPagination(req.Pagination),
	}

	resp, err := v1.DataStorePluginClient.ListBundles(ctx, dsReq)
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	bundles, err := fromPluginToServerBundles(resp.GetBundles())
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return &ds_types.ListBundlesResponse{
		Bundles:    bundles,
		Pagination: fromPluginToServerPagination(resp.GetPagination()),
	}, nil
}

func (v1 *V1Alpha1) PruneBundle(ctx context.Context, trustDomainID string, expiresBefore time.Time) (changed bool, err error) {
	resp, err := v1.DataStorePluginClient.PruneBundle(ctx, &datastorev1.PruneBundleRequest{
		TrustDomain:   trustDomainID,
		ExpiresBefore: int64(expiresBefore.Unix()),
	})
	if err != nil {
		return false, v1.WrapErr(err)
	}

	return resp.GetChanged(), nil
}

func (v1 *V1Alpha1) SetBundle(ctx context.Context, bundle *common.Bundle) (*common.Bundle, error) {
	pluginBundle, err := fromServerToPluginBundle(bundle)
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	resp, err := v1.DataStorePluginClient.SetBundle(ctx, &datastorev1.SetBundleRequest{
		Bundle: pluginBundle,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerBundle(resp.GetBundle())
}

func (v1 *V1Alpha1) UpdateBundle(ctx context.Context, bundle *common.Bundle, mask *common.BundleMask) (*common.Bundle, error) {
	pluginBundle, err := fromServerToPluginBundle(bundle)
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	resp, err := v1.DataStorePluginClient.UpdateBundle(ctx, &datastorev1.UpdateBundleRequest{
		Bundle: pluginBundle,
		Mask:   fromServerToPluginBundleMask(mask),
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerBundle(resp.GetBundle())
}

// Keys
func (v1 *V1Alpha1) TaintX509CA(ctx context.Context, trustDomainID string, subjectKeyIDToTaint string) error {
	_, err := v1.DataStorePluginClient.TaintX509CA(ctx, &datastorev1.TaintX509CARequest{
		TrustDomain: trustDomainID,
		KeyId:       subjectKeyIDToTaint,
	})
	if err != nil {
		return v1.WrapErr(err)
	}

	return nil
}

func (v1 *V1Alpha1) RevokeX509CA(ctx context.Context, trustDomainID string, subjectKeyIDToRevoke string) error {
	_, err := v1.DataStorePluginClient.RevokeX509CA(ctx, &datastorev1.RevokeX509CARequest{
		TrustDomain: trustDomainID,
		KeyId:       subjectKeyIDToRevoke,
	})
	if err != nil {
		return v1.WrapErr(err)
	}

	return nil
}

func (v1 *V1Alpha1) TaintJWTKey(ctx context.Context, trustDomainID string, authorityID string) (*common.PublicKey, error) {
	resp, err := v1.DataStorePluginClient.TaintJWTKey(ctx, &datastorev1.TaintJWTKeyRequest{
		TrustDomain: trustDomainID,
		AuthorityId: authorityID,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerJwtSigningKey(resp.GetKey()), nil
}

func (v1 *V1Alpha1) RevokeJWTKey(ctx context.Context, trustDomainID string, authorityID string) (*common.PublicKey, error) {
	resp, err := v1.DataStorePluginClient.RevokeJWTKey(ctx, &datastorev1.RevokeJWTKeyRequest{
		TrustDomain: trustDomainID,
		AuthorityId: authorityID,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerJwtSigningKey(resp.GetKey()), nil
}

// Entries
func (v1 *V1Alpha1) CountRegistrationEntries(ctx context.Context, req *ds_types.CountRegistrationEntriesRequest) (int32, error) {
	dsReq := &datastorev1.CountRegistrationEntriesRequest{
		BySelectors:     fromServerToPluginBySelectors(req.BySelectors),
		ByParentId:      req.ByParentID,
		BySpiffeId:      req.BySpiffeID,
		ByHint:          req.ByHint,
		ByFederatesWith: fromServerToPluginByFederatesWith(req.ByFederatesWith),
	}

	if req.ByDownstream != nil {
		dsReq.FilterByDownstream = true
		dsReq.DownstreamValue = *req.ByDownstream
	}

	resp, err := v1.DataStorePluginClient.CountRegistrationEntries(ctx, dsReq)
	if err != nil {
		return 0, v1.WrapErr(err)
	}

	return resp.GetCount(), nil
}

func (v1 *V1Alpha1) CreateRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	resp, err := v1.DataStorePluginClient.CreateRegistrationEntry(ctx, &datastorev1.CreateRegistrationEntryRequest{
		Entry: fromServerToPluginRegistrationEntry(entry),
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerRegistrationEntry(resp.GetEntry()), nil
}

func (v1 *V1Alpha1) CreateOrReturnRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, bool, error) {
	resp, err := v1.DataStorePluginClient.CreateOrReturnRegistrationEntry(ctx, &datastorev1.CreateOrReturnRegistrationEntryRequest{
		Entry: fromServerToPluginRegistrationEntry(entry),
	})
	if err != nil {
		return nil, false, v1.WrapErr(err)
	}

	return fromPluginToServerRegistrationEntry(resp.GetEntry()), !resp.GetCreated(), nil
}

func (v1 *V1Alpha1) DeleteRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error) {
	resp, err := v1.DataStorePluginClient.DeleteRegistrationEntry(ctx, &datastorev1.DeleteRegistrationEntryRequest{
		EntryId: entryID,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerRegistrationEntry(resp.GetEntry()), nil
}

func (v1 *V1Alpha1) FetchRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error) {
	resp, err := v1.DataStorePluginClient.FetchRegistrationEntry(ctx, &datastorev1.FetchRegistrationEntryRequest{
		EntryId: entryID,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerRegistrationEntry(resp.GetEntry()), nil
}

func (v1 *V1Alpha1) FetchRegistrationEntries(ctx context.Context, entryIDs []string) (map[string]*common.RegistrationEntry, error) {
	resp, err := v1.DataStorePluginClient.FetchRegistrationEntries(ctx, &datastorev1.FetchRegistrationEntriesRequest{
		EntryIds: entryIDs,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	entryMap := make(map[string]*common.RegistrationEntry, len(resp.GetEntries()))
	for _, entry := range resp.GetEntries() {
		commonEntry := fromPluginToServerRegistrationEntry(entry)
		entryMap[commonEntry.EntryId] = commonEntry
	}

	return entryMap, nil
}

func (v1 *V1Alpha1) ListRegistrationEntries(ctx context.Context, req *ds_types.ListRegistrationEntriesRequest) (*ds_types.ListRegistrationEntriesResponse, error) {
	dsReq := &datastorev1.ListRegistrationEntriesRequest{
		BySelectors:     fromServerToPluginBySelectors(req.BySelectors),
		ByParentId:      req.ByParentID,
		BySpiffeId:      req.BySpiffeID,
		ByHint:          req.ByHint,
		ByFederatesWith: fromServerToPluginByFederatesWith(req.ByFederatesWith),
		Pagination:      fromServerToPluginPagination(req.Pagination),
	}

	if req.ByDownstream != nil {
		dsReq.FilterByDownstream = true
		dsReq.DownstreamValue = *req.ByDownstream
	}

	resp, err := v1.DataStorePluginClient.ListRegistrationEntries(ctx, dsReq)
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return &ds_types.ListRegistrationEntriesResponse{
		Entries:    fromPluginToServerRegisterationEntries(resp.GetEntries()),
		Pagination: fromPluginToServerPagination(resp.GetPagination()),
	}, nil
}

func (v1 *V1Alpha1) PruneRegistrationEntries(ctx context.Context, expiresBefore time.Time) error {
	_, err := v1.DataStorePluginClient.PruneRegistrationEntries(ctx, &datastorev1.PruneRegistrationEntriesRequest{
		ExpiresBefore: int64(expiresBefore.Unix()),
	})
	return v1.WrapErr(err)
}

func (v1 *V1Alpha1) UpdateRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry, mask *common.RegistrationEntryMask) (*common.RegistrationEntry, error) {
	resp, err := v1.DataStorePluginClient.UpdateRegistrationEntry(ctx, &datastorev1.UpdateRegistrationEntryRequest{
		Entry: fromServerToPluginRegistrationEntry(entry),
		Mask:  fromServerToPluginRegistrationEntriesMask(mask),
	})

	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerRegistrationEntry(resp.GetEntry()), nil
}

// Entries Events
func (v1 *V1Alpha1) ListRegistrationEntryEvents(ctx context.Context, req *ds_types.ListRegistrationEntryEventsRequest) (*ds_types.ListRegistrationEntryEventsResponse, error) {
	resp, err := v1.DataStorePluginClient.ListRegistrationEntryEvents(ctx, &datastorev1.ListRegistrationEntryEventsRequest{
		GreaterThanEventId: uint64(req.GreaterThanEventID),
		LessThanEventId:    uint64(req.LessThanEventID),
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	events := make([]ds_types.RegistrationEntryEvent, len(resp.GetEvents()))
	for i, event := range resp.GetEvents() {
		events[i] = ds_types.RegistrationEntryEvent{
			EventID: uint(event.GetEventId()),
			EntryID: event.GetEntryId(),
		}
	}

	return &ds_types.ListRegistrationEntryEventsResponse{
		Events: events,
	}, nil
}

func (v1 *V1Alpha1) PruneRegistrationEntryEvents(ctx context.Context, olderThan time.Duration) error {
	_, err := v1.DataStorePluginClient.PruneRegistrationEntryEvents(ctx, &datastorev1.PruneRegistrationEntryEventsRequest{
		ExpiresBefore: int64(olderThan.Seconds()), // TODO(tjons): not correct
	})
	return v1.WrapErr(err)
}

func (v1 *V1Alpha1) FetchRegistrationEntryEvent(ctx context.Context, eventID uint) (*ds_types.RegistrationEntryEvent, error) {
	resp, err := v1.DataStorePluginClient.FetchRegistrationEntryEvent(ctx, &datastorev1.FetchRegistrationEntryEventRequest{
		EventId: uint64(eventID),
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return &ds_types.RegistrationEntryEvent{
		EventID: uint(resp.GetEvent().GetEventId()),
		EntryID: resp.GetEvent().GetEntryId(),
	}, nil
}

func (v1 *V1Alpha1) CreateRegistrationEntryEventForTesting(ctx context.Context, event *ds_types.RegistrationEntryEvent) error {
	_, err := v1.DataStorePluginClient.CreateRegistrationEntryEvent(ctx, &datastorev1.CreateRegistrationEntryEventRequest{
		Event: &datastorev1.RegistrationEntryEvent{
			EventId: uint64(event.EventID),
			EntryId: event.EntryID,
		},
	})

	return v1.WrapErr(err)
}

func (v1 *V1Alpha1) DeleteRegistrationEntryEventForTesting(ctx context.Context, eventID uint) error {
	_, err := v1.DataStorePluginClient.DeleteRegistrationEntryEvent(ctx, &datastorev1.DeleteRegistrationEntryEventRequest{
		EventId: uint64(eventID),
	})

	return v1.WrapErr(err)
}

// Nodes
func (v1 *V1Alpha1) CountAttestedNodes(ctx context.Context, req *ds_types.CountAttestedNodesRequest) (int32, error) {
	dsReq := &datastorev1.CountAttestedNodesRequest{
		ByAttestationType: req.ByAttestationType,
		BySelectors:       fromServerToPluginBySelectors(req.BySelectorMatch),
		ByExpiresBefore:   int64(req.ByExpiresBefore.Unix()),
		FetchSelectors:    req.FetchSelectors,
	}

	if req.ByCanReattest != nil {
		dsReq.ByCanReattest = true
		dsReq.CanReattestValue = *req.ByCanReattest
	}

	if req.ByBanned != nil {
		dsReq.ByBanned = true
		dsReq.BannedValue = *req.ByBanned
	}

	resp, err := v1.DataStorePluginClient.CountAttestedNodes(ctx, dsReq)
	if err != nil {
		return 0, v1.WrapErr(err)
	}

	return int32(resp.GetCount()), nil
}

func (v1 *V1Alpha1) CreateAttestedNode(ctx context.Context, node *common.AttestedNode) (*common.AttestedNode, error) {
	resp, err := v1.DataStorePluginClient.CreateAttestedNode(ctx, &datastorev1.CreateAttestedNodeRequest{
		Node: fromServerToPluginAttestedNode(node),
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerAttestedNode(resp.GetNode()), nil
}

func (v1 *V1Alpha1) DeleteAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error) {
	resp, err := v1.DataStorePluginClient.DeleteAttestedNode(ctx, &datastorev1.DeleteAttestedNodeRequest{
		SpiffeId: spiffeID,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerAttestedNode(resp.GetNode()), nil
}

func (v1 *V1Alpha1) FetchAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error) {
	resp, err := v1.DataStorePluginClient.FetchAttestedNode(ctx, &datastorev1.FetchAttestedNodeRequest{
		SpiffeId: spiffeID,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerAttestedNode(resp.GetNode()), nil
}

func (v1 *V1Alpha1) ListAttestedNodes(ctx context.Context, req *ds_types.ListAttestedNodesRequest) (*ds_types.ListAttestedNodesResponse, error) {
	dsReq := &datastorev1.ListAttestedNodesRequest{
		ByAttestationType: req.ByAttestationType,
		BySelectors:       fromServerToPluginBySelectors(req.BySelectorMatch),
		ByExpiresBefore:   int64(req.ByExpiresBefore.Unix()),
		Pagination:        fromServerToPluginPagination(req.Pagination),
		FetchSelectors:    req.FetchSelectors,
		ByValidAt:         int64(req.ValidAt.Unix()),
	}

	if req.ByCanReattest != nil {
		dsReq.ByCanReattest = true
		dsReq.CanReattestValue = *req.ByCanReattest
	}

	if req.ByBanned != nil {
		dsReq.ByBanned = true
		dsReq.BannedValue = *req.ByBanned
	}

	resp, err := v1.DataStorePluginClient.ListAttestedNodes(ctx, dsReq)
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	nodes := make([]*common.AttestedNode, len(resp.GetNodes()))
	for i, node := range resp.GetNodes() {
		nodes[i] = fromPluginToServerAttestedNode(node)
	}

	return &ds_types.ListAttestedNodesResponse{
		Nodes:      nodes,
		Pagination: fromPluginToServerPagination(resp.GetPagination()),
	}, nil
}

func (v1 *V1Alpha1) UpdateAttestedNode(ctx context.Context, node *common.AttestedNode, mask *common.AttestedNodeMask) (*common.AttestedNode, error) {
	req := &datastorev1.UpdateAttestedNodeRequest{
		Node: fromServerToPluginAttestedNode(node),
	}

	if mask != nil {
		req.Mask = &datastorev1.AttestedNodeMask{
			AttestationDataType: mask.AttestationDataType,
			CertSerialNumber:    mask.CertSerialNumber,
			CertNotAfter:        mask.CertNotAfter,
			NewCertSerialNumber: mask.NewCertSerialNumber,
			NewCertNotAfter:     mask.NewCertNotAfter,
			CanReattest:         mask.CanReattest,
			AgentVersion:        mask.AgentVersion,
		}
	}

	resp, err := v1.DataStorePluginClient.UpdateAttestedNode(ctx, req)
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerAttestedNode(resp.GetNode()), nil
}

func (v1 *V1Alpha1) PruneAttestedExpiredNodes(ctx context.Context, expiredBefore time.Time, includeNonReattestable bool) error {
	_, err := v1.DataStorePluginClient.PruneAttestedExpiredNodes(ctx, &datastorev1.PruneAttestedExpiredNodesRequest{
		ExpiresBefore:          int64(expiredBefore.Unix()),
		IncludeNonReattestable: includeNonReattestable,
	})

	return v1.WrapErr(err)
}

// Nodes Events
func (v1 *V1Alpha1) ListAttestedNodeEvents(ctx context.Context, req *ds_types.ListAttestedNodeEventsRequest) (*ds_types.ListAttestedNodeEventsResponse, error) {
	resp, err := v1.DataStorePluginClient.ListAttestedNodeEvents(ctx, &datastorev1.ListAttestedNodeEventsRequest{
		GreaterThanEventId: int64(req.GreaterThanEventID),
		LessThanEventId:    int64(req.LessThanEventID),
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	events := make([]ds_types.AttestedNodeEvent, len(resp.GetEvents()))
	for i, event := range resp.GetEvents() {
		events[i] = ds_types.AttestedNodeEvent{
			EventID:  uint(event.GetEventId()),
			SpiffeID: event.GetSpiffeId(),
		}
	}

	return &ds_types.ListAttestedNodeEventsResponse{
		Events: events,
	}, nil
}

func (v1 *V1Alpha1) PruneAttestedNodeEvents(ctx context.Context, olderThan time.Duration) error {
	_, err := v1.DataStorePluginClient.PruneAttestedNodeEvents(ctx, &datastorev1.PruneAttestedNodeEventsRequest{
		OlderThan: int64(olderThan.Seconds()),
	})
	return v1.WrapErr(err)
}

func (v1 *V1Alpha1) FetchAttestedNodeEvent(ctx context.Context, eventID uint) (*ds_types.AttestedNodeEvent, error) {
	resp, err := v1.DataStorePluginClient.FetchAttestedNodeEvent(ctx, &datastorev1.FetchAttestedNodeEventRequest{
		EventId: uint64(eventID),
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return &ds_types.AttestedNodeEvent{
		EventID:  uint(resp.GetEvent().GetEventId()),
		SpiffeID: resp.GetEvent().GetSpiffeId(),
	}, nil
}

func (v1 *V1Alpha1) CreateAttestedNodeEventForTesting(ctx context.Context, event *ds_types.AttestedNodeEvent) error {
	_, err := v1.DataStorePluginClient.CreateAttestedNodeEvent(ctx, &datastorev1.CreateAttestedNodeEventRequest{
		Event: &datastorev1.AttestedNodeEvent{
			EventId:  uint64(event.EventID),
			SpiffeId: event.SpiffeID,
		},
	})

	return v1.WrapErr(err)
}

func (v1 *V1Alpha1) DeleteAttestedNodeEventForTesting(ctx context.Context, eventID uint) error {
	_, err := v1.DataStorePluginClient.DeleteAttestedNodeEvent(ctx, &datastorev1.DeleteAttestedNodeEventRequest{
		EventId: uint64(eventID),
	})

	return v1.WrapErr(err)
}

// Node selectors
func (v1 *V1Alpha1) GetNodeSelectors(ctx context.Context, spiffeID string, dataConsistency ds_types.DataConsistency) ([]*common.Selector, error) {
	resp, err := v1.DataStorePluginClient.GetNodeSelectors(ctx, &datastorev1.GetNodeSelectorsRequest{
		SpiffeId:        spiffeID,
		DataConsistency: fromServerToPluginDataConsistency(dataConsistency),
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerSelectors(resp.GetSelectors()), nil
}

func (v1 *V1Alpha1) ListNodeSelectors(ctx context.Context, req *ds_types.ListNodeSelectorsRequest) (*ds_types.ListNodeSelectorsResponse, error) {
	resp, err := v1.DataStorePluginClient.ListNodeSelectors(ctx, &datastorev1.ListNodeSelectorsRequest{
		ValidAt:         int64(req.ValidAt.Unix()),
		DataConsistency: datastorev1.DataConsistency(req.DataConsistency),
	})

	if err != nil {
		return nil, v1.WrapErr(err)
	}

	sls := make(map[string][]*common.Selector, len(resp.GetSelectors()))
	for _, ns := range resp.GetSelectors() {
		sls[ns.GetSpiffeId()] = fromPluginToServerSelectors(ns.GetSelectors())
	}

	return &ds_types.ListNodeSelectorsResponse{
		Selectors: sls,
	}, nil
}

func (v1 *V1Alpha1) SetNodeSelectors(ctx context.Context, spiffeID string, selectors []*common.Selector) error {
	_, err := v1.DataStorePluginClient.SetNodeSelectors(ctx, &datastorev1.SetNodeSelectorsRequest{
		SpiffeId:  spiffeID,
		Selectors: fromServerToPluginSelectors(selectors),
	})
	return v1.WrapErr(err)
}

// Tokens
func (v1 *V1Alpha1) CreateJoinToken(ctx context.Context, token *ds_types.JoinToken) error {
	_, err := v1.DataStorePluginClient.CreateJoinToken(ctx, &datastorev1.CreateJoinTokenRequest{
		Token:     token.Token,
		ExpiresAt: token.Expiry.Unix(),
	})

	return v1.WrapErr(err)
}

func (v1 *V1Alpha1) DeleteJoinToken(ctx context.Context, token string) error {
	_, err := v1.DataStorePluginClient.DeleteJoinToken(ctx, &datastorev1.DeleteJoinTokenRequest{
		Token: token,
	})

	return v1.WrapErr(err)
}

func (v1 *V1Alpha1) FetchJoinToken(ctx context.Context, token string) (*ds_types.JoinToken, error) {
	resp, err := v1.DataStorePluginClient.FetchJoinToken(ctx, &datastorev1.FetchJoinTokenRequest{
		Token: token,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	if resp.GetToken() == "" {
		return nil, nil
	}

	return &ds_types.JoinToken{
		Token:  resp.GetToken(),
		Expiry: time.Unix(resp.GetExpiresAt(), 0),
	}, nil
}

func (v1 *V1Alpha1) PruneJoinTokens(ctx context.Context, olderThan time.Time) error {
	_, err := v1.DataStorePluginClient.PruneJoinTokens(ctx, &datastorev1.PruneJoinTokensRequest{
		ExpiresBefore: int64(olderThan.Unix()),
	})
	return v1.WrapErr(err)
}

// Federation Relationships
func (v1 *V1Alpha1) CreateFederationRelationship(ctx context.Context, fr *ds_types.FederationRelationship) (*ds_types.FederationRelationship, error) {
	pluginFederationRelationship, err := fromServerToPluginFederationRelationship(fr)
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	resp, err := v1.DataStorePluginClient.CreateFederationRelationship(ctx, &datastorev1.CreateFederationRelationshipRequest{
		Relationship: pluginFederationRelationship,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerFederationRelationship(resp.GetRelationship())
}

func (v1 *V1Alpha1) FetchFederationRelationship(ctx context.Context, td spiffeid.TrustDomain) (*ds_types.FederationRelationship, error) {
	resp, err := v1.DataStorePluginClient.FetchFederationRelationship(ctx, &datastorev1.FetchFederationRelationshipRequest{
		TrustDomainId: td.IDString(),
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerFederationRelationship(resp.GetRelationship())
}

func (v1 *V1Alpha1) ListFederationRelationships(ctx context.Context, req *ds_types.ListFederationRelationshipsRequest) (*ds_types.ListFederationRelationshipsResponse, error) {
	resp, err := v1.DataStorePluginClient.ListFederationRelationships(ctx, &datastorev1.ListFederationRelationshipsRequest{
		Pagination: fromServerToPluginPagination(req.Pagination),
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	relationships := make([]*ds_types.FederationRelationship, len(resp.GetRelationships()))
	for i, r := range resp.GetRelationships() {
		relationships[i], err = fromPluginToServerFederationRelationship(r)
		if err != nil {
			return nil, v1.WrapErr(err)
		}
	}

	return &ds_types.ListFederationRelationshipsResponse{
		FederationRelationships: relationships,
		Pagination:              fromPluginToServerPagination(resp.GetPagination()),
	}, nil
}

func (v1 *V1Alpha1) DeleteFederationRelationship(ctx context.Context, td spiffeid.TrustDomain) error {
	_, err := v1.DataStorePluginClient.DeleteFederationRelationship(ctx, &datastorev1.DeleteFederationRelationshipRequest{
		TrustDomainId: td.IDString(),
	})
	return v1.WrapErr(err)
}

func (v1 *V1Alpha1) UpdateFederationRelationship(ctx context.Context, fr *ds_types.FederationRelationship, mask *types.FederationRelationshipMask) (*ds_types.FederationRelationship, error) {
	pluginFederationRelationship, err := fromServerToPluginFederationRelationship(fr)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, v1.WrapErr(err).Error()) // TODO(tjons): align on this error wrapping! it's nice
	}

	var pluginMask *datastorev1.FederationRelationshipMask
	if mask != nil {
		pluginMask = &datastorev1.FederationRelationshipMask{
			TrustDomainBundle:     mask.TrustDomainBundle,
			BundleEndpointUrl:     mask.BundleEndpointUrl,
			BundleEndpointProfile: mask.BundleEndpointProfile,
		}
	}

	resp, err := v1.DataStorePluginClient.UpdateFederationRelationship(ctx, &datastorev1.UpdateFederationRelationshipRequest{
		Relationship: pluginFederationRelationship,
		Mask:         pluginMask,
	})

	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerFederationRelationship(resp.GetRelationship())
}

// CA Journals
func (v1 *V1Alpha1) SetCAJournal(ctx context.Context, caJournal *ds_types.CAJournal) (*ds_types.CAJournal, error) {
	resp, err := v1.DataStorePluginClient.SetCAJournal(ctx, &datastorev1.SetCAJournalRequest{
		Journal: fromServerToPluginCAJournal(caJournal),
	})

	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerCAJournal(resp.GetJournal()), nil
}

func (v1 *V1Alpha1) FetchCAJournal(ctx context.Context, activeX509AuthorityID string) (*ds_types.CAJournal, error) {
	resp, err := v1.DataStorePluginClient.FetchCAJournal(ctx, &datastorev1.FetchCAJournalRequest{
		ActiveX509AuthorityId: activeX509AuthorityID,
	})

	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return fromPluginToServerCAJournal(resp.GetJournal()), nil
}

func (v1 *V1Alpha1) PruneCAJournals(ctx context.Context, allCAsExpireBefore int64) error {
	_, err := v1.DataStorePluginClient.PruneCAJournals(ctx, &datastorev1.PruneCAJournalsRequest{
		ExpiresBefore: int64(allCAsExpireBefore),
	})

	return v1.WrapErr(err)
}

func (v1 *V1Alpha1) ListCAJournalsForTesting(ctx context.Context) ([]*ds_types.CAJournal, error) {
	resp, err := v1.DataStorePluginClient.ListCAJournals(ctx, &datastorev1.ListCAJournalsRequest{})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	journals := make([]*ds_types.CAJournal, len(resp.GetJournals()))
	for i, j := range resp.GetJournals() {
		journals[i] = fromPluginToServerCAJournal(j)
	}

	return journals, nil
}

func (v1 *V1Alpha1) Close() error {
	// TODO(tjons): This is a no-op right now. There is currently no method to
	// close the plugin client connection as that is managed by the
	// plugin closers in the catalog.
	//
	// It's required to implement the ds_core.Datastore interface.
	return nil
}
