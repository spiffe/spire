package keyvaluestore

import (
	"context"
	"errors"
	"time"

	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/record"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func (ds *DataStore) CountAttestedNodes(ctx context.Context, req *datastore.CountAttestedNodesRequest) (int32, error) {
	if req.BySelectorMatch != nil && len(req.BySelectorMatch.Selectors) == 0 {
		return -1, status.Error(codes.InvalidArgument, "cannot list by empty selectors set")
	}

	listReq := &listAttestedNodes{
		ListAttestedNodesRequest: datastore.ListAttestedNodesRequest{
			ByAttestationType: req.ByAttestationType,
			ByBanned:          req.ByBanned,
			ByExpiresBefore:   req.ByExpiresBefore,
			BySelectorMatch:   req.BySelectorMatch,
			FetchSelectors:    req.FetchSelectors,
			ByCanReattest:     req.ByCanReattest,
		},
	}

	records, _, err := ds.agents.List(ctx, listReq)
	return int32(len(records)), err
}

func (ds *DataStore) CreateAttestedNode(ctx context.Context, in *common.AttestedNode) (*common.AttestedNode, error) {
	if in == nil {
		return nil, kvError.New("invalid request: missing attested node")
	}

	if err := ds.agents.Create(ctx, agentObject{AttestedNode: in, Banned: in.CertSerialNumber == "" && in.NewCertSerialNumber == ""}); err != nil {
		return nil, dsErr(err, "failed to create agent")
	}

	if err := ds.createAttestedNodeEvent(ctx, &datastore.AttestedNodeEvent{
		SpiffeID: in.SpiffeId,
	}); err != nil {
		return nil, err
	}

	return in, nil
}

func (ds *DataStore) DeleteAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error) {
	r, err := ds.agents.Get(ctx, spiffeID)

	if err != nil {
		return nil, dsErr(err, "failed to delete agent")
	}

	if err := ds.agents.Delete(ctx, spiffeID); err != nil {
		return nil, dsErr(err, "failed to delete agent")
	}

	if err = ds.createAttestedNodeEvent(ctx, &datastore.AttestedNodeEvent{
		SpiffeID: spiffeID,
	}); err != nil {
		return nil, err
	}

	return r.Object.AttestedNode, nil
}

func (ds *DataStore) FetchAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error) {
	r, err := ds.agents.Get(ctx, spiffeID)
	switch {
	case err == nil:
		return r.Object.AttestedNode, nil
	case errors.Is(err, record.ErrNotFound):
		return nil, nil
	default:
		return nil, dsErr(err, "failed to agent bundle")
	}
}

func (ds *DataStore) ListAttestedNodes(ctx context.Context, req *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
	records, cursor, err := ds.agents.List(ctx, &listAttestedNodes{
		ListAttestedNodesRequest: *req,
	})
	if err != nil {
		return nil, err
	}
	resp := &datastore.ListAttestedNodesResponse{
		Pagination: newPagination(req.Pagination, cursor),
	}
	resp.Nodes = make([]*common.AttestedNode, 0, len(records))
	for _, record := range records {
		resp.Nodes = append(resp.Nodes, record.Object.AttestedNode)
	}
	return resp, nil
}

func (ds *DataStore) UpdateAttestedNode(ctx context.Context, newAgent *common.AttestedNode, mask *common.AttestedNodeMask) (*common.AttestedNode, error) {
	record, err := ds.agents.Get(ctx, newAgent.SpiffeId)
	if err != nil {
		return nil, dsErr(err, "failed to update agent")
	}
	existing := record.Object

	if mask == nil {
		mask = protoutil.AllTrueCommonAgentMask
	}

	if mask.CertNotAfter {
		existing.CertNotAfter = newAgent.CertNotAfter
	}
	if mask.CertSerialNumber {
		existing.CertSerialNumber = newAgent.CertSerialNumber
	}
	if mask.NewCertNotAfter {
		existing.NewCertNotAfter = newAgent.NewCertNotAfter
	}
	if mask.NewCertSerialNumber {
		existing.NewCertSerialNumber = newAgent.NewCertSerialNumber
	}
	if mask.CanReattest {
		existing.CanReattest = newAgent.CanReattest
	}
	/*if mask.AttestationDataType {
		existing.AttestationDataType = newAgent.AttestationDataType
	}*/

	existing.Banned = existing.CertSerialNumber == "" && existing.NewCertSerialNumber == ""

	if err := ds.agents.Update(ctx, existing, record.Metadata.Revision); err != nil {
		return nil, dsErr(err, "failed to update agent")
	}

	if err = ds.createAttestedNodeEvent(ctx, &datastore.AttestedNodeEvent{
		SpiffeID: newAgent.SpiffeId,
	}); err != nil {
		return nil, err
	}

	return existing.AttestedNode, nil
}

func (ds *DataStore) GetNodeSelectors(ctx context.Context, spiffeID string, dataConsistency datastore.DataConsistency) ([]*common.Selector, error) {
	record, err := ds.agents.Get(ctx, spiffeID)
	if err != nil {
		return nil, dsErr(err, "failed to get agent selectors")
	}
	return record.Object.Selectors, nil
}

func (ds *DataStore) ListNodeSelectors(ctx context.Context, req *datastore.ListNodeSelectorsRequest) (*datastore.ListNodeSelectorsResponse, error) {
	records, _, err := ds.agents.List(ctx, &listAttestedNodes{
		ByExpiresAfter: req.ValidAt,
	})
	if err != nil {
		return nil, err
	}
	resp := &datastore.ListNodeSelectorsResponse{
		Selectors: map[string][]*common.Selector{},
	}
	for _, record := range records {
		resp.Selectors[record.Object.SpiffeId] = record.Object.Selectors
	}
	return resp, nil
}

func (ds *DataStore) SetNodeSelectors(ctx context.Context, spiffeID string, selectors []*common.Selector) error {
	agent, err := ds.agents.Get(ctx, spiffeID)
	switch {
	case err != nil:
		return err
	case agent == nil:
		_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{SpiffeId: spiffeID, Selectors: selectors})
		return err
	default:
		existing := agent.Object
		existing.Selectors = selectors

		if err := ds.agents.Update(ctx, existing, agent.Metadata.Revision); err != nil {
			return dsErr(err, "failed to update agent")
		}

		if err = ds.createAttestedNodeEvent(ctx, &datastore.AttestedNodeEvent{
			SpiffeID: spiffeID,
		}); err != nil {
			return err
		}
		return err
	}
}

type agentCodec struct{}

func (agentCodec) Marshal(in *agentObject) (string, []byte, error) {
	out, err := proto.Marshal(in.AttestedNode)
	if err != nil {
		return "", nil, err
	}
	return in.AttestedNode.SpiffeId, out, nil
}

func (agentCodec) Unmarshal(in []byte, out *agentObject) error {
	attestedNode := new(common.AttestedNode)
	if err := proto.Unmarshal(in, attestedNode); err != nil {
		return err
	}
	out.AttestedNode = attestedNode
	return nil
}

type agentObject struct {
	*common.AttestedNode
	Banned bool
}

func (r agentObject) Key() string { return r.AttestedNode.SpiffeId }

type listAttestedNodes struct {
	datastore.ListAttestedNodesRequest
	ByExpiresAfter time.Time
}

type agentIndex struct {
	attestationType record.UnaryIndex[string]
	banned          record.UnaryIndex[bool]
	expiresAt       record.UnaryIndex[int64]
	selectors       record.MultiIndex[*common.Selector]
	canReattest     record.UnaryIndex[bool]
}

func (idx *agentIndex) SetUp() {
	idx.attestationType.SetQuerry("Object.AttestationDataType")
	idx.banned.SetQuerry("Object.Banned")
	idx.expiresAt.SetQuerry("Object.CertNotAfter")
	idx.selectors.SetQuerry("Object.Selectors")
	idx.canReattest.SetQuerry("Object.CanReattest")
}

func (idx *agentIndex) List(req *listAttestedNodes) (*keyvalue.ListObject, error) {
	cursor, limit, err := getPaginationParams(req.Pagination)
	if err != nil {
		return nil, err
	}

	if req.BySelectorMatch != nil && len(req.BySelectorMatch.Selectors) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot list by empty selectors set")
	}

	list := new(keyvalue.ListObject)

	list.Cursor = cursor
	list.Limit = limit

	if req.ByAttestationType != "" {
		list.Filters = append(list.Filters, idx.attestationType.EqualTo(req.ByAttestationType))
	}
	if req.ByBanned != nil {
		list.Filters = append(list.Filters, idx.banned.EqualTo(*req.ByBanned))
	}
	if !req.ByExpiresBefore.IsZero() {
		list.Filters = append(list.Filters, idx.expiresAt.LessThan(req.ByExpiresBefore.Unix()))
	}
	if !req.ByExpiresAfter.IsZero() {
		list.Filters = append(list.Filters, idx.expiresAt.GreaterThan(req.ByExpiresAfter.Unix()))
	}
	if req.BySelectorMatch != nil {
		list.Filters = append(list.Filters, idx.selectors.Matching(req.BySelectorMatch.Selectors, matchBehavior(req.BySelectorMatch.Match)))
	}
	if req.ByCanReattest != nil {
		list.Filters = append(list.Filters, idx.canReattest.EqualTo(*req.ByCanReattest))
	}

	return list, nil
}
