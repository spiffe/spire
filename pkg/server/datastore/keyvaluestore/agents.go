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

// CountAttestedNodes counts all attested nodes
func (ds *DataStore) CountAttestedNodes(ctx context.Context, req *datastore.CountAttestedNodesRequest) (int32, error) {
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

// CreateAttestedNode stores the given attested node
func (ds *DataStore) CreateAttestedNode(ctx context.Context, in *common.AttestedNode) (*common.AttestedNode, error) {
	if in == nil {
		return nil, kvError.New("invalid request: missing attested node")
	}

	if err := ds.agents.Create(ctx, agentObject{Node: in, Banned: in.CertSerialNumber == "" && in.NewCertSerialNumber == ""}); err != nil {
		switch {
		case errors.Is(err, record.ErrExists):

			oldAgent, err := ds.agents.Get(ctx, in.SpiffeId)
			if err != nil {
				return nil, dsErr(err, "failed to retrieve agent")
			}

			existing := oldAgent.Object.Node
			emptyNode := &common.AttestedNode{SpiffeId: in.SpiffeId, Selectors: copySelectors(in.Selectors)}

			// If the node only contains selectors, it was most likely created by SetNodeSelectors.
			// That's why we update its contents.
			if existing.String() == emptyNode.String() {
				_, err = ds.updateAttestedNode(ctx, in, nil, oldAgent)

				if err != nil {
					return nil, dsErr(err, "failed to create agent")
				}

				return in, nil
			} else {
				return nil, dsErr(record.ErrExists, "failed to create agent")
			}
		default:
			return nil, dsErr(err, "failed to create agent")
		}
	}

	if err := ds.createAttestedNodeEvent(ctx, &datastore.AttestedNodeEvent{
		SpiffeID: in.SpiffeId,
	}); err != nil {
		return nil, err
	}

	return in, nil
}

// DeleteAttestedNode deletes the given attested node and the associated node selectors.
func (ds *DataStore) DeleteAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error) {
	r, err := ds.agents.Get(ctx, spiffeID)

	if err != nil {
		return nil, dsErr(err, "datastore-keyvalue")
	}

	if err := ds.agents.Delete(ctx, spiffeID); err != nil {
		return nil, dsErr(err, "datastore-keyvalue")
	}

	if err = ds.createAttestedNodeEvent(ctx, &datastore.AttestedNodeEvent{
		SpiffeID: spiffeID,
	}); err != nil {
		return nil, err
	}

	r.Object.Node.Selectors = nil
	return r.Object.Node, nil
}

// FetchAttestedNode fetches an existing attested node by SPIFFE ID
func (ds *DataStore) FetchAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error) {
	r, err := ds.agents.Get(ctx, spiffeID)
	switch {
	case err == nil:
		return r.Object.Node, nil
	case errors.Is(err, record.ErrNotFound):
		return nil, nil
	default:
		return nil, dsErr(err, "failed to agent bundle")
	}
}

// ListAttestedNodes lists all attested nodes (pagination available)
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
		if !req.FetchSelectors {
			record.Object.Node.Selectors = []*common.Selector{}
		}
		resp.Nodes = append(resp.Nodes, record.Object.Node)
	}
	return resp, nil
}

// UpdateAttestedNode updates the given node's cert serial and expiration.
func (ds *DataStore) UpdateAttestedNode(ctx context.Context, newAgent *common.AttestedNode, mask *common.AttestedNodeMask) (*common.AttestedNode, error) {
	oldAgent, err := ds.agents.Get(ctx, newAgent.SpiffeId)
	if err != nil {
		return nil, dsErr(err, "datastore-keyvalue")
	}

	return ds.updateAttestedNode(ctx, newAgent, mask, oldAgent)
}

func (ds *DataStore) updateAttestedNode(ctx context.Context, newAgent *common.AttestedNode, mask *common.AttestedNodeMask, oldAgent *record.Record[agentObject]) (*common.AttestedNode, error) {
	existing := oldAgent.Object

	if mask == nil {
		mask = protoutil.AllTrueCommonAgentMask
	}

	if mask.CertNotAfter {
		existing.Node.CertNotAfter = newAgent.CertNotAfter
	}
	if mask.CertSerialNumber {
		existing.Node.CertSerialNumber = newAgent.CertSerialNumber
	}
	if mask.NewCertNotAfter {
		existing.Node.NewCertNotAfter = newAgent.NewCertNotAfter
	}
	if mask.NewCertSerialNumber {
		existing.Node.NewCertSerialNumber = newAgent.NewCertSerialNumber
	}
	if mask.CanReattest {
		existing.Node.CanReattest = newAgent.CanReattest
	}
	/*if mask.AttestationDataType {
		existing.AttestationDataType = newAgent.AttestationDataType
	}*/

	if err := ds.agents.Update(ctx, existing, oldAgent.Metadata.Revision); err != nil {
		return nil, dsErr(err, "datastore-keyvalue")
	}

	if err := ds.createAttestedNodeEvent(ctx, &datastore.AttestedNodeEvent{
		SpiffeID: newAgent.SpiffeId,
	}); err != nil {
		return nil, err
	}

	return existing.Node, nil
}

// GetNodeSelectors gets node (agent) selectors by SPIFFE ID
func (ds *DataStore) GetNodeSelectors(ctx context.Context, spiffeID string, dataConsistency datastore.DataConsistency) ([]*common.Selector, error) {
	r, err := ds.agents.Get(ctx, spiffeID)
	switch {
	case errors.Is(err, record.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, dsErr(err, "failed to get agent selectors")
	default:
		return r.Object.Node.Selectors, nil
	}
}

// ListNodeSelectors gets node (agent) selectors by SPIFFE ID
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
		resp.Selectors[record.Object.Node.SpiffeId] = record.Object.Node.Selectors
	}
	return resp, nil
}

// SetNodeSelectors sets node (agent) selectors by SPIFFE ID, deleting old selectors first
func (ds *DataStore) SetNodeSelectors(ctx context.Context, spiffeID string, selectors []*common.Selector) error {
	agent, err := ds.agents.Get(ctx, spiffeID)
	switch {
	case errors.Is(err, record.ErrNotFound):
		_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{SpiffeId: spiffeID, Selectors: copySelectors(selectors)})
		return err
	case err != nil:
		return err
	default:
		existing := agent.Object
		existing.Node.Selectors = copySelectors(selectors)

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

// Helper function to copy the selectors with right "sizeCache" value
func copySelectors(selectors []*common.Selector) []*common.Selector {
	copiedSelectors := make([]*common.Selector, len(selectors))
	for i, selector := range selectors {
		copiedSelectors[i] = &common.Selector{
			Type:  selector.Type,
			Value: selector.Value,
		}
	}
	return copiedSelectors
}

type agentCodec struct{}

func (agentCodec) Marshal(in *agentObject) (string, []byte, error) {
	out, err := proto.Marshal(in.Node)
	if err != nil {
		return "", nil, err
	}
	return in.Node.SpiffeId, out, nil
}

func (agentCodec) Unmarshal(in []byte, out *agentObject) error {
	attestedNode := new(common.AttestedNode)
	if err := proto.Unmarshal(in, attestedNode); err != nil {
		return err
	}
	out.Node = attestedNode
	out.Banned = attestedNode.CertSerialNumber == "" && attestedNode.NewCertSerialNumber == ""
	return nil
}

type agentObject struct {
	Node   *common.AttestedNode
	Banned bool
}

func (r agentObject) Key() string { return r.Node.SpiffeId }

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
	idx.attestationType.SetQuery("Object.Node.AttestationDataType")
	idx.banned.SetQuery("Object.Banned")
	idx.expiresAt.SetQuery("Object.Node.CertNotAfter")
	idx.selectors.SetQuery("Object.Node.Selectors")
	idx.canReattest.SetQuery("Object.Node.CanReattest")
}

func (c *agentIndex) Get(obj *record.Record[agentObject]) {
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
