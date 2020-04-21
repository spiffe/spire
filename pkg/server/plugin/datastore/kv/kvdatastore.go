package kv

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/gogo/protobuf/proto"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/internal/protokv"
	"github.com/spiffe/spire/internal/protokv/mysqlkv"
	"github.com/spiffe/spire/internal/protokv/sqlite3kv"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	PluginName = "kv"

	// These constants CANNOT CHANGE in value. They are used to namespace the
	// keys in the key value store.
	bundleMessageID        = 1
	attestedNodeMessageID  = 2
	joinTokenMessageID     = 3
	entryMessageID         = 4
	nodeSelectorsMessageID = 5
)

var (
	bundleTrustDomainIdField = protokv.StringField(1)

	attestedNodeSpiffeIdField = protokv.StringField(1)

	joinTokenTokenField = protokv.StringField(1)

	selectorTypeField  = protokv.StringField(1)
	selectorValueField = protokv.StringField(2)

	entrySelectorsField = protokv.RepeatedSet(protokv.MessageField(1, selectorTypeField, selectorValueField))
	entryParentIdField  = protokv.StringField(2)
	entrySpiffeIdField  = protokv.StringField(3)
	entryEntryIdField   = protokv.StringField(6)
	entryTtlField       = protokv.Int32Field(4)

	nodeSelectorsSpiffeIdField = protokv.StringField(1)

	bundleMessage = protokv.Message{
		ID:         bundleMessageID,
		PrimaryKey: bundleTrustDomainIdField,
	}

	attestedNodeMessage = protokv.Message{
		ID:         attestedNodeMessageID,
		PrimaryKey: attestedNodeSpiffeIdField,
	}

	joinTokenMessage = protokv.Message{
		ID:         joinTokenMessageID,
		PrimaryKey: joinTokenTokenField,
	}

	entryMessage = protokv.Message{
		ID:         entryMessageID,
		PrimaryKey: entryEntryIdField,
		Indices: []protokv.Field{
			entrySelectorsField,
			entryParentIdField,
			entrySpiffeIdField,
			entryTtlField,
		},
	}

	nodeSelectorsMessage = protokv.Message{
		ID:         nodeSelectorsMessageID,
		PrimaryKey: nodeSelectorsSpiffeIdField,
	}
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(PluginName,
		datastore.PluginServer(p),
	)
}

type Config struct {
	DatabaseType     string `hcl:"database_type" json:"database_type"`
	ConnectionString string `hcl:"connection_string" json:"connection_string"`
}

type Plugin struct {
	datastore.Plugin

	kv            protokv.KV
	bundles       *protokv.Store
	attestedNodes *protokv.Store
	joinTokens    *protokv.Store
	entries       *protokv.Store
	nodeSelectors *protokv.Store
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) FetchBundle(ctx context.Context, req *datastore.FetchBundleRequest) (*datastore.FetchBundleResponse, error) {
	in := &common.Bundle{
		TrustDomainId: req.TrustDomainId,
	}
	out := new(common.Bundle)
	ok, err := doRead(ctx, p.bundles, in, out)
	switch {
	case err != nil:
		return nil, err
	case ok:
		return &datastore.FetchBundleResponse{Bundle: out}, nil
	default:
		return &datastore.FetchBundleResponse{}, nil
	}
}

func (p *Plugin) ListBundles(ctx context.Context, req *datastore.ListBundlesRequest) (*datastore.ListBundlesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) CreateBundle(ctx context.Context, req *datastore.CreateBundleRequest) (*datastore.CreateBundleResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) UpdateBundle(ctx context.Context, req *datastore.UpdateBundleRequest) (*datastore.UpdateBundleResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) SetBundle(ctx context.Context, req *datastore.SetBundleRequest) (*datastore.SetBundleResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) AppendBundle(ctx context.Context, req *datastore.AppendBundleRequest) (*datastore.AppendBundleResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) PruneBundle(ctx context.Context, req *datastore.PruneBundleRequest) (*datastore.PruneBundleResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) DeleteBundle(ctx context.Context, req *datastore.DeleteBundleRequest) (*datastore.DeleteBundleResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) FetchAttestedNode(ctx context.Context, req *datastore.FetchAttestedNodeRequest) (*datastore.FetchAttestedNodeResponse, error) {
	in := &common.AttestedNode{SpiffeId: req.SpiffeId}
	out := new(common.AttestedNode)
	ok, err := doRead(ctx, p.attestedNodes, in, out)
	switch {
	case err != nil:
		return nil, err
	case ok:
		return &datastore.FetchAttestedNodeResponse{Node: out}, nil
	default:
		return &datastore.FetchAttestedNodeResponse{}, nil
	}
}

func (p *Plugin) ListAttestedNodes(ctx context.Context, req *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
	// TODO: protokv does not have support yet for subsets of indices, i.e., what
	// would be needed to implement ByExpiresFor
	if req.ByExpiresBefore != nil {
		return nil, status.Error(codes.Unimplemented, "by-expires-before support not implemented")
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) CreateAttestedNode(ctx context.Context, req *datastore.CreateAttestedNodeRequest) (*datastore.CreateAttestedNodeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) UpdateAttestedNode(ctx context.Context, req *datastore.UpdateAttestedNodeRequest) (*datastore.UpdateAttestedNodeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) DeleteAttestedNode(ctx context.Context, req *datastore.DeleteAttestedNodeRequest) (*datastore.DeleteAttestedNodeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) FetchJoinToken(ctx context.Context, req *datastore.FetchJoinTokenRequest) (*datastore.FetchJoinTokenResponse, error) {
	in := &datastore.JoinToken{Token: req.Token}
	out := new(datastore.JoinToken)
	ok, err := doRead(ctx, p.joinTokens, in, out)
	switch {
	case err != nil:
		return nil, err
	case ok:
		return &datastore.FetchJoinTokenResponse{JoinToken: out}, nil
	default:
		return &datastore.FetchJoinTokenResponse{}, nil
	}
}

func (p *Plugin) CreateJoinToken(ctx context.Context, req *datastore.CreateJoinTokenRequest) (*datastore.CreateJoinTokenResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) PruneJoinTokens(ctx context.Context, req *datastore.PruneJoinTokensRequest) (*datastore.PruneJoinTokensResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) DeleteJoinToken(ctx context.Context, req *datastore.DeleteJoinTokenRequest) (*datastore.DeleteJoinTokenResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) FetchRegistrationEntry(ctx context.Context, req *datastore.FetchRegistrationEntryRequest) (*datastore.FetchRegistrationEntryResponse, error) {
	in := &common.RegistrationEntry{
		EntryId: req.EntryId,
	}
	out := new(common.RegistrationEntry)
	ok, err := doRead(ctx, p.entries, in, out)
	switch {
	case err != nil:
		return nil, err
	case ok:
		return &datastore.FetchRegistrationEntryResponse{Entry: out}, nil
	default:
		return &datastore.FetchRegistrationEntryResponse{}, nil
	}
}

func (p *Plugin) ListRegistrationEntries(ctx context.Context, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	if req.Pagination != nil && req.Pagination.PageSize == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}
	if req.BySelectors != nil && len(req.BySelectors.Selectors) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot list by empty selector set")
	}

	type selectorKey struct {
		Type  string
		Value string
	}
	var selectorSet map[selectorKey]struct{}
	if req.BySelectors != nil {
		selectorSet = make(map[selectorKey]struct{})
		for _, s := range req.BySelectors.Selectors {
			selectorSet[selectorKey{Type: s.Type, Value: s.Value}] = struct{}{}
		}
	}

	for {
		resp, err := p.listRegistrationEntriesOnce(ctx, req)
		if err != nil {
			return nil, err
		}

		// Not filtering by selectors? return what we've got
		if req.BySelectors == nil ||
			len(req.BySelectors.Selectors) == 0 {
			return resp, nil
		}

		matching := make([]*common.RegistrationEntry, 0, len(resp.Entries))
		for _, entry := range resp.Entries {
			matches := true
			switch req.BySelectors.Match {
			case datastore.BySelectors_MATCH_SUBSET:
				for _, s := range entry.Selectors {
					if _, ok := selectorSet[selectorKey{Type: s.Type, Value: s.Value}]; !ok {
						matches = false
						break
					}
				}
			case datastore.BySelectors_MATCH_EXACT:
				// The listing currently contains all entries that have AT LEAST
				// the provided selectors. We only want those that match exactly.
				matches = len(entry.Selectors) == len(selectorSet)
			}
			if matches {
				matching = append(matching, entry)
			}
		}
		resp.Entries = matching

		if len(resp.Entries) > 0 || resp.Pagination == nil || len(resp.Pagination.Token) == 0 {
			return resp, nil
		}

		req.Pagination = resp.Pagination
	}
}

func (p *Plugin) CreateRegistrationEntry(ctx context.Context,
	req *datastore.CreateRegistrationEntryRequest) (*datastore.CreateRegistrationEntryResponse, error) {

	var err error
	req.Entry.EntryId, err = newRegistrationEntryID()
	if err != nil {
		return nil, errs.Wrap(err)
	}

	value, err := proto.Marshal(req.Entry)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	if err := p.entries.Create(ctx, value); err != nil {
		return nil, errs.Wrap(err)
	}

	return &datastore.CreateRegistrationEntryResponse{
		Entry: req.Entry,
	}, nil
}

func (p *Plugin) GetNodeSelectors(ctx context.Context, req *datastore.GetNodeSelectorsRequest) (*datastore.GetNodeSelectorsResponse, error) {
	in := &datastore.NodeSelectors{SpiffeId: req.SpiffeId}
	out := new(datastore.NodeSelectors)
	ok, err := doRead(ctx, p.nodeSelectors, in, out)
	switch {
	case err != nil:
		return nil, err
	case ok:
		return &datastore.GetNodeSelectorsResponse{Selectors: out}, nil
	default:
		return &datastore.GetNodeSelectorsResponse{}, nil
	}
}

func (p *Plugin) SetNodeSelectors(ctx context.Context, req *datastore.SetNodeSelectorsRequest) (*datastore.SetNodeSelectorsResponse, error) {
	value, err := proto.Marshal(req.Selectors)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if err := p.nodeSelectors.Upsert(ctx, value); err != nil {
		return nil, errs.Wrap(err)
	}
	return &datastore.SetNodeSelectorsResponse{}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, err
	}

	var kv protokv.KV
	var err error
	switch strings.ToLower(config.DatabaseType) {
	case "sqlite", "sqlite3":
		kv, err = sqlite3kv.Open(config.ConnectionString)
	case "mysql":
		kv, err = mysqlkv.Open(config.ConnectionString)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported database type %s", config.DatabaseType)
	}
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// TODO: reconfiguration
	p.kv = kv
	p.bundles = protokv.NewStore(kv, &bundleMessage)
	p.attestedNodes = protokv.NewStore(kv, &attestedNodeMessage)
	p.joinTokens = protokv.NewStore(kv, &joinTokenMessage)
	p.entries = protokv.NewStore(kv, &entryMessage)
	p.nodeSelectors = protokv.NewStore(kv, &nodeSelectorsMessage)

	return &spi.ConfigureResponse{}, nil
}

func (p *Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *Plugin) closeDB() error {
	return p.kv.Close()
}

func (p *Plugin) listRegistrationEntriesOnce(ctx context.Context,
	req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {

	msg := new(common.RegistrationEntry)

	var fields []protokv.Field
	var setOps []protokv.SetOp
	if req.BySelectors != nil {
		msg.Selectors = req.BySelectors.Selectors
		switch req.BySelectors.Match {
		case datastore.BySelectors_MATCH_SUBSET:
			fields = append(fields, entrySelectorsField)
			setOps = append(setOps, protokv.SetUnion)
		case datastore.BySelectors_MATCH_EXACT:
			fields = append(fields, entrySelectorsField)
			setOps = append(setOps, protokv.SetIntersect)
		default:
			return nil, errs.New("unhandled match behavior %q", req.BySelectors.Match)
		}
	}
	if req.ByParentId != nil {
		msg.ParentId = req.ByParentId.Value
		fields = append(fields, entryParentIdField)
		setOps = append(setOps, protokv.SetDefault)
	}
	if req.BySpiffeId != nil {
		msg.SpiffeId = req.BySpiffeId.Value
		fields = append(fields, entrySpiffeIdField)
		setOps = append(setOps, protokv.SetDefault)
	}

	var token []byte
	var limit int
	var err error
	if req.Pagination != nil {
		if len(req.Pagination.Token) > 0 {
			token, err = decodePaginationToken(req.Pagination.Token)
			if err != nil {
				return nil, err
			}
		}
		limit = int(req.Pagination.PageSize)
	}

	var values [][]byte
	if len(fields) == 0 {
		values, token, err = p.entries.Page(ctx, token, limit)
	} else {
		msgBytes, err := proto.Marshal(msg)
		if err != nil {
			return nil, errs.Wrap(err)
		}
		values, token, err = p.entries.PageIndex(ctx, msgBytes, token, limit, fields, setOps)
	}
	if err != nil {
		return nil, errs.Wrap(err)
	}

	resp := new(datastore.ListRegistrationEntriesResponse)
	for _, value := range values {
		entry := new(common.RegistrationEntry)
		if err := proto.Unmarshal(value, entry); err != nil {
			return nil, errs.Wrap(err)
		}
		resp.Entries = append(resp.Entries, entry)
	}
	if req.Pagination != nil {
		resp.Pagination = &datastore.Pagination{
			Token: encodePaginationToken(token),
		}
	}
	return resp, nil
}

func doRead(ctx context.Context, store *protokv.Store, in proto.Message, out proto.Message) (bool, error) {
	inBytes, err := proto.Marshal(in)
	if err != nil {
		return false, errs.Wrap(err)
	}
	outBytes, err := store.Read(ctx, inBytes)
	if err != nil {
		if protokv.NotFound.Has(err) {
			return false, nil
		}
		return false, errs.Wrap(err)
	}
	if err := proto.Unmarshal(outBytes, out); err != nil {
		return false, errs.Wrap(err)
	}
	return true, nil
}

func newRegistrationEntryID() (string, error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func encodePaginationToken(token []byte) string {
	return base64.RawURLEncoding.EncodeToString(token)
}

func decodePaginationToken(token string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(token)
}
