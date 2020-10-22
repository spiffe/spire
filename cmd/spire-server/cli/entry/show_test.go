package entry

import (
	"testing"

	"github.com/spiffe/spire/cmd/spire-server/util"
	commonutil "github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/suite"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

func TestShowTestSuite(t *testing.T) {
	suite.Run(t, new(ShowTestSuite))
}

type ShowTestSuite struct {
	suite.Suite

	cli        *ShowCLI
	fakeServer *fakeEntryServer
	fakeClient util.ServerClient
}

func (s *ShowTestSuite) SetupTest() {
	s.startFakeEntryServer()
	cli := &ShowCLI{
		Config:  new(ShowConfig),
		Client:  s.fakeClient.NewEntryClient(),
		Entries: []*types.Entry{},
	}
	s.cli = cli
}

func (s ShowTestSuite) TearDownTest() {
	s.fakeClient.Release()
}

func (s *ShowTestSuite) TestRunWithEntryID() {
	entryID := "123456"

	args := []string{
		"-entryID",
		entryID,
	}

	s.fakeServer.expGetEntryReq = &entry.GetEntryRequest{Id: entryID}
	s.fakeServer.getEntryResp = s.registrationEntries(1)[0]

	s.Require().Zero(s.cli.Run(args))
	s.Assert().Equal(s.registrationEntries(1), s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithParentID() {
	entries := s.registrationEntries(2)

	args := []string{
		"-parentID",
		protoToIDString(entries[0].ParentId),
	}

	s.fakeServer.expListEntriesReq = &entry.ListEntriesRequest{
		Filter: &entry.ListEntriesRequest_Filter{
			ByParentId: entries[0].ParentId,
		},
	}
	s.fakeServer.listEntriesResp = &entry.ListEntriesResponse{Entries: entries}

	s.Require().Zero(s.cli.Run(args))

	commonutil.SortTypesEntries(entries)
	spiretest.RequireProtoListEqual(s.T(), entries, s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithSpiffeID() {
	entries := s.registrationEntries(1)

	args := []string{
		"-spiffeID",
		protoToIDString(entries[0].SpiffeId),
	}

	s.fakeServer.expListEntriesReq = &entry.ListEntriesRequest{
		Filter: &entry.ListEntriesRequest_Filter{
			BySpiffeId: entries[0].SpiffeId,
		},
	}
	s.fakeServer.listEntriesResp = &entry.ListEntriesResponse{Entries: entries}

	s.Require().Zero(s.cli.Run(args))
	spiretest.RequireProtoListEqual(s.T(), entries, s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithSelector() {
	entries := s.registrationEntries(2)

	args := []string{
		"-selector",
		"foo:bar",
	}

	s.fakeServer.expListEntriesReq = &entry.ListEntriesRequest{
		Filter: &entry.ListEntriesRequest_Filter{
			BySelectors: &types.SelectorMatch{
				Match: types.SelectorMatch_MATCH_SUBSET,
				Selectors: []*types.Selector{
					{Type: "foo", Value: "bar"},
				},
			},
		},
	}

	s.fakeServer.listEntriesResp = &entry.ListEntriesResponse{
		Entries: entries,
	}

	s.Require().Zero(s.cli.Run(args))

	commonutil.SortTypesEntries(entries)
	spiretest.RequireProtoListEqual(s.T(), entries, s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithSelectors() {
	entries := s.registrationEntries(2)

	args := []string{
		"-selector",
		"foo:bar",
		"-selector",
		"bar:baz",
	}

	s.fakeServer.expListEntriesReq = &entry.ListEntriesRequest{
		Filter: &entry.ListEntriesRequest_Filter{
			BySelectors: &types.SelectorMatch{
				Match: types.SelectorMatch_MATCH_SUBSET,
				Selectors: []*types.Selector{
					{Type: "foo", Value: "bar"},
					{Type: "bar", Value: "baz"},
				},
			},
		},
	}

	s.fakeServer.listEntriesResp = &entry.ListEntriesResponse{Entries: entries[1:2]}

	s.Require().Zero(s.cli.Run(args))

	commonutil.SortTypesEntries(s.fakeServer.listEntriesResp.Entries)
	spiretest.RequireProtoListEqual(s.T(), s.fakeServer.listEntriesResp.Entries, s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithParentIDAndSelectors() {
	entries := s.registrationEntries(4)[2:4]

	args := []string{
		"-parentID",
		protoToIDString(entries[0].ParentId),
		"-selector",
		"bar:baz",
	}

	s.fakeServer.expListEntriesReq = &entry.ListEntriesRequest{
		Filter: &entry.ListEntriesRequest_Filter{
			ByParentId: entries[0].ParentId,
			BySelectors: &types.SelectorMatch{
				Match: types.SelectorMatch_MATCH_SUBSET,
				Selectors: []*types.Selector{
					{Type: "bar", Value: "baz"},
				},
			},
		},
	}

	s.fakeServer.listEntriesResp = &entry.ListEntriesResponse{Entries: entries[0:1]}

	s.Require().Zero(s.cli.Run(args))

	spiretest.RequireProtoListEqual(s.T(), s.fakeServer.listEntriesResp.Entries, s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithFederatesWith() {
	s.fakeServer.expListEntriesReq = &entry.ListEntriesRequest{
		Filter: &entry.ListEntriesRequest_Filter{},
	}
	s.fakeServer.listEntriesResp = &entry.ListEntriesResponse{
		Entries: s.registrationEntries(4),
	}

	args := []string{
		"-federatesWith",
		"spiffe://domain.test",
	}

	s.Require().Zero(s.cli.Run(args))

	expectEntries := s.registrationEntries(4)[2:3]
	spiretest.RequireProtoListEqual(s.T(), expectEntries, s.cli.Entries)
}

// registrationEntries returns `count` registration entry records. At most 4.
func (ShowTestSuite) registrationEntries(count int) []*types.Entry {
	selectors := []*types.Selector{
		{Type: "foo", Value: "bar"},
		{Type: "bar", Value: "baz"},
		{Type: "baz", Value: "bat"},
	}
	entries := []*types.Entry{
		{
			ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/father"},
			SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/son"},
			Selectors: []*types.Selector{selectors[0]},
			Id:        "00000000-0000-0000-0000-000000000000",
		},
		{
			ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/father"},
			SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/daughter"},
			Selectors: []*types.Selector{selectors[0], selectors[1]},
			Id:        "00000000-0000-0000-0000-000000000001",
		},
		{
			ParentId:      &types.SPIFFEID{TrustDomain: "example.org", Path: "/mother"},
			SpiffeId:      &types.SPIFFEID{TrustDomain: "example.org", Path: "/daughter"},
			Selectors:     []*types.Selector{selectors[1], selectors[2]},
			Id:            "00000000-0000-0000-0000-000000000002",
			FederatesWith: []string{"spiffe://domain.test"},
		},
		{
			ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/mother"},
			SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/son"},
			Selectors: []*types.Selector{selectors[2]},
			Id:        "00000000-0000-0000-0000-000000000003",
		},
	}

	e := []*types.Entry{}
	for i := 0; i < count; i++ {
		e = append(e, entries[i])
	}

	return e
}

func (s *ShowTestSuite) startFakeEntryServer() {
	s.fakeServer = &fakeEntryServer{
		t: s.T(),
	}
	socketPath := spiretest.StartGRPCSocketServerOnTempSocket(s.T(), func(srv *grpc.Server) {
		entry.RegisterEntryServer(srv, s.fakeServer)
	})
	srvCl, err := util.NewServerClient(socketPath)
	if err != nil {
		s.FailNow("Error creating new registration client: %v", err)
	}
	s.fakeClient = srvCl
}

type fakeEntryServer struct {
	*entry.UnimplementedEntryServer

	t                 *testing.T
	expGetEntryReq    *entry.GetEntryRequest
	expListEntriesReq *entry.ListEntriesRequest
	getEntryResp      *types.Entry
	listEntriesResp   *entry.ListEntriesResponse
}

func (f fakeEntryServer) ListEntries(ctx context.Context, req *entry.ListEntriesRequest) (*entry.ListEntriesResponse, error) {
	spiretest.RequireProtoEqual(f.t, f.expListEntriesReq, req)
	return f.listEntriesResp, nil
}

func (f fakeEntryServer) GetEntry(ctx context.Context, req *entry.GetEntryRequest) (*types.Entry, error) {
	spiretest.RequireProtoEqual(f.t, f.expGetEntryReq, req)
	return f.getEntryResp, nil
}
