package entry

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire/types"
	mock_entry "github.com/spiffe/spire/test/mock/proto/api/entry"
	"github.com/stretchr/testify/suite"
)

func TestShowTestSuite(t *testing.T) {
	suite.Run(t, new(ShowTestSuite))
}

type ShowTestSuite struct {
	suite.Suite

	cli        *ShowCLI
	mockClient *mock_entry.MockEntryClient
}

func (s *ShowTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.T())
	defer mockCtrl.Finish()

	s.mockClient = mock_entry.NewMockEntryClient(mockCtrl)

	cli := &ShowCLI{
		Config:  new(ShowConfig),
		Client:  s.mockClient,
		Entries: []*types.Entry{},
	}
	s.cli = cli
}

func (s *ShowTestSuite) TestRunWithEntryID() {
	entryID := "123456"

	args := []string{
		"-entryID",
		entryID,
	}

	req := &entry.GetEntryRequest{Id: entryID}
	resp := s.registrationEntries(1)[0]
	s.mockClient.EXPECT().GetEntry(gomock.Any(), req).Return(resp, nil)

	s.Require().Zero(s.cli.Run(args))
	s.Assert().Equal(s.registrationEntries(1), s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithParentID() {
	entries := s.registrationEntries(2)

	args := []string{
		"-parentID",
		protoToIDString(entries[0].ParentId),
	}

	req := &entry.ListEntriesRequest{
		Filter: &entry.ListEntriesRequest_Filter{
			ByParentId: entries[0].ParentId,
		},
	}
	resp := &entry.ListEntriesResponse{Entries: entries}
	s.mockClient.EXPECT().ListEntries(gomock.Any(), req).Return(resp, nil)

	s.Require().Zero(s.cli.Run(args))

	util.SortTypesEntries(entries)
	s.Assert().Equal(entries, s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithSpiffeID() {
	entries := s.registrationEntries(1)

	args := []string{
		"-spiffeID",
		protoToIDString(entries[0].SpiffeId),
	}

	req := &entry.ListEntriesRequest{
		Filter: &entry.ListEntriesRequest_Filter{
			BySpiffeId: entries[0].SpiffeId,
		},
	}
	resp := &entry.ListEntriesResponse{Entries: entries}
	s.mockClient.EXPECT().ListEntries(gomock.Any(), req).Return(resp, nil)

	s.Require().Zero(s.cli.Run(args))
	s.Assert().Equal(entries, s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithSelector() {
	entries := s.registrationEntries(2)

	args := []string{
		"-selector",
		"foo:bar",
	}

	req := &entry.ListEntriesRequest{
		Filter: &entry.ListEntriesRequest_Filter{
			BySelectors: &types.SelectorMatch{
				Match: types.SelectorMatch_MATCH_SUBSET,
				Selectors: []*types.Selector{
					{Type: "foo", Value: "bar"},
				},
			},
		},
	}

	resp := &entry.ListEntriesResponse{
		Entries: entries,
	}
	s.mockClient.EXPECT().ListEntries(gomock.Any(), req).Return(resp, nil)

	s.Require().Zero(s.cli.Run(args))

	util.SortTypesEntries(entries)
	s.Assert().Equal(entries, s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithSelectors() {
	entries := s.registrationEntries(2)

	args := []string{
		"-selector",
		"foo:bar",
		"-selector",
		"bar:baz",
	}

	req := &entry.ListEntriesRequest{
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

	resp := &entry.ListEntriesResponse{Entries: entries[1:2]}
	s.mockClient.EXPECT().ListEntries(gomock.Any(), req).Return(resp, nil)

	s.Require().Zero(s.cli.Run(args))
	s.Assert().Equal(resp.Entries, s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithParentIDAndSelectors() {
	entries := s.registrationEntries(4)[2:4]

	args := []string{
		"-parentID",
		protoToIDString(entries[0].ParentId),
		"-selector",
		"bar:baz",
	}

	req := &entry.ListEntriesRequest{
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

	resp := &entry.ListEntriesResponse{Entries: entries[0:1]}
	s.mockClient.EXPECT().ListEntries(gomock.Any(), req).Return(resp, nil)

	s.Require().Zero(s.cli.Run(args))

	s.Assert().Equal(resp.Entries, s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithFederatesWith() {
	req := &entry.ListEntriesRequest{
		Filter: &entry.ListEntriesRequest_Filter{},
	}
	resp := &entry.ListEntriesResponse{
		Entries: s.registrationEntries(4),
	}

	s.mockClient.EXPECT().ListEntries(gomock.Any(), req).Return(resp, nil)

	args := []string{
		"-federatesWith",
		"spiffe://domain.test",
	}

	s.Require().Zero(s.cli.Run(args))

	expectEntries := s.registrationEntries(4)[2:3]
	s.Assert().Equal(expectEntries, s.cli.Entries)
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
