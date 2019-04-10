package entry

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"
	mock_registration "github.com/spiffe/spire/test/mock/proto/api/registration"
	"github.com/stretchr/testify/suite"
)

type ShowTestSuite struct {
	suite.Suite

	cli        *ShowCLI
	mockClient *mock_registration.MockRegistrationClient
}

func (suite *ShowTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(suite.T())
	defer mockCtrl.Finish()

	suite.mockClient = mock_registration.NewMockRegistrationClient(mockCtrl)

	cli := &ShowCLI{
		Config:  new(ShowConfig),
		Client:  suite.mockClient,
		Entries: []*common.RegistrationEntry{},
	}
	suite.cli = cli
}

func TestShowTestSuite(t *testing.T) {
	suite.Run(t, new(ShowTestSuite))
}

func (s *ShowTestSuite) TestRunWithEntryID() {
	entryID := "123456"

	args := []string{
		"-entryID",
		entryID,
	}

	req := &registration.RegistrationEntryID{Id: entryID}
	resp := s.registrationEntries(1)[0]
	s.mockClient.EXPECT().FetchEntry(gomock.Any(), req).Return(resp, nil)

	s.Require().Equal(0, s.cli.Run(args))
	s.Assert().Equal(s.registrationEntries(1), s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithParentID() {
	entries := s.registrationEntries(2)

	args := []string{
		"-parentID",
		entries[0].ParentId,
	}

	req := &registration.ParentID{Id: entries[0].ParentId}
	resp := &common.RegistrationEntries{Entries: entries}
	s.mockClient.EXPECT().ListByParentID(gomock.Any(), req).Return(resp, nil)

	s.Require().Equal(0, s.cli.Run(args))

	util.SortRegistrationEntries(entries)
	s.Assert().Equal(entries, s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithSpiffeID() {
	entries := s.registrationEntries(1)
	entry := entries[0]

	args := []string{
		"-spiffeID",
		entry.SpiffeId,
	}

	req := &registration.SpiffeID{Id: entry.SpiffeId}
	resp := &common.RegistrationEntries{Entries: entries}
	s.mockClient.EXPECT().ListBySpiffeID(gomock.Any(), req).Return(resp, nil)

	s.Require().Equal(0, s.cli.Run(args))
	s.Assert().Equal(entries, s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithSelector() {
	entries := s.registrationEntries(2)

	args := []string{
		"-selector",
		"foo:bar",
	}

	req := &common.Selector{Type: "foo", Value: "bar"}
	resp := &common.RegistrationEntries{Entries: entries}
	s.mockClient.EXPECT().ListBySelector(gomock.Any(), req).Return(resp, nil)

	s.Require().Equal(0, s.cli.Run(args))

	util.SortRegistrationEntries(entries)
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

	req := &common.Selector{Type: "foo", Value: "bar"}
	resp := &common.RegistrationEntries{Entries: entries}
	s.mockClient.EXPECT().ListBySelector(gomock.Any(), req).Return(resp, nil)

	req = &common.Selector{Type: "bar", Value: "baz"}
	resp.Entries = entries[1:2]
	s.mockClient.EXPECT().ListBySelector(gomock.Any(), req).Return(resp, nil)

	s.Require().Equal(0, s.cli.Run(args))
	s.Assert().Equal(entries[1:2], s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithParentIDAndSelectors() {
	entries := s.registrationEntries(4)[2:4]

	args := []string{
		"-parentID",
		entries[0].ParentId,
		"-selector",
		"bar:baz",
	}

	req1 := &registration.ParentID{Id: entries[0].ParentId}
	resp := &common.RegistrationEntries{Entries: entries}
	s.mockClient.EXPECT().ListByParentID(gomock.Any(), req1).Return(resp, nil)

	req2 := &common.Selector{Type: "bar", Value: "baz"}
	resp = &common.RegistrationEntries{Entries: entries[0:1]}
	s.mockClient.EXPECT().ListBySelector(gomock.Any(), req2).Return(resp, nil)

	s.Require().Equal(0, s.cli.Run(args))

	expectEntries := entries[0:1]
	util.SortRegistrationEntries(expectEntries)
	s.Assert().Equal(expectEntries, s.cli.Entries)
}

func (s *ShowTestSuite) TestRunWithFederatesWith() {
	resp := &common.RegistrationEntries{
		Entries: s.registrationEntries(4),
	}
	s.mockClient.EXPECT().FetchEntries(gomock.Any(), &common.Empty{}).Return(resp, nil)

	args := []string{
		"-federatesWith",
		"spiffe://domain.test",
	}

	s.Require().Equal(0, s.cli.Run(args))

	expectEntries := s.registrationEntries(4)[2:3]
	util.SortRegistrationEntries(expectEntries)
	s.Assert().Equal(expectEntries, s.cli.Entries)
}

// registrationEntries returns `count` registration entry records. At most 4.
func (ShowTestSuite) registrationEntries(count int) []*common.RegistrationEntry {
	selectors := []*common.Selector{
		{Type: "foo", Value: "bar"},
		{Type: "bar", Value: "baz"},
		{Type: "baz", Value: "bat"},
	}
	entries := []*common.RegistrationEntry{
		{
			ParentId:  "spiffe://example.org/father",
			SpiffeId:  "spiffe://example.org/son",
			Selectors: []*common.Selector{selectors[0]},
			EntryId:   "00000000-0000-0000-0000-000000000000",
		},
		{
			ParentId:  "spiffe://example.org/father",
			SpiffeId:  "spiffe://example.org/daughter",
			Selectors: []*common.Selector{selectors[0], selectors[1]},
			EntryId:   "00000000-0000-0000-0000-000000000001",
		},
		{
			ParentId:      "spiffe://example.org/mother",
			SpiffeId:      "spiffe://example.org/daughter",
			Selectors:     []*common.Selector{selectors[1], selectors[2]},
			EntryId:       "00000000-0000-0000-0000-000000000002",
			FederatesWith: []string{"spiffe://domain.test"},
		},
		{
			ParentId:  "spiffe://example.org/mother",
			SpiffeId:  "spiffe://example.org/son",
			Selectors: []*common.Selector{selectors[2]},
			EntryId:   "00000000-0000-0000-0000-000000000003",
		},
	}

	e := []*common.RegistrationEntry{}
	for i := 0; i < count; i++ {
		e = append(e, entries[i])
	}

	return e
}
