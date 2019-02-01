package agent

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/proto/api/registration"
	"github.com/stretchr/testify/suite"
)

type ListTestSuite struct {
	suite.Suite
	cli        *ListCLI
	mockClient *mock_registration.MockRegistrationClient
	mockCtrl   *gomock.Controller
}

func (s *ListTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockClient = mock_registration.NewMockRegistrationClient(s.mockCtrl)
	s.cli = &ListCLI{
		registrationClient: s.mockClient,
	}
}

func (s *ListTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
}

func TestListTestSuite(t *testing.T) {
	suite.Run(t, new(ListTestSuite))
}

func (s *ListTestSuite) TestRun() {
	req := &registration.ListAgentsRequest{}
	resp := &registration.ListAgentsResponse{
		Nodes: []*common.AttestedNode{
			&common.AttestedNode{SpiffeId: "spiffe://example.org/spire/agent/join_token/token_a"},
		},
	}
	s.mockClient.EXPECT().ListAgents(gomock.Any(), req).Return(resp, nil)
	s.Require().Equal(0, s.cli.Run([]string{}))
	s.Assert().Equal(resp.Nodes, s.cli.nodeList)
}

func (s *ListTestSuite) TestRunWithNoAgentsInDatastore() {
	req := &registration.ListAgentsRequest{}
	resp := &registration.ListAgentsResponse{}
	s.mockClient.EXPECT().ListAgents(gomock.Any(), req).Return(resp, nil)
	s.Require().Equal(0, s.cli.Run([]string{}))
	s.Assert().Equal(resp.Nodes, s.cli.nodeList)
}

func (s *ListTestSuite) TestRunExitsWithNonZeroCodeOnFailure() {
	req := &registration.ListAgentsRequest{}
	s.mockClient.EXPECT().ListAgents(gomock.Any(), req).Return(nil, errors.New("Some error"))
	s.Require().Equal(1, s.cli.Run([]string{}))
	s.Assert().Nil(s.cli.nodeList)
}
