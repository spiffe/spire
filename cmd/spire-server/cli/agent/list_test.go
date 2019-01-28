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
}

func (s *ListTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.T())
	defer mockCtrl.Finish()
	s.mockClient = mock_registration.NewMockRegistrationClient(mockCtrl)
	s.cli = &ListCLI{
		RegistrationClient: s.mockClient,
	}
}

func TestListTestSuite(t *testing.T) {
	suite.Run(t, new(ListTestSuite))
}

func (s *ListTestSuite) TestRun() {
	req := &common.Empty{}
	resp := &registration.ListAgentsResponse{
		Nodes: []*common.AttestedNode{
			&common.AttestedNode{SpiffeId: "spiffe://example.org/spire/agent/join_token/token_a"},
		},
	}
	s.mockClient.EXPECT().ListAgents(gomock.Any(), req).Return(resp, nil)
	s.Require().Equal(0, s.cli.Run([]string{}))
	s.Assert().Equal(resp.Nodes, s.cli.NodeList)
}

func (s *ListTestSuite) TestRunWithNoAgentsInDatastore() {
	req := &common.Empty{}
	resp := &registration.ListAgentsResponse{}
	s.mockClient.EXPECT().ListAgents(gomock.Any(), req).Return(resp, nil)
	s.Require().Equal(0, s.cli.Run([]string{}))
	s.Assert().Equal(resp.Nodes, s.cli.NodeList)
}

func (s *ListTestSuite) TestRunExitsWithNonZeroCodeOnFailure() {
	req := &common.Empty{}
	s.mockClient.EXPECT().ListAgents(gomock.Any(), req).Return(nil, errors.New("Some error"))
	s.Require().Equal(1, s.cli.Run([]string{}))
	s.Assert().Nil(s.cli.NodeList)
}
