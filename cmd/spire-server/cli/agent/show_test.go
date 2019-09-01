package agent

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"
	mock_registration "github.com/spiffe/spire/test/mock/proto/api/registration"
	"github.com/stretchr/testify/suite"
)

type ShowTestSuite struct {
	suite.Suite
	cli        *ShowCLI
	mockClient *mock_registration.MockRegistrationClient
	mockCtrl   *gomock.Controller
}

func (s *ShowTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockClient = mock_registration.NewMockRegistrationClient(s.mockCtrl)
	s.cli = &ShowCLI{
		registrationClient: s.mockClient,
	}
}

func (s *ShowTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
}

func TestShowTestSuite(t *testing.T) {
	suite.Run(t, new(ShowTestSuite))
}

func (s *ShowTestSuite) TestRun() {
	spiffeID := "spiffe://example.org/spire/agent/k8s_sat/demo-cluster/c54f273c-f9c2-4d08-9d6f-08879e418aef"
	selectors := []*common.Selector{
		{Type: "k8s_sat", Value: "agent_ns:spire"},
		{Type: "k8s_sat", Value: "agent_sa:spire-agent"},
		{Type: "k8s_sat", Value: "cluster:demo-cluster"},
	}

	req1 := &registration.ListAgentsRequest{}
	resp1 := &registration.ListAgentsResponse{
		Nodes: []*common.AttestedNode{
			{SpiffeId: spiffeID},
		},
	}
	s.mockClient.EXPECT().ListAgents(gomock.Any(), req1).Return(resp1, nil)

	req2 := &registration.GetNodeSelectorsRequest{
		SpiffeId: spiffeID,
	}
	resp2 := &registration.GetNodeSelectorsResponse{
		Selectors: &registration.NodeSelectors{
			Selectors: selectors,
		},
	}
	s.mockClient.EXPECT().GetNodeSelectors(gomock.Any(), req2).Return(resp2, nil)

	args := []string{"-spiffeID", spiffeID}
	s.Require().Equal(0, s.cli.Run(args))
	s.Assert().Equal(spiffeID, s.cli.node.SpiffeId)
	s.Assert().Equal(selectors, s.cli.selectors)
}

func (s *ShowTestSuite) TestRunWithNoSelectorsInDatastore() {
	spiffeID := "spiffe://example.org/spire/agent/k8s_sat/demo-cluster/c54f273c-f9c2-4d08-9d6f-08879e418aef"

	req1 := &registration.ListAgentsRequest{}
	resp1 := &registration.ListAgentsResponse{
		Nodes: []*common.AttestedNode{
			{SpiffeId: spiffeID},
		},
	}
	s.mockClient.EXPECT().ListAgents(gomock.Any(), req1).Return(resp1, nil)

	req2 := &registration.GetNodeSelectorsRequest{
		SpiffeId: spiffeID,
	}
	resp2 := &registration.GetNodeSelectorsResponse{
		Selectors: &registration.NodeSelectors{},
	}
	s.mockClient.EXPECT().GetNodeSelectors(gomock.Any(), req2).Return(resp2, nil)

	args := []string{"-spiffeID", spiffeID}
	s.Require().Equal(0, s.cli.Run(args))
	s.Assert().Equal(spiffeID, s.cli.node.SpiffeId)
	s.Assert().Nil(s.cli.selectors)
}

func (s *ShowTestSuite) TestRunWithNoAgentInDatastore() {
	spiffeID := "spiffe://example.org/spire/agent/k8s_sat/demo-cluster/c54f273c-f9c2-4d08-9d6f-08879e418aef"

	req1 := &registration.ListAgentsRequest{}
	resp1 := &registration.ListAgentsResponse{
		Nodes: []*common.AttestedNode{
			{SpiffeId: "spiffe://example.org/no-agent"},
		},
	}
	s.mockClient.EXPECT().ListAgents(gomock.Any(), req1).Return(resp1, nil)

	args := []string{"-spiffeID", spiffeID}
	s.Require().Equal(1, s.cli.Run(args))
	s.Assert().Nil(s.cli.node)
	s.Assert().Nil(s.cli.selectors)
}

func (s *ShowTestSuite) TestRunListAgentsExitsWithNonZeroCodeOnFailure() {
	spiffeID := "spiffe://example.org/spire/agent/k8s_sat/demo-cluster/c54f273c-f9c2-4d08-9d6f-08879e418aef"

	req1 := &registration.ListAgentsRequest{}
	s.mockClient.EXPECT().ListAgents(gomock.Any(), req1).Return(nil, errors.New("Some error"))

	args := []string{"-spiffeID", spiffeID}
	s.Require().Equal(1, s.cli.Run(args))
	s.Assert().Nil(s.cli.node)
	s.Assert().Nil(s.cli.selectors)
}

func (s *ShowTestSuite) TestRunGetNodeSelectorsExitsWithNonZeroCodeOnFailure() {
	spiffeID := "spiffe://example.org/spire/agent/k8s_sat/demo-cluster/c54f273c-f9c2-4d08-9d6f-08879e418aef"

	req1 := &registration.ListAgentsRequest{}
	resp1 := &registration.ListAgentsResponse{
		Nodes: []*common.AttestedNode{
			{SpiffeId: spiffeID},
		},
	}
	s.mockClient.EXPECT().ListAgents(gomock.Any(), req1).Return(resp1, nil)

	req2 := &registration.GetNodeSelectorsRequest{
		SpiffeId: spiffeID,
	}
	s.mockClient.EXPECT().GetNodeSelectors(gomock.Any(), req2).Return(nil, errors.New("Some error"))

	args := []string{"-spiffeID", spiffeID}
	s.Require().Equal(1, s.cli.Run(args))
	s.Assert().Equal(spiffeID, s.cli.node.SpiffeId)
	s.Assert().Nil(s.cli.selectors)
}

func (s *ShowTestSuite) TestRunValidatesSpiffeID() {
	spiffeID := "invalid-spiffe-id"
	args := []string{"-spiffeID", spiffeID}
	s.Require().Equal(1, s.cli.Run(args))
}
