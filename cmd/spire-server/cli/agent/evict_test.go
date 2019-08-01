package agent

import (
	"errors"
	"testing"

	"github.com/spiffe/spire/proto/spire/common"

	"github.com/spiffe/spire/proto/spire/api/registration"

	"github.com/golang/mock/gomock"
	mock_registration "github.com/spiffe/spire/test/mock/proto/api/registration"
	"github.com/stretchr/testify/suite"
)

type EvictTestSuite struct {
	suite.Suite
	cli        *EvictCLI
	mockClient *mock_registration.MockRegistrationClient
	mockCtrl   *gomock.Controller
}

func (s *EvictTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockClient = mock_registration.NewMockRegistrationClient(s.mockCtrl)
	s.cli = &EvictCLI{
		registrationClient: s.mockClient,
	}
}

func (s *EvictTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
}

func TestEvictTestSuite(t *testing.T) {
	suite.Run(t, new(EvictTestSuite))
}

func (s *EvictTestSuite) TestRun() {
	spiffeIDToRemove := "spiffe://example.org/spire/agent/join_token/token_a"
	args := []string{"-spiffeID", spiffeIDToRemove}

	req := &registration.EvictAgentRequest{
		SpiffeID: spiffeIDToRemove,
	}

	resp := &registration.EvictAgentResponse{
		Node: &common.AttestedNode{SpiffeId: spiffeIDToRemove},
	}

	s.mockClient.EXPECT().EvictAgent(gomock.Any(), req).Return(resp, nil)
	s.Require().Equal(0, s.cli.Run(args))
}

func (s *EvictTestSuite) TestRunExitsWithNonZeroCodeOnError() {
	spiffeIDToRemove := "spiffe://example.org/spire/agent/join_token/token_a"
	args := []string{"-spiffeID", spiffeIDToRemove}

	req := &registration.EvictAgentRequest{
		SpiffeID: spiffeIDToRemove,
	}

	s.mockClient.EXPECT().EvictAgent(gomock.Any(), req).Return(nil, errors.New("Some error"))
	s.Require().Equal(1, s.cli.Run(args))
}

func (s *EvictTestSuite) TestRunExitsWithNonZeroCodeOnDeleteFailed() {
	spiffeIDToRemove := "spiffe://example.org/spire/agent/join_token/token_a"
	args := []string{"-spiffeID", spiffeIDToRemove}

	req := &registration.EvictAgentRequest{
		SpiffeID: spiffeIDToRemove,
	}
	resp := &registration.EvictAgentResponse{}

	s.mockClient.EXPECT().EvictAgent(gomock.Any(), req).Return(resp, nil)
	s.Require().Equal(1, s.cli.Run(args))
}

func (s *EvictTestSuite) TestRunValidatesSpiffeID() {
	spiffeIDToRemove := "not//an//spiffe/id"
	args := []string{"-spiffeID", spiffeIDToRemove}
	s.Require().Equal(1, s.cli.Run(args))
}
