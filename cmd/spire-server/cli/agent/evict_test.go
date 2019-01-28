package agent

import (
	"errors"
	"testing"

	"github.com/spiffe/spire/proto/api/registration"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/test/mock/proto/api/registration"
	"github.com/stretchr/testify/suite"
)

type EvictTestSuite struct {
	suite.Suite
	cli        *EvictCLI
	mockClient *mock_registration.MockRegistrationClient
}

func (s *EvictTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.T())
	defer mockCtrl.Finish()
	s.mockClient = mock_registration.NewMockRegistrationClient(mockCtrl)
	s.cli = &EvictCLI{
		RegistrationClient: s.mockClient,
	}
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
		DeleteSucceed: true,
	}

	s.mockClient.EXPECT().EvictAgent(gomock.Any(), req).Return(resp, nil)
	s.Require().Equal(0, s.cli.Run(args))
}

func (s *EvictTestSuite) TestRunExitsWithNonZeroCodeOnFailure() {
	spiffeIDToRemove := "spiffe://example.org/spire/agent/join_token/token_a"
	args := []string{"-spiffeID", spiffeIDToRemove}

	req := &registration.EvictAgentRequest{
		SpiffeID: spiffeIDToRemove,
	}

	resp := &registration.EvictAgentResponse{
		DeleteSucceed: false,
	}

	s.mockClient.EXPECT().EvictAgent(gomock.Any(), req).Return(resp, errors.New("Some error"))
	s.Require().Equal(1, s.cli.Run(args))
}

func (s *EvictTestSuite) TestRunValidatesSpiffeID() {
	spiffeIDToRemove := "not//an//spiffe/id"
	args := []string{"-spiffeID", spiffeIDToRemove}
	s.Require().Equal(1, s.cli.Run(args))
}
