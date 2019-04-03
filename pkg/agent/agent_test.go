package agent

import (
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	mock_manager "github.com/spiffe/spire/test/mock/agent/manager"
	mock_keymanager "github.com/spiffe/spire/test/mock/proto/agent/keymanager"
	mock_nodeattestor "github.com/spiffe/spire/test/mock/proto/agent/nodeattestor"
	"github.com/stretchr/testify/suite"
)

func TestAgent(t *testing.T) {
	suite.Run(t, new(AgentTestSuite))
}

type AgentTestSuite struct {
	suite.Suite

	ctrl *gomock.Controller

	agent      *Agent
	attestor   *mock_nodeattestor.MockNodeAttestor
	keyManager *mock_keymanager.MockKeyManager
	manager    *mock_manager.MockManager
}

func (s *AgentTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())

	s.attestor = mock_nodeattestor.NewMockNodeAttestor(s.ctrl)
	s.keyManager = mock_keymanager.NewMockKeyManager(s.ctrl)
	s.manager = mock_manager.NewMockManager(s.ctrl)

	addr := &net.UnixAddr{Name: "./spire_api", Net: "unix"}
	log, _ := test.NewNullLogger()
	tempDir, err := ioutil.TempDir("", "spire-test")
	s.Require().NoError(err)

	config := &Config{
		BindAddress: addr,
		DataDir:     tempDir,
		Log:         log,
		TrustDomain: url.URL{
			Scheme: "spiffe",
			Host:   "example.com",
		},
	}

	s.agent = New(config)
}

func (s *AgentTestSuite) TearDownTest() {
	os.RemoveAll(s.agent.c.DataDir)
	s.ctrl.Finish()
}

func (s *AgentTestSuite) TestSomething() {
	// TODO: add meaningful test here.
}
