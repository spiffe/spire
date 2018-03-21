package agent

import (
	"io/ioutil"
	"net"
	"net/url"
	"os"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/agent/catalog"
	"github.com/spiffe/spire/test/mock/agent/manager"
	"github.com/spiffe/spire/test/mock/proto/agent/keymanager"
	"github.com/spiffe/spire/test/mock/proto/agent/nodeattestor"
	"github.com/stretchr/testify/suite"
)

type selectors []*common.Selector

type AgentTestSuite struct {
	suite.Suite

	ctrl *gomock.Controller

	agent      *Agent
	catalog    *mock_catalog.MockCatalog
	attestor   *mock_nodeattestor.MockNodeAttestor
	keyManager *mock_keymanager.MockKeyManager
	manager    *mock_manager.MockManager
}

func (s *AgentTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())

	s.catalog = mock_catalog.NewMockCatalog(s.ctrl)
	s.attestor = mock_nodeattestor.NewMockNodeAttestor(s.ctrl)
	s.keyManager = mock_keymanager.NewMockKeyManager(s.ctrl)
	s.manager = mock_manager.NewMockManager(s.ctrl)

	addr := &net.UnixAddr{Name: "./spire_api", Net: "unix"}
	log, _ := test.NewNullLogger()
	tempDir, err := ioutil.TempDir(os.TempDir(), "spire-test")
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

func (s *AgentTestSuite) TeardownTest() {
	os.RemoveAll(s.agent.c.DataDir)
	s.ctrl.Finish()
}
