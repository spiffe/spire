package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/agent/keymanager"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/agent/cache"
	"github.com/spiffe/spire/test/mock/agent/catalog"
	"github.com/spiffe/spire/test/mock/proto/agent/keymanager"
	"github.com/spiffe/spire/test/mock/proto/agent/nodeattestor"
	"github.com/spiffe/spire/test/util"
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
	manager    *mock_cache.MockManager
}

func (s *AgentTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())

	s.catalog = mock_catalog.NewMockCatalog(s.ctrl)
	s.attestor = mock_nodeattestor.NewMockNodeAttestor(s.ctrl)
	s.keyManager = mock_keymanager.NewMockKeyManager(s.ctrl)
	s.manager = mock_cache.NewMockManager(s.ctrl)

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

func (s *AgentTestSuite) TestLoadBundle() {
	// No configured bundle
	_, err := s.agent.loadBundle()
	s.Assert().NotNil(err)

	// Empty bundle
	s.agent.c.TrustBundle = []*x509.Certificate{}
	_, err = s.agent.loadBundle()
	s.Assert().NotNil(err)

	// The right stuff
	cert, _, err := util.LoadCAFixture()
	s.Require().NoError(err)
	s.agent.c.TrustBundle = []*x509.Certificate{cert}
	bundle, err := s.agent.loadBundle()
	s.Require().NoError(err)
	s.Assert().Equal(s.agent.c.TrustBundle, bundle)
}

func (s *AgentTestSuite) TestLoadSVIDWithKey() {
	// Generate a key to be returned
	kmKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	s.Require().NoError(err)
	keyData, err := x509.MarshalECPrivateKey(kmKey)
	s.Require().NoError(err)

	// Expect a call to keymanager
	kmResp := &keymanager.FetchPrivateKeyResponse{keyData}
	s.catalog.EXPECT().KeyManagers().Return([]*mock_keymanager.MockKeyManager{s.keyManager})
	s.keyManager.EXPECT().FetchPrivateKey(gomock.Any()).Return(kmResp)

	// Without a cached SVID
	svid, key, err := s.agent.loadSVID()
	s.Assert().Nil(svid)
	s.Assert().NotNil(key)
	s.Assert().NotEqual(kmKey, key)
	s.Assert().NoError(err)

	// With a cached SVID
	fixture, _, err := util.LoadSVIDFixture()
	s.Require().NoError(err)
	svidPath := path.Join(s.agent.c.DataDir, "agent_svid.der")
	err = ioutil.WriteFile(svidPath, fixture.Raw, 0640)
	s.Require().NoError(err)
	svid, key, err = s.agent.loadSVID()
	s.Assert().Equal(fixture, svid)
	s.Assert().Equal(kmKey, key)
	s.Assert().NoError(err)
}

func (s *AgentTestSuite) TestLoadSVIDWithoutKey() {
	// Generate a key to be returned with GenerateKeyPair()
	kmKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	s.Require().NoError(err)
	pubKey, err := x509.MarshalPKIXPublicKey(kmKey.PublicKey)
	s.Require().NoError(err)
	privKey, err := x509.MarshalECPrivateKey(kmKey)
	s.Require().NoError(err)

	// Expect a call to keymanager
	fetchResp := &keymanager.FetchPrivateKeyResponse{}
	genResp := &keymanager.GenerateKeyPairResponse{pubKey, privKey}
	s.catalog.EXPECT().KeyManagers().Return([]*mock_keymanager.MockKeyManager{s.keyManager})
	s.keyManager.EXPECT().FetchPrivateKey(gomock.Any()).Return(fetchResp)
	s.keyManager.EXPECT().GenerateKeyPair(gomock.Any()).Return(genResp)

	// Without a cached SVID
	svid, key, err := s.agent.loadSVID()
	s.Assert().Nil(svid)
	s.Assert().NotNil(key)
	s.Assert().Equal(kmKey, key)
	s.Assert().NoError(err)

	// With a cached SVID
	fixture, _, err := util.LoadSVIDFixture()
	s.Require().NoError(err)
	svidPath := path.Join(s.agent.c.DataDir, "agent_svid.der")
	err = ioutil.WriteFile(svidPath, fixture.Raw, 0640)
	s.Require().NoError(err)
	svid, key, err = s.agent.loadSVID()
	s.Assert().Nil(svid)
	s.Assert().Equal(kmKey, key)
	s.Assert().NoError(err)
}

func (s *AgentTestSuite) TestAttestableData() {
	// Expect a call to a node attestor
	expectData := &common.AttestedData{"foo", []byte{}}
	expectResp := &nodeattestor.FetchAttestationDataResponse{expectData, "spiffe://example.com/bar"}
	s.catalog.EXPECT().NodeAttestors().Return([]*mock_nodeattestor.MockNodeAttestor{s.attestor})
	s.attestor.EXPECT().FetchAttestationData(gomock.Any()).Return(expectResp)

	// Without a join token
	resp, err := s.agent.attestableData()
	s.Assert().NoError(err)
	s.Assert().Equal(expectResp, resp)

	// With a join token
	s.agent.c.JoinToken = "foo"
	tokenData := &common.AttestedData{"join_token", []byte("foo")}
	tokenResp := &nodeattestor.FetchAttestationDataResponse{tokenData, "spiffe://example.com/agent/join_token/foo"}
	resp, err = s.agent.attestableData()
	s.Assert().Equal(tokenResp, resp)
}
