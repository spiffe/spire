package attestor

import (
	"context"
	"crypto/x509"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/agent/keymanager"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/agent/catalog"
	"github.com/spiffe/spire/test/mock/proto/agent/keymanager"
	"github.com/spiffe/spire/test/mock/proto/agent/nodeattestor"
	"github.com/spiffe/spire/test/mock/proto/api/node"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/suite"
)

var (
	ctx = context.Background()
)

type NodeAttestorTestSuite struct {
	suite.Suite

	ctrl    *gomock.Controller
	tempDir string

	attestor     Attestor
	catalog      *mock_catalog.MockCatalog
	nodeAttestor *mock_nodeattestor.MockNodeAttestor
	keyManager   *mock_keymanager.MockKeyManager
	nodeClient   *mock_node.MockNodeClient
	config       *Config
	expectation  *node.SvidUpdate
}

func (s *NodeAttestorTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())

	s.nodeAttestor = mock_nodeattestor.NewMockNodeAttestor(s.ctrl)
	s.keyManager = mock_keymanager.NewMockKeyManager(s.ctrl)
	s.catalog = mock_catalog.NewMockCatalog(s.ctrl)
	s.nodeClient = mock_node.NewMockNodeClient(s.ctrl)

	log, _ := test.NewNullLogger()
	tempDir, err := ioutil.TempDir(os.TempDir(), "spire-test")
	s.Require().NoError(err)
	s.tempDir = tempDir

	s.config = &Config{
		Catalog:         s.catalog,
		SVIDCachePath:   path.Join(tempDir, "agent_svid.der"),
		BundleCachePath: path.Join(tempDir, "bundle.der"),
		Log:             log,
		TrustDomain: url.URL{
			Scheme: "spiffe",
			Host:   "example.com",
		},
		NodeClient: s.nodeClient,
	}

	s.attestor = New(s.config)
}

func (s *NodeAttestorTestSuite) TearDownTest() {
	os.RemoveAll(s.tempDir)
	s.ctrl.Finish()
}

func (s *NodeAttestorTestSuite) TestAttestLoadFromDisk() {
	s.linkBundle()
	s.linkAgentSVIDPath()

	s.setCatalog(false)
	s.setFetchPrivateKeyResponse()

	as, err := s.attestor.Attest(ctx)
	s.Require().NoError(err)

	_, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)

	s.Assert().Equal(as.Key, key)

	bundle, err := util.LoadBundleFixture()
	s.Require().NoError(err)
	s.Assert().Equal(as.Bundle, bundle)
}

func (s *NodeAttestorTestSuite) TestAttestNode() {
	s.linkBundle()
	s.setCatalog(true)
	s.setFetchPrivateKeyResponse()
	s.setGenerateKeyPairResponse()
	s.setFetchAttestationDataResponse()
	s.setFetchBaseSVIDResponse()
	as, err := s.attestor.Attest(ctx)
	s.Require().NoError(err)

	svid, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)

	s.Assert().Equal(as.Key, key)
	s.Assert().Equal(as.SVID, svid)
}

func (s *NodeAttestorTestSuite) TestAttestJoinToken() {
	s.config.JoinToken = "foobar"
	s.linkBundle()
	s.setCatalog(false)
	s.setFetchPrivateKeyResponse()
	s.setGenerateKeyPairResponse()
	s.setFetchBaseSVIDResponse()

	as, err := s.attestor.Attest(ctx)
	s.Require().NoError(err)

	svid, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)

	s.Assert().Equal(as.Key, key)
	s.Assert().Equal(as.SVID, svid)
}

func TestNodeAttestorTestSuite(t *testing.T) {
	suite.Run(t, new(NodeAttestorTestSuite))
}

func (s *NodeAttestorTestSuite) linkAgentSVIDPath() {
	err := os.Symlink(
		path.Join(util.ProjectRoot(), "test/fixture/certs/agent_svid.der"),
		s.config.SVIDCachePath)
	s.Require().NoError(err)
}

func (s *NodeAttestorTestSuite) linkBundle() {
	err := os.Symlink(
		path.Join(util.ProjectRoot(), "test/fixture/certs/bundle.der"),
		s.config.BundleCachePath)
	s.Require().NoError(err)
}

func (s *NodeAttestorTestSuite) setFetchAttestationDataResponse() {
	attestationData := &common.AttestedData{
		Type: "join_token",
		Data: []byte("foobar"),
	}
	fa := &nodeattestor.FetchAttestationDataResponse{
		AttestedData: attestationData,
		SpiffeId:     "spiffe://example.com/spire/agent/join_token/foobar",
	}
	s.nodeAttestor.EXPECT().FetchAttestationData(gomock.Any(), gomock.Any()).
		Return(fa, nil)
}

func (s *NodeAttestorTestSuite) setFetchPrivateKeyResponse() {
	_, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)

	keyDer, err := x509.MarshalECPrivateKey(key)
	s.Require().NoError(err)

	s.keyManager.EXPECT().FetchPrivateKey(gomock.Any(), gomock.Any()).Return(
		&keymanager.FetchPrivateKeyResponse{PrivateKey: keyDer}, nil)
}

func (s *NodeAttestorTestSuite) setGenerateKeyPairResponse() {
	svid, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)

	keyDer, err := x509.MarshalECPrivateKey(key)
	s.Require().NoError(err)

	s.keyManager.EXPECT().GenerateKeyPair(gomock.Any(), gomock.Any()).Return(
		&keymanager.GenerateKeyPairResponse{PublicKey: svid.RawSubjectPublicKeyInfo, PrivateKey: keyDer}, nil)
}

func (s *NodeAttestorTestSuite) setCatalog(usesNodeAttestor bool) {
	if usesNodeAttestor {
		s.catalog.EXPECT().NodeAttestors().
			Return([]nodeattestor.NodeAttestor{s.nodeAttestor})
	}
	s.catalog.EXPECT().KeyManagers().
		Return([]keymanager.KeyManager{s.keyManager})
}

func (s *NodeAttestorTestSuite) setFetchBaseSVIDResponse() {
	svid, _, err := util.LoadSVIDFixture()
	s.Require().NoError(err)

	s.nodeClient.EXPECT().FetchBaseSVID(gomock.Any(), gomock.Any()).
		Return(&node.FetchBaseSVIDResponse{SvidUpdate: &node.SvidUpdate{
			Svids: map[string]*node.Svid{
				"spiffe://example.com/spire/agent/join_token/foobar": &node.Svid{
					SvidCert: svid.Raw,
					Ttl:      300,
				}},
		}}, nil)
}
