package attestor

import (
	"io/ioutil"
	"net/url"
	"os"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"

	"crypto/x509"
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
	"path"
	"testing"
)

type AttestorTestSuite struct {
	suite.Suite

	ctrl *gomock.Controller

	attestor     Attestor
	catalog      *mock_catalog.MockCatalog
	nodeAttestor *mock_nodeattestor.MockNodeAttestor
	keyManager   *mock_keymanager.MockKeyManager
	nodeClient   *mock_node.MockNodeClient
	config       *Config
	expectation  *node.SvidUpdate
}

func (s *AttestorTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())

	s.nodeAttestor = mock_nodeattestor.NewMockNodeAttestor(s.ctrl)
	attestationData := &common.AttestedData{
		Type: "join_token",
		Data: []byte("foobar"),
	}
	fa := &nodeattestor.FetchAttestationDataResponse{
		AttestedData: attestationData,
		SpiffeId:     "spiffe://example.com/spire/agent/join_token/foobar",
	}
	s.nodeAttestor.EXPECT().FetchAttestationData(gomock.Any()).
		Return(fa, nil)

	svid, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)

	keyDer, err := x509.MarshalECPrivateKey(key)
	s.Require().NoError(err)

	s.keyManager = mock_keymanager.NewMockKeyManager(s.ctrl)
	s.keyManager.EXPECT().FetchPrivateKey(gomock.Any()).Return(
		&keymanager.FetchPrivateKeyResponse{PrivateKey: keyDer}, nil)
	s.keyManager.EXPECT().GenerateKeyPair(gomock.Any()).Return(
		&keymanager.GenerateKeyPairResponse{key.Y.Bytes(), keyDer}, nil)

	s.catalog = mock_catalog.NewMockCatalog(s.ctrl)
	s.catalog.EXPECT().NodeAttestors().
		Return([]nodeattestor.NodeAttestor{s.nodeAttestor})
	s.catalog.EXPECT().KeyManagers().
		Return([]keymanager.KeyManager{s.keyManager})

	s.nodeClient = mock_node.NewMockNodeClient(s.ctrl)
	s.nodeClient.EXPECT().FetchBaseSVID(gomock.Any(), gomock.Any()).
		Return(&node.FetchBaseSVIDResponse{&node.SvidUpdate{
			Svids: map[string]*node.Svid{
				"spiffe://example.com/spire/agent/join_token/foobar": &node.Svid{
					svid.Raw,
					300,
				}},
		}}, nil)
	log, _ := test.NewNullLogger()
	tempDir, err := ioutil.TempDir(os.TempDir(), "spire-test")
	s.Require().NoError(err)

	s.config = &Config{
		Catalog: s.catalog,
		DataDir: tempDir,
		Log:     log,
		TrustDomain: url.URL{
			Scheme: "spiffe",
			Host:   "example.com",
		},
		NodeClient: s.nodeClient,
	}

	s.attestor = New(s.config)
}

func (s *AttestorTestSuite) TeardownTest() {
	os.RemoveAll(s.config.DataDir)
	s.ctrl.Finish()
}

func (s *AttestorTestSuite) TestAttestLoadFromDisk() {
	err := os.Link(
		"../../../test/fixture/certs/bundle.der",
		path.Join(s.config.DataDir, "bundle.der"))
	s.Require().NoError(err)
	err = os.Link(
		"../../../test/fixture/certs/base_cert.der",
		path.Join(s.config.DataDir, "agent_svid.der"))

	s.Require().NoError(err)
	as, err := s.attestor.Attest()
	s.Require().NoError(err)
	_, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)

	s.Assert().Equal(as.Key, key)
	bundle, err := util.LoadBundleFixture()
	s.Assert().Equal(as.Bundle, bundle)
}

func (s *AttestorTestSuite) TestAttest() {
	tempDir, err := ioutil.TempDir(os.TempDir(), "spire-test")
	s.config.DataDir = tempDir

	err = os.Link(
		"../../../test/fixture/certs/bundle.der",
		path.Join(s.config.DataDir, "bundle.der"))
	s.Require().NoError(err)

	as, err := s.attestor.Attest()
	s.Require().NoError(err)

	svid, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)

	s.Require().NoError(err)

	s.Assert().Equal(as.Key, key)
	s.Assert().Equal(as.SVID, svid)
}

func (s *AttestorTestSuite) TestAttestJoinToken() {
	tempDir, err := ioutil.TempDir(os.TempDir(), "spire-test")
	s.config.DataDir = tempDir
	s.config.JoinToken = "foobar"
	err = os.Link(
		"../../../test/fixture/certs/bundle.der",
		path.Join(s.config.DataDir, "bundle.der"))
	s.Require().NoError(err)

	as, err := s.attestor.Attest()
	s.Require().NoError(err)

	svid, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)

	s.Require().NoError(err)

	s.Assert().Equal(as.Key, key)
	s.Assert().Equal(as.SVID, svid)
}

func TestAttestorTestSuite(t *testing.T) {
	suite.Run(t, new(AttestorTestSuite))
}
