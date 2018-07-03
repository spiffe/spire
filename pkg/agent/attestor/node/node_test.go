package attestor

import (
	"context"
	"crypto/x509"
	"io"
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
	tempDir, err := ioutil.TempDir("", "spire-test")
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
	s.setFetchAttestationDataResponse(nil)
	s.setAttestResponse(nil)
	as, err := s.attestor.Attest(ctx)
	s.Require().NoError(err)

	svid, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)

	s.Assert().Equal(as.Key, key)
	s.Assert().Equal(as.SVID, svid)
}

func (s *NodeAttestorTestSuite) TestAttestNodeWithChallengeResponse() {
	challenges := []challengeResponse{
		{challenge: "1+1", response: "2"},
		{challenge: "5+7", response: "12"},
	}

	s.linkBundle()
	s.setCatalog(true)
	s.setFetchPrivateKeyResponse()
	s.setGenerateKeyPairResponse()
	s.setFetchAttestationDataResponse(challenges)
	s.setAttestResponse(challenges)
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
	s.setAttestResponse(nil)

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

type challengeResponse struct {
	challenge string
	response  string
}

func (s *NodeAttestorTestSuite) setFetchAttestationDataResponse(challenges []challengeResponse) {
	attestationData := &common.AttestationData{
		Type: "join_token",
		Data: []byte("foobar"),
	}

	fa := &nodeattestor.FetchAttestationDataResponse{
		AttestationData: attestationData,
		SpiffeId:        "spiffe://example.com/spire/agent/join_token/foobar",
	}

	stream := mock_nodeattestor.NewMockFetchAttestationData_Stream(s.ctrl)
	stream.EXPECT().Recv().Return(fa, nil)
	for _, challenge := range challenges {
		stream.EXPECT().Send(&nodeattestor.FetchAttestationDataRequest{
			Challenge: []byte(challenge.challenge),
		})
		fa := *fa
		fa.Response = []byte(challenge.response)
		stream.EXPECT().Recv().Return(&fa, nil)
	}
	stream.EXPECT().CloseSend()
	stream.EXPECT().Recv().Return(nil, io.EOF)
	s.nodeAttestor.EXPECT().FetchAttestationData(gomock.Any()).Return(stream, nil)
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

func (s *NodeAttestorTestSuite) setAttestResponse(challenges []challengeResponse) {
	svid, _, err := util.LoadSVIDFixture()
	s.Require().NoError(err)

	stream := mock_node.NewMockNode_AttestClient(s.ctrl)
	stream.EXPECT().Send(gomock.Any())
	for _, challenge := range challenges {
		stream.EXPECT().Send(gomock.Any())
		stream.EXPECT().Recv().Return(&node.AttestResponse{
			Challenge: []byte(challenge.challenge),
		}, nil)
	}
	stream.EXPECT().Recv().Return(&node.AttestResponse{
		SvidUpdate: &node.SvidUpdate{
			Svids: map[string]*node.Svid{
				"spiffe://example.com/spire/agent/join_token/foobar": &node.Svid{
					SvidCert: svid.Raw,
					Ttl:      300,
				}},
		}}, nil)
	stream.EXPECT().CloseSend()
	stream.EXPECT().Recv().Return(nil, io.EOF)

	s.nodeClient.EXPECT().Attest(gomock.Any()).Return(stream, nil)
}
