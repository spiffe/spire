package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"net"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/agent/keymanager"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/agent/cache"
	"github.com/spiffe/spire/test/mock/agent/catalog"
	"github.com/spiffe/spire/test/mock/proto/agent/keymanager"
	"github.com/stretchr/testify/suite"
)

type selectors []*common.Selector

type AgentTestSuite struct {
	suite.Suite
	t                 *testing.T
	agent             *Agent
	mockPluginCatalog *mock_catalog.MockCatalog
	mockKeyManager    *mock_keymanager.MockKeyManager
	kmManager         []keymanager.KeyManager
	mockCacheManager  *mock_cache.MockManager
	expectedKey       *ecdsa.PrivateKey
	config            *Config
}

func (suite *AgentTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(suite.t)
	defer mockCtrl.Finish()
	suite.mockPluginCatalog = mock_catalog.NewMockCatalog(mockCtrl)
	suite.mockKeyManager = mock_keymanager.NewMockKeyManager(mockCtrl)
	suite.mockCacheManager = mock_cache.NewMockManager(mockCtrl)

	addr := &net.UnixAddr{Name: "./spire_api", Net: "unix"}
	srvAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081}
	certDN := &pkix.Name{
		Country:      []string{"testCountry"},
		Organization: []string{"testOrg"}}
	errCh := make(chan error)

	l, _ := test.NewNullLogger()
	suite.config = &Config{BindAddress: addr, CertDN: certDN,
		DataDir: os.TempDir(),
		Log:     l, ServerAddress: srvAddr,
		ErrorCh: errCh,
	}

}

func TestNodeServiceTestSuite(t *testing.T) {
	suite.Run(t, new(AgentTestSuite))
}

func (suite *AgentTestSuite) Testbootstrap() {
	expectedkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	suite.expectedKey = expectedkey
	expectedPublicKey, _ := x509.MarshalPKIXPublicKey(expectedkey)
	expectedPrivateKey, _ := x509.MarshalECPrivateKey(expectedkey)

	kmresp := &keymanager.GenerateKeyPairResponse{
		PublicKey: expectedPublicKey, PrivateKey: expectedPrivateKey}
	kmreq := &keymanager.GenerateKeyPairRequest{}
	suite.mockKeyManager.EXPECT().GenerateKeyPair(
		kmreq).Return(kmresp, nil)
	suite.mockKeyManager.EXPECT().FetchPrivateKey(&keymanager.FetchPrivateKeyRequest{}).Return(
		&keymanager.FetchPrivateKeyResponse{expectedPrivateKey}, nil)
	suite.kmManager = append(suite.kmManager, suite.mockKeyManager)
	suite.mockPluginCatalog.EXPECT().KeyManagers().Return(suite.kmManager)
	suite.mockPluginCatalog.EXPECT().Run().Return(nil)
	suite.agent = &Agent{
		Catalog: suite.mockPluginCatalog,
		config:  suite.config}
	err := suite.agent.bootstrap()
	suite.Require().NoError(err)
	suite.Assert().Equal(expectedkey, suite.agent.baseSVIDKey)
}

func (suite *AgentTestSuite) TestSocketPermission() {
	suite.agent = &Agent{
		Catalog:  suite.mockPluginCatalog,
		CacheMgr: suite.mockCacheManager,
		config:   suite.config}

	suite.agent.serverCerts = []*x509.Certificate{{}, {}}
	suite.mockCacheManager.EXPECT().Cache().Return(nil)
	err := suite.agent.initEndpoints()
	suite.Require().NoError(err)

	info, err := os.Stat("./spire_api")
	suite.Require().NoError(err)
	suite.Assert().Equal(os.ModePerm|os.ModeSocket, info.Mode())
}

func (suite *AgentTestSuite) TestUmask() {
	suite.agent = &Agent{
		config: suite.config}

	suite.agent.config.Umask = 0000
	suite.agent.prepareUmask()
	f, err := ioutil.TempFile("", "")
	suite.Nil(err)
	defer os.Remove(f.Name())
	fi, err := os.Stat(f.Name())
	suite.Nil(err)
	suite.Equal(os.FileMode(0600), fi.Mode().Perm()) //0600 is permission set by TempFile()

	suite.agent.config.Umask = 0777
	suite.agent.prepareUmask()
	f, err = ioutil.TempFile("", "")
	suite.Nil(err)
	defer os.Remove(f.Name())
	fi, err = os.Stat(f.Name())
	suite.Nil(err)
	suite.Equal(os.FileMode(0000), fi.Mode().Perm())
}

// WIP(walmav)
func TestAgent_FetchSVID(t *testing.T) {
	tests := []struct {
		name        string
		regEntryMap map[string]*common.RegistrationEntry
	}{{
		name: "test",
		regEntryMap: map[string]*common.RegistrationEntry{"spiffe:test": {
			Selectors: selectors{&common.Selector{Type: "testtype", Value: "testValue"}},
			ParentId:  "spiffe:parent",
			SpiffeId:  "spiffe:test"}},
	},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

		})
	}
}
