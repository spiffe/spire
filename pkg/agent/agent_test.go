package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/keymanager"
	"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/test/mock/agent/catalog"
	"github.com/stretchr/testify/suite"
)

type selectors []*common.Selector

type AgentTestSuite struct {
	suite.Suite
	t                 *testing.T
	agent             *Agent
	mockPluginCatalog *mock_catalog.MockCatalog
	mockKeyManager    *keymanager.MockKeyManager
	kmManager         []keymanager.KeyManager
	expectedKey       *ecdsa.PrivateKey
	config            *Config
}

func (suite *AgentTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(suite.t)
	defer mockCtrl.Finish()
	suite.mockPluginCatalog = mock_catalog.NewMockCatalog(mockCtrl)
	suite.mockKeyManager = keymanager.NewMockKeyManager(mockCtrl)

	addr := &net.UnixAddr{Name: "./spire_api", Net: "unix"}
	srvAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081}
	certDN := &pkix.Name{
		Country:      []string{"testCountry"},
		Organization: []string{"testOrg"}}
	errCh := make(chan error)
	shutdownCh := make(chan struct{})

	l, _ := test.NewNullLogger()
	suite.config = &Config{BindAddress: addr, CertDN: certDN,
		DataDir:   os.TempDir(),
		PluginDir: os.TempDir(), Log: l, ServerAddress: srvAddr,
		ErrorCh:    errCh,
		ShutdownCh: shutdownCh}

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
	suite.mockPluginCatalog.EXPECT().KeyManagers().Return(suite.kmManager, nil)
	suite.mockPluginCatalog.EXPECT().Run().Return(nil)
	suite.agent = &Agent{
		Catalog: suite.mockPluginCatalog,
		config:  suite.config}
	err := suite.agent.bootstrap()
	suite.Require().NoError(err)
	suite.Assert().Equal(expectedkey, suite.agent.baseSVIDKey)
}

// WIP(walmav)
func TestAgent_FetchSVID(t *testing.T) {
	tests := []struct {
		name        string
		regEntryMap map[string]*common.RegistrationEntry
	}{{
		name: "test",
		regEntryMap: map[string]*common.RegistrationEntry{"spiffe:test": &common.RegistrationEntry{
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
