package agent

import (
	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/stretchr/testify/suite"
	"testing"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"

	"crypto/x509"
	"github.com/hashicorp/go-plugin"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/proto/agent/keymanager"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"net"
	"os"
)

type selectors []*common.Selector

type AgentTestSuite struct {
	suite.Suite
	t                 *testing.T
	agent             *Agent
	mockPluginCatalog *sriplugin.MockPluginCatalogInterface
	mockKeyManager    *keymanager.MockKeyManager
	kmManager         []interface{}
	expectedKey       *ecdsa.PrivateKey
	config            *Config
}

func (suite *AgentTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(suite.t)
	defer mockCtrl.Finish()
	suite.mockPluginCatalog = sriplugin.NewMockPluginCatalogInterface(mockCtrl)
	suite.mockKeyManager = keymanager.NewMockKeyManager(mockCtrl)

	addr := &net.TCPAddr{net.ParseIP("127.0.0.1"), 8086, ""}
	certDN := &pkix.Name{
		Country:      []string{"testCountry"},
		Organization: []string{"testOrg"}}
	errCh := make(chan error)
	shutdownCh := make(chan struct{})

	suite.config = &Config{BindAddress: addr, CertDN: certDN,
		DataDir:   os.TempDir(),
		PluginDir: os.TempDir(), Log: logrus.StandardLogger(), ServerAddress: addr,
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
	suite.mockPluginCatalog.EXPECT().GetPluginsByType("KeyManager").Return(suite.kmManager)
	suite.mockPluginCatalog.EXPECT().Run().Return(nil)
	suite.mockPluginCatalog.EXPECT().SetMaxPluginTypeMap(map[string]int{"KeyManager": 1, "NodeAttestor": 1, "WorkloadAttestor": 1})
	suite.mockPluginCatalog.EXPECT().SetPluginTypeMap(map[string]plugin.Plugin{
		"KeyManager":       &keymanager.KeyManagerPlugin{},
		"NodeAttestor":     &nodeattestor.NodeAttestorPlugin{},
		"WorkloadAttestor": &workloadattestor.WorkloadAttestorPlugin{},
	})
	suite.agent = &Agent{
		pluginCatalog: suite.mockPluginCatalog,
		config:        suite.config}
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
