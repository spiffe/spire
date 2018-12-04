package server

import (
	"context"
	"io/ioutil"
	"net/url"
	"os"
	"testing"

	"fmt"

	"bytes"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/mock/proto/server/upstreamca"
	"github.com/spiffe/spire/test/mock/server/catalog"
	"github.com/stretchr/testify/suite"
)

type ServerTestSuite struct {
	suite.Suite
	server  *Server
	catalog *mock_catalog.MockCatalog
	upsCa   *mock_upstreamca.MockUpstreamCA
	ds      *fakedatastore.DataStore
	stdout  *bytes.Buffer

	mockCtrl *gomock.Controller
}

func (suite *ServerTestSuite) SetupTest() {
	suite.mockCtrl = gomock.NewController(suite.T())

	suite.catalog = mock_catalog.NewMockCatalog(suite.mockCtrl)
	suite.ds = fakedatastore.New()
	suite.upsCa = mock_upstreamca.NewMockUpstreamCA(suite.mockCtrl)

	suite.stdout = new(bytes.Buffer)
	logrusLevel, err := logrus.ParseLevel("DEBUG")
	suite.Nil(err)

	logger := logrus.New()
	logger.Out = suite.stdout
	logger.Level = logrusLevel

	suite.server = New(Config{
		Log: logger,
		TrustDomain: url.URL{
			Scheme: "spiffe",
			Host:   "example.org",
		},
	})
}

func (s *ServerTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
}

func TestServerTestSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}

func (suite *ServerTestSuite) TestUmask() {
	suite.server.config.Umask = 0000
	suite.server.prepareUmask()
	f, err := ioutil.TempFile("", "")
	suite.Nil(err)
	defer os.Remove(f.Name())
	fi, err := os.Stat(f.Name())
	suite.Nil(err)
	suite.Equal(os.FileMode(0600), fi.Mode().Perm()) //0600 is permission set by TempFile()

	suite.server.config.Umask = 0777
	suite.server.prepareUmask()
	f, err = ioutil.TempFile("", "")
	suite.Nil(err)
	defer os.Remove(f.Name())
	fi, err = os.Stat(f.Name())
	suite.Nil(err)
	suite.Equal(os.FileMode(0000), fi.Mode().Perm())
}

func (suite *ServerTestSuite) TestValidateTrustDomain() {
	ctx := context.Background()
	ds := suite.ds

	// Create default trust domain
	trustDomain := "spiffe://test.com"
	uri, err := url.Parse(trustDomain)
	suite.NoError(err)

	// Create new trust domain
	newTrustDomain := "spiffe://new_test.com"
	newUri, err := url.Parse(newTrustDomain)
	suite.NoError(err)

	// Set trust domain to server
	suite.server.config.TrustDomain = *uri
	suite.NoError(err)

	// No attested nodes, not error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)

	// create attested node with current trust domain
	ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{
		Node: &datastore.AttestedNode{
			SpiffeId:            "spiffe://test.com/host",
			AttestationDataType: "fake_nodeattestor_1",
			CertNotAfter:        1822684794,
			CertSerialNumber:    "18392437442709699290",
		},
	})

	// Attested now with same trust domain created, no error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)

	// Update server trust domain to force errors
	suite.server.config.TrustDomain = *newUri

	// Update server's trust domain, error expected because invalid trust domain
	err = suite.server.validateTrustDomain(ctx, ds)
	// no error expected, warning is displaying in this case
	suite.NoError(err)
	suite.Require().Contains(suite.stdout.String(), fmt.Sprintf(invalidTrustDomainAttestedNode, "test.com", "new_test.com"))

	// Back server's trust domain
	suite.server.config.TrustDomain = *uri

	// Create a registration entry with original trust domain
	ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
		Entry: &common.RegistrationEntry{
			SpiffeId:  "spiffe://test.com/foo",
			Selectors: []*common.Selector{{Type: "TYPE", Value: "VALUE"}},
		},
	})

	// Attested node and registration entry have the same trust domain as server, no error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)

	// Update server's trust domain, error expected because invalid trust domain
	suite.server.config.TrustDomain = *newUri
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.EqualError(err, fmt.Sprintf(invalidTrustDomainRegistrationEntry, "test.com", "new_test.com"))
}
