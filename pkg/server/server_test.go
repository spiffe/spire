package server

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	mock_upstreamca "github.com/spiffe/spire/test/mock/plugin/server/upstreamca"
	"github.com/stretchr/testify/suite"
)

type ServerTestSuite struct {
	suite.Suite
	server *Server
	upsCa  *mock_upstreamca.MockUpstreamCA
	ds     *fakedatastore.DataStore
	stdout *bytes.Buffer

	mockCtrl *gomock.Controller
}

func (suite *ServerTestSuite) SetupTest() {
	suite.mockCtrl = gomock.NewController(suite.T())

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

func (suite *ServerTestSuite) TearDownTest() {
	suite.mockCtrl.Finish()
}

func TestServerTestSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
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
	newURI, err := url.Parse(newTrustDomain)
	suite.NoError(err)

	// Set trust domain to server
	suite.server.config.TrustDomain = *uri
	suite.NoError(err)

	// No attested nodes, not error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)

	// create attested node with current trust domain
	_, err = ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{
		Node: &common.AttestedNode{
			SpiffeId:            "spiffe://test.com/host",
			AttestationDataType: "fake_nodeattestor_1",
			CertNotAfter:        1822684794,
			CertSerialNumber:    "18392437442709699290",
		},
	})
	suite.NoError(err)

	// Attested now with same trust domain created, no error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)

	// Update server trust domain to force errors
	suite.server.config.TrustDomain = *newURI

	// Update server's trust domain, error expected because invalid trust domain
	err = suite.server.validateTrustDomain(ctx, ds)
	// no error expected, warning is displaying in this case
	suite.NoError(err)
	suite.Require().Contains(suite.stdout.String(), fmt.Sprintf(invalidTrustDomainAttestedNode, "test.com", "new_test.com"))

	// Back server's trust domain
	suite.server.config.TrustDomain = *uri

	// Create a registration entry with original trust domain
	_, err = ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
		Entry: &common.RegistrationEntry{
			SpiffeId:  "spiffe://test.com/foo",
			Selectors: []*common.Selector{{Type: "TYPE", Value: "VALUE"}},
		},
	})
	suite.NoError(err)

	// Attested node and registration entry have the same trust domain as server, no error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)

	// Update server's trust domain, error expected because invalid trust domain
	suite.server.config.TrustDomain = *newURI
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.EqualError(err, fmt.Sprintf(invalidTrustDomainRegistrationEntry, "test.com", "new_test.com"))

	// Create a registration entry with an invalid url
	suite.server.config.TrustDomain = *uri
	resp, err := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
		Entry: &common.RegistrationEntry{
			SpiffeId:  "spiffe://inv%ild/test",
			Selectors: []*common.Selector{{Type: "TYPE", Value: "VALUE"}},
		},
	})
	suite.NoError(err)
	err = suite.server.validateTrustDomain(ctx, ds)
	expectedError := fmt.Sprintf(invalidSpiffeIDRegistrationEntry, resp.Entry.EntryId, "")
	suite.Contains(err.Error(), expectedError)

	// remove entry to solve error
	_, err = ds.DeleteRegistrationEntry(ctx, &datastore.DeleteRegistrationEntryRequest{
		EntryId: resp.Entry.EntryId,
	})
	suite.NoError(err)

	// create attested node with current trust domain
	// drop resp
	_, err = ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{
		Node: &common.AttestedNode{
			SpiffeId:            "spiffe://inv%ild/host",
			AttestationDataType: "fake_nodeattestor_1",
			CertNotAfter:        1822684794,
			CertSerialNumber:    "18392437442709699290",
		},
	})
	suite.NoError(err)
	// Attested now with same trust domain created, no error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)
	suite.Require().Contains(suite.stdout.String(), invalidSpiffeIDAttestedNode)
}
