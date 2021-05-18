package server

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/suite"
)

type ServerTestSuite struct {
	suite.Suite
	server *Server
	ds     *fakedatastore.DataStore
	stdout *bytes.Buffer
}

func (suite *ServerTestSuite) SetupTest() {
	suite.ds = fakedatastore.New(suite.T())

	suite.stdout = new(bytes.Buffer)
	logrusLevel, err := logrus.ParseLevel("DEBUG")
	suite.Nil(err)

	logger := logrus.New()
	logger.Out = suite.stdout
	logger.Level = logrusLevel

	suite.server = New(Config{
		Log:         logger,
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	})
}

func TestServerTestSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}

func (suite *ServerTestSuite) TestValidateTrustDomain() {
	ctx := context.Background()
	ds := suite.ds

	// Create default trust domain
	trustDomain, err := spiffeid.TrustDomainFromString("spiffe://test.com")
	suite.NoError(err)

	// Create new trust domain
	newTrustDomain, err := spiffeid.TrustDomainFromString("spiffe://new_test.com")
	suite.NoError(err)

	// Set trust domain to server
	suite.server.config.TrustDomain = trustDomain
	suite.NoError(err)

	// No attested nodes, not error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)

	// create attested node with current trust domain
	attestedNode, err := ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:            "spiffe://test.com/host",
		AttestationDataType: "fake_nodeattestor_1",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
		CertSerialNumber:    "18392437442709699290",
	})
	suite.NoError(err)

	// Validate created trust domain, no error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)

	// Update server trust domain to force errors
	suite.server.config.TrustDomain = newTrustDomain

	// Validate new trust domain
	err = suite.server.validateTrustDomain(ctx, ds)
	// no error expected, warning is displaying in this case
	suite.NoError(err)
	suite.Require().Contains(suite.stdout.String(), fmt.Sprintf(invalidTrustDomainAttestedNode, "test.com", "new_test.com"))

	// Restore original trust domain
	suite.server.config.TrustDomain = trustDomain

	// Create a registration entry with original trust domain
	registrationEntry, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId:  "spiffe://test.com/foo",
		Selectors: []*common.Selector{{Type: "TYPE", Value: "VALUE"}},
	})
	suite.NoError(err)

	// Attested node and registration entry have the same trust domain as server, no error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)

	// Update server's trust domain, error expected because invalid trust domain
	suite.server.config.TrustDomain = newTrustDomain
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.EqualError(err, fmt.Sprintf(invalidTrustDomainRegistrationEntry, "test.com", "new_test.com"))

	// Create a registration entry with an invalid url
	_, err = ds.DeleteRegistrationEntry(ctx, registrationEntry.EntryId)
	suite.NoError(err)
	suite.server.config.TrustDomain = trustDomain
	registrationEntry, err = ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId:  "spiffe://inv%ild/test",
		Selectors: []*common.Selector{{Type: "TYPE", Value: "VALUE"}},
	})
	suite.NoError(err)
	err = suite.server.validateTrustDomain(ctx, ds)
	expectedError := fmt.Sprintf(invalidSpiffeIDRegistrationEntry, registrationEntry.EntryId, "")
	if suite.Error(err) {
		suite.Contains(err.Error(), expectedError)
	}

	// remove entry to solve error
	_, err = ds.DeleteRegistrationEntry(ctx, registrationEntry.EntryId)
	suite.NoError(err)

	// create attested node with current trust domain
	// drop resp
	_, err = ds.DeleteAttestedNode(ctx, attestedNode.SpiffeId)
	suite.NoError(err)
	_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:            "spiffe://inv%ild/host",
		AttestationDataType: "fake_nodeattestor_1",
		CertNotAfter:        time.Now().Add(time.Hour).Unix(),
		CertSerialNumber:    "18392437442709699290",
	})
	suite.NoError(err)
	// Attested now with same trust domain created, no error expected
	err = suite.server.validateTrustDomain(ctx, ds)
	suite.NoError(err)
	suite.Require().Contains(suite.stdout.String(), invalidSpiffeIDAttestedNode)
}
