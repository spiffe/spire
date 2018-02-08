package ca

import (
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/upstreamca"
	"github.com/spiffe/spire/test/mock/proto/server/ca"
	"github.com/spiffe/spire/test/mock/proto/server/datastore"
	"github.com/spiffe/spire/test/mock/proto/server/upstreamca"
	"github.com/spiffe/spire/test/mock/server/catalog"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ServerTestSuite struct {
	suite.Suite

	t       *testing.T
	m       *manager
	catalog *mock_catalog.MockCatalog
	ca      *mock_ca.MockControlPlaneCa
	ds      *mock_datastore.MockDataStore
	upsCa   *mock_upstreamca.MockUpstreamCa
}

func (s *ServerTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.t)
	defer mockCtrl.Finish()

	s.catalog = mock_catalog.NewMockCatalog(mockCtrl)
	s.ca = mock_ca.NewMockControlPlaneCa(mockCtrl)
	s.ds = mock_datastore.NewMockDataStore(mockCtrl)
	s.upsCa = mock_upstreamca.NewMockUpstreamCa(mockCtrl)

	logger, err := log.NewLogger("DEBUG", "")
	s.Nil(err)

	config := &Config{
		Catalog: s.catalog,
		Log:     logger,
		TrustDomain: url.URL{
			Scheme: "spiffe",
			Host:   "example.org",
		},
	}

	s.m = New(config)
}

func (s *ServerTestSuite) TestRotateSigningCert() {
	cert, _, err := util.LoadSVIDFixture()
	require.NoError(s.T(), err)

	// Set expectations
	s.catalog.EXPECT().CAs().Return([]ca.ControlPlaneCa{s.ca})
	s.catalog.EXPECT().DataStores().Return([]datastore.DataStore{s.ds})
	s.catalog.EXPECT().UpstreamCAs().Return([]upstreamca.UpstreamCa{s.upsCa})

	generateCsrResponse := &ca.GenerateCsrResponse{}
	s.ca.EXPECT().GenerateCsr(&ca.GenerateCsrRequest{}).Return(generateCsrResponse, nil)
	submitCSRResponse := &upstreamca.SubmitCSRResponse{
		Cert: cert.Raw,
	}
	s.upsCa.EXPECT().SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: generateCsrResponse.Csr}).Return(submitCSRResponse, nil)

	dsBundle := &datastore.Bundle{
		TrustDomain: "spiffe://example.org",
		CaCerts:     cert.Raw,
	}
	s.ds.EXPECT().AppendBundle(dsBundle).Return(dsBundle)

	loadCertificateResponse := &ca.LoadCertificateResponse{}
	s.ca.EXPECT().LoadCertificate(&ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResponse.Cert}).Return(loadCertificateResponse, nil)

	err = s.m.rotateCA()
	s.NoError(err)
	s.Equal(cert, s.m.caCert)
}
