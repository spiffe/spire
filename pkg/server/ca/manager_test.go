package ca

import (
	"errors"
	"net/url"
	"testing"
	"time"

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

type ManagerTestSuite struct {
	suite.Suite

	t       *testing.T
	m       *manager
	catalog *mock_catalog.MockCatalog
	ca      *mock_ca.MockServerCa
	ds      *mock_datastore.MockDataStore
	upsCa   *mock_upstreamca.MockUpstreamCa
}

func (m *ManagerTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(m.t)
	defer mockCtrl.Finish()

	m.catalog = mock_catalog.NewMockCatalog(mockCtrl)
	m.ca = mock_ca.NewMockServerCa(mockCtrl)
	m.ds = mock_datastore.NewMockDataStore(mockCtrl)
	m.upsCa = mock_upstreamca.NewMockUpstreamCa(mockCtrl)

	logger, err := log.NewLogger("DEBUG", "")
	m.Nil(err)

	config := &Config{
		Catalog: m.catalog,
		Log:     logger,
		TrustDomain: url.URL{
			Scheme: "spiffe",
			Host:   "example.org",
		},
	}

	m.m = New(config)
}

func TestManager(t *testing.T) {
	suite.Run(t, new(ManagerTestSuite))
}

func (m *ManagerTestSuite) TestCARotate() {
	// Should return error when uninitialized
	m.Assert().Error(m.m.caRotate())

	// Should do nothing when called with new-ish cert
	template, err := util.NewSVIDTemplate(m.m.c.TrustDomain.String())
	cert1, _, err := util.SelfSign(template)
	m.Require().NoError(err)
	m.m.caCert = cert1
	m.Assert().NoError(m.m.caRotate())
	m.Assert().Equal(cert1, m.m.caCert)
	m.Assert().Nil(m.m.nextCACert)

	m.catalog.EXPECT().CAs().Return([]ca.ServerCa{m.ca})
	m.catalog.EXPECT().DataStores().Return([]datastore.DataStore{m.ds})
	m.catalog.EXPECT().UpstreamCAs().Return([]upstreamca.UpstreamCa{m.upsCa})

	// Should call prepareNextCA() when past 50% of validity period
	template.NotBefore = time.Now().Add(-2 * time.Hour)
	template.NotAfter = time.Now().Add(1 * time.Hour)
	cert2, _, err := util.SelfSign(template)
	m.Require().NoError(err)
	m.m.caCert = cert2

	resp := &upstreamca.SubmitCSRResponse{Cert: cert1.Raw}
	m.ca.EXPECT().GenerateCsr(gomock.Any()).Return(new(ca.GenerateCsrResponse), nil)
	m.upsCa.EXPECT().SubmitCSR(gomock.Any()).Return(resp, nil)
	m.ds.EXPECT().AppendBundle(gomock.Any())
	m.Assert().NoError(m.m.caRotate())
	m.Assert().Equal(cert1, m.m.nextCACert)

	m.catalog.EXPECT().CAs().Return([]ca.ServerCa{m.ca})
	m.catalog.EXPECT().DataStores().Return([]datastore.DataStore{m.ds})
	m.catalog.EXPECT().UpstreamCAs().Return([]upstreamca.UpstreamCa{m.upsCa})

	// Should call activateNextCA() when we're almost expired
	template.NotBefore = time.Now().Add(-2 * time.Hour)
	template.NotAfter = time.Now().Add(1 * time.Minute)
	cert3, _, err := util.SelfSign(template)
	m.Require().NoError(err)
	m.m.caCert = cert3
	m.ca.EXPECT().LoadCertificate(gomock.Any())
	m.Assert().NoError(m.m.caRotate())
	m.Assert().Equal(cert1, m.m.caCert)
	m.Assert().Nil(m.m.nextCACert)
}

func (m *ManagerTestSuite) TestPrepareNextCA() {
	m.catalog.EXPECT().CAs().Return([]ca.ServerCa{m.ca})
	m.catalog.EXPECT().DataStores().Return([]datastore.DataStore{m.ds})
	m.catalog.EXPECT().UpstreamCAs().Return([]upstreamca.UpstreamCa{m.upsCa})

	cert, _, err := util.LoadSVIDFixture()
	m.Require().NoError(err)

	resp := &upstreamca.SubmitCSRResponse{Cert: cert.Raw}
	m.ca.EXPECT().GenerateCsr(gomock.Any()).Return(new(ca.GenerateCsrResponse), nil)
	m.upsCa.EXPECT().SubmitCSR(gomock.Any()).Return(resp, nil)

	req := &datastore.Bundle{
		TrustDomain: m.m.c.TrustDomain.String(),
		CaCerts:     cert.Raw,
	}
	m.ds.EXPECT().AppendBundle(req)

	m.Assert().NoError(m.m.prepareNextCA())
	m.Assert().Equal(cert, m.m.nextCACert)
}

func (m *ManagerTestSuite) TestActivateNextCA() {
	// Should return error if we're not ready
	m.Assert().Error(m.m.activateNextCA())

	cert, _, err := util.LoadSVIDFixture()
	m.Require().NoError(err)
	m.m.nextCACert = cert

	m.catalog.EXPECT().CAs().Return([]ca.ServerCa{m.ca})
	req := &ca.LoadCertificateRequest{cert.Raw}
	m.ca.EXPECT().LoadCertificate(req)

	m.Assert().NoError(m.m.activateNextCA())
	m.Assert().Equal(cert, m.m.caCert)
	m.Assert().Nil(m.m.nextCACert)
}

func (m *ManagerTestSuite) TestPrune() {
	template, err := util.NewSVIDTemplate(m.m.c.TrustDomain.String())
	template.NotAfter = time.Now()
	ca1, _, err := util.SelfSign(template)
	require.NoError(m.T(), err)

	template.NotAfter = time.Now().Add(-48 * time.Hour)
	ca2, _, err := util.SelfSign(template)
	require.NoError(m.T(), err)

	caCerts := ca1.Raw
	caCerts = append(caCerts, ca2.Raw...)
	m.catalog.EXPECT().DataStores().Return([]datastore.DataStore{m.ds}).AnyTimes()
	oldBundle := &datastore.Bundle{
		TrustDomain: m.m.c.TrustDomain.String(),
		CaCerts:     caCerts,
	}
	m.ds.EXPECT().FetchBundle(gomock.Any()).Return(oldBundle, nil)

	// Expect only ca2 to be pruned
	newBundle := &datastore.Bundle{
		TrustDomain: m.m.c.TrustDomain.String(),
		CaCerts:     ca1.Raw,
	}
	m.ds.EXPECT().UpdateBundle(newBundle).Return(newBundle, nil)

	err = m.m.prune()
	m.Assert().NoError(err)

	// Pruning should not occur in steady state
	m.ds.EXPECT().FetchBundle(gomock.Any()).Return(newBundle, nil)
	m.ds.EXPECT().UpdateBundle(gomock.Any()).Times(0)
	err = m.m.prune()
	m.Assert().NoError(err)

	// Pruning should not occur if all certs will be removed
	badBundle := &datastore.Bundle{
		TrustDomain: m.m.c.TrustDomain.String(),
		CaCerts:     ca2.Raw,
	}
	m.ds.EXPECT().FetchBundle(gomock.Any()).Return(badBundle, nil)
	m.ds.EXPECT().UpdateBundle(gomock.Any()).Times(0)
	err = m.m.prune()
	m.Assert().Error(err)
}

func (m *ManagerTestSuite) TestPruner() {
	// Pruner shouldn't exit on pruning error
	m.catalog.EXPECT().DataStores().Return([]datastore.DataStore{m.ds}).MinTimes(1)
	m.ds.EXPECT().FetchBundle(gomock.Any()).Return(nil, errors.New("i'm an error")).MinTimes(1)

	m.m.pruneTicker = time.NewTicker(1 * time.Millisecond)
	m.m.t.Go(m.m.startPruner)
	time.Sleep(2 * time.Millisecond)
	m.Assert().True(m.m.t.Alive())

	// Pruner should shut down when we tell it to
	m.m.t.Kill(nil)
	m.Assert().False(m.m.t.Alive())
}

func (m *ManagerTestSuite) TestStoreCACert() {
	cert, _, err := util.LoadSVIDFixture()
	m.Require().NoError(err)
	upstream, _, err := util.LoadCAFixture()
	m.Require().NoError(err)

	// With upstream bundle disabled
	m.m.c.UpstreamBundle = false
	req := &datastore.Bundle{
		TrustDomain: m.m.c.TrustDomain.String(),
		CaCerts:     cert.Raw,
	}
	m.catalog.EXPECT().DataStores().Return([]datastore.DataStore{m.ds})
	m.ds.EXPECT().AppendBundle(req)

	m.Assert().NoError(m.m.storeCACert(cert, upstream.Raw))

	// With upstream bundle enabled
	m.m.c.UpstreamBundle = true
	req.CaCerts = append(req.CaCerts, upstream.Raw...)
	m.catalog.EXPECT().DataStores().Return([]datastore.DataStore{m.ds})
	m.ds.EXPECT().AppendBundle(req)

	m.Assert().NoError(m.m.storeCACert(cert, upstream.Raw))
}
