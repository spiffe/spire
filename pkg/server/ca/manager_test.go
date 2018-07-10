package ca

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/upstreamca"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/mock/proto/server/ca"
	"github.com/spiffe/spire/test/mock/proto/server/datastore"
	"github.com/spiffe/spire/test/mock/proto/server/upstreamca"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var (
	ctx = context.Background()
)

type ManagerTestSuite struct {
	suite.Suite

	m        *manager
	mockCtrl *gomock.Controller
	ca       *mock_ca.MockServerCA
	ds       *mock_datastore.MockDataStore
	upsCa    *mock_upstreamca.MockUpstreamCA
}

func (m *ManagerTestSuite) SetupTest() {
	m.mockCtrl = gomock.NewController(m.T())

	m.ca = mock_ca.NewMockServerCA(m.mockCtrl)
	m.ds = mock_datastore.NewMockDataStore(m.mockCtrl)
	m.upsCa = mock_upstreamca.NewMockUpstreamCA(m.mockCtrl)

	catalog := fakeservercatalog.New()
	catalog.SetCAs(m.ca)
	catalog.SetDataStores(m.ds)
	catalog.SetUpstreamCAs(m.upsCa)

	logger, err := log.NewLogger("DEBUG", "")
	m.NoError(err)

	config := &Config{
		Catalog: catalog,
		Log:     logger,
		TrustDomain: url.URL{
			Scheme: "spiffe",
			Host:   "example.org",
		},
	}

	m.m = New(config)
}

func (m *ManagerTestSuite) TearDownTest() {
	m.mockCtrl.Finish()
}

func TestManager(t *testing.T) {
	suite.Run(t, new(ManagerTestSuite))
}

func (m *ManagerTestSuite) TestInitializeWithPristineCA() {
	template, err := util.NewSVIDTemplate(m.m.c.TrustDomain.String())
	m.Require().NoError(err)
	cert, _, err := util.SelfSign(template)
	m.Require().NoError(err)

	// since the CA returns no certificate the manager should both
	// prepare and activate a new CA keypair.
	m.ca.EXPECT().FetchCertificate(gomock.Any(), gomock.Any()).Return(&ca.FetchCertificateResponse{}, nil)
	m.ca.EXPECT().GenerateCsr(gomock.Any(), gomock.Any()).Return(new(ca.GenerateCsrResponse), nil)
	m.upsCa.EXPECT().SubmitCSR(gomock.Any(), gomock.Any()).Return(&upstreamca.SubmitCSRResponse{Cert: cert.Raw}, nil)
	m.ds.EXPECT().AppendBundle(gomock.Any(), gomock.Any())
	m.ca.EXPECT().LoadCertificate(gomock.Any(), gomock.Any())
	m.Require().NoError(m.m.Initialize(ctx))
}

func (m *ManagerTestSuite) TestInitializeWithLoadedCA() {
	template, err := util.NewSVIDTemplate(m.m.c.TrustDomain.String())
	m.Require().NoError(err)
	cert, _, err := util.SelfSign(template)
	m.Require().NoError(err)

	// since the CA returns an unexpired certificate the manager should skip
	// preparing and activating a new CA keypair.
	m.ca.EXPECT().FetchCertificate(gomock.Any(), gomock.Any()).Return(&ca.FetchCertificateResponse{
		StoredIntermediateCert: cert.Raw,
	}, nil)
	m.Require().NoError(m.m.Initialize(ctx))
}

func (m *ManagerTestSuite) TestCARotate() {
	// Should return error when uninitialized
	m.Assert().Error(m.m.caRotate(ctx))

	// Should do nothing when called with new-ish cert
	template, err := util.NewSVIDTemplate(m.m.c.TrustDomain.String())
	cert1, _, err := util.SelfSign(template)
	m.Require().NoError(err)
	m.m.caCert = cert1
	m.Assert().NoError(m.m.caRotate(ctx))
	m.Assert().Equal(cert1, m.m.caCert)
	m.Assert().Nil(m.m.nextCACert)

	// Should call prepareNextCA() when past 50% of validity period
	template.NotBefore = time.Now().Add(-2 * time.Hour)
	template.NotAfter = time.Now().Add(1 * time.Hour)
	cert2, _, err := util.SelfSign(template)
	m.Require().NoError(err)
	m.m.caCert = cert2

	resp := &upstreamca.SubmitCSRResponse{Cert: cert1.Raw}
	m.ca.EXPECT().GenerateCsr(gomock.Any(), gomock.Any()).Return(new(ca.GenerateCsrResponse), nil)
	m.upsCa.EXPECT().SubmitCSR(gomock.Any(), gomock.Any()).Return(resp, nil)
	m.ds.EXPECT().AppendBundle(gomock.Any(), gomock.Any())
	m.Assert().NoError(m.m.caRotate(ctx))
	m.Assert().Equal(cert1, m.m.nextCACert)

	// Should call activateNextCA() when we're almost expired
	template.NotBefore = time.Now().Add(-2 * time.Hour)
	template.NotAfter = time.Now().Add(1 * time.Minute)
	cert3, _, err := util.SelfSign(template)
	m.Require().NoError(err)
	m.m.caCert = cert3
	m.ca.EXPECT().LoadCertificate(gomock.Any(), gomock.Any())
	m.Assert().NoError(m.m.caRotate(ctx))
	m.Assert().Equal(cert1, m.m.caCert)
	m.Assert().Nil(m.m.nextCACert)

	// If the ttl has expired, or has almost expired, but the new CA hasn't
	// been prepared yet due to the rotation interval, make sure the CA is both
	// prepared and activated on the same rotation call (issue #501)
	template.NotBefore = time.Now().Add(-3 * time.Hour)
	template.NotAfter = time.Now().Add(-2 * time.Hour)
	cert4, _, err := util.SelfSign(template)
	m.Require().NoError(err)
	m.m.caCert = cert4
	m.ca.EXPECT().GenerateCsr(gomock.Any(), gomock.Any()).Return(new(ca.GenerateCsrResponse), nil)
	m.upsCa.EXPECT().SubmitCSR(gomock.Any(), gomock.Any()).Return(resp, nil)
	m.ds.EXPECT().AppendBundle(gomock.Any(), gomock.Any())
	m.ca.EXPECT().LoadCertificate(gomock.Any(), gomock.Any())
	m.Assert().NoError(m.m.caRotate(ctx))
	m.Assert().Equal(cert1, m.m.caCert)
	m.Assert().Nil(m.m.nextCACert)
}

func (m *ManagerTestSuite) TestPrepareNextCA() {
	cert, _, err := util.LoadSVIDFixture()
	m.Require().NoError(err)

	resp := &upstreamca.SubmitCSRResponse{Cert: cert.Raw}
	m.ca.EXPECT().GenerateCsr(gomock.Any(), gomock.Any()).Return(new(ca.GenerateCsrResponse), nil)
	m.upsCa.EXPECT().SubmitCSR(gomock.Any(), gomock.Any()).Return(resp, nil)

	req := &datastore.Bundle{
		TrustDomain: m.m.c.TrustDomain.String(),
		CaCerts:     cert.Raw,
	}
	m.ds.EXPECT().AppendBundle(gomock.Any(), req)

	m.Assert().NoError(m.m.prepareNextCA(ctx))
	m.Assert().Equal(cert, m.m.nextCACert)
}

func (m *ManagerTestSuite) TestActivateNextCA() {
	// Should return error if we're not ready
	m.Assert().Error(m.m.activateNextCA(ctx))

	cert, _, err := util.LoadSVIDFixture()
	m.Require().NoError(err)
	m.m.nextCACert = cert

	req := &ca.LoadCertificateRequest{SignedIntermediateCert: cert.Raw}
	m.ca.EXPECT().LoadCertificate(gomock.Any(), req)

	m.Assert().NoError(m.m.activateNextCA(ctx))
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
	oldBundle := &datastore.Bundle{
		TrustDomain: m.m.c.TrustDomain.String(),
		CaCerts:     caCerts,
	}
	m.ds.EXPECT().FetchBundle(gomock.Any(), gomock.Any()).Return(oldBundle, nil)

	// Expect only ca2 to be pruned
	newBundle := &datastore.Bundle{
		TrustDomain: m.m.c.TrustDomain.String(),
		CaCerts:     ca1.Raw,
	}
	m.ds.EXPECT().UpdateBundle(gomock.Any(), newBundle).Return(newBundle, nil)

	err = m.m.prune(ctx)
	m.Assert().NoError(err)

	// Pruning should not occur in steady state
	m.ds.EXPECT().FetchBundle(gomock.Any(), gomock.Any()).Return(newBundle, nil)
	m.ds.EXPECT().UpdateBundle(gomock.Any(), gomock.Any()).Times(0)
	err = m.m.prune(ctx)
	m.Assert().NoError(err)

	// Pruning should not occur if all certs will be removed
	badBundle := &datastore.Bundle{
		TrustDomain: m.m.c.TrustDomain.String(),
		CaCerts:     ca2.Raw,
	}
	m.ds.EXPECT().FetchBundle(gomock.Any(), gomock.Any()).Return(badBundle, nil)
	m.ds.EXPECT().UpdateBundle(gomock.Any(), gomock.Any()).Times(0)
	err = m.m.prune(ctx)
	m.Assert().Error(err)
}

func (m *ManagerTestSuite) TestPruner() {
	// Pruner shouldn't exit on pruning error
	m.ds.EXPECT().FetchBundle(gomock.Any(), gomock.Any()).Return(nil, errors.New("i'm an error")).MinTimes(1)

	ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	errch := make(chan error, 1)
	go func() {
		errch <- m.m.startPruner(ctx, 25*time.Millisecond)
	}()

	select {
	case <-time.NewTimer(time.Second).C:
		m.T().Fatalf("timed out waiting for pruner to exit.")
	case err := <-errch:
		m.Assert().NoError(err)
	}
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
	m.ds.EXPECT().AppendBundle(gomock.Any(), req)

	m.Assert().NoError(m.m.storeCACert(ctx, cert, upstream.Raw))

	// With upstream bundle enabled
	m.m.c.UpstreamBundle = true
	req.CaCerts = append(req.CaCerts, upstream.Raw...)
	m.ds.EXPECT().AppendBundle(gomock.Any(), req)

	m.Assert().NoError(m.m.storeCACert(ctx, cert, upstream.Raw))
}
