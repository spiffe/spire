package ca

import (
	"context"
	"crypto/x509"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/memory"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeupstreamca"
	"github.com/stretchr/testify/suite"
)

var (
	ctx = context.Background()
)

func TestManager(t *testing.T) {
	suite.Run(t, new(ManagerTestSuite))
}

type ManagerTestSuite struct {
	suite.Suite
	tmpDir string

	keymanager *memory.KeyManager
	datastore  *fakedatastore.DataStore
	catalog    *fakeservercatalog.Catalog
	m          *manager

	mu  sync.Mutex
	now time.Time
}

func (m *ManagerTestSuite) SetupTest() {
	tmpDir, err := ioutil.TempDir("", "server-ca-manager-")
	m.Require().NoError(err)
	m.tmpDir = tmpDir

	m.keymanager = memory.New()
	m.datastore = fakedatastore.New()

	m.catalog = fakeservercatalog.New()
	m.catalog.SetKeyManagers(m.keymanager)
	m.catalog.SetDataStores(m.datastore)

	logger, err := log.NewLogger("DEBUG", "")
	m.NoError(err)

	config := &ManagerConfig{
		Catalog: m.catalog,
		Log:     logger,
		TrustDomain: url.URL{
			Scheme: "spiffe",
			Host:   "example.org",
		},
		UpstreamBundle: true,
		CertsPath:      m.certsPath(),
	}

	m.m = NewManager(config)
	m.m.hooks.now = m.nowHook
	m.now = time.Now().Truncate(time.Second).UTC()
}

func (m *ManagerTestSuite) TearDownTest() {
	os.RemoveAll(m.tmpDir)
}

func (m *ManagerTestSuite) certsPath() string {
	return filepath.Join(m.tmpDir, "certs.json")
}

func (m *ManagerTestSuite) nowHook() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now
}

func (m *ManagerTestSuite) setTime(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
}

func (m *ManagerTestSuite) advanceTime(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = m.now.Add(d).Truncate(time.Second)
}

func (m *ManagerTestSuite) loadKeypairSets() (a, b *keypairSet) {
	certs, err := loadCertificates(m.certsPath())
	m.Require().NoError(err)
	xa := certs["x509-CA-A"]
	ja := certs["JWT-Signer-A"]
	xb := certs["x509-CA-B"]
	jb := certs["JWT-Signer-B"]
	m.Require().True((xa != nil) == (ja != nil))
	m.Require().True((xb != nil) == (jb != nil))

	if xa != nil {
		a = &keypairSet{
			slot:      "A",
			x509CA:    xa,
			jwtSigner: ja,
		}
	}
	if xb != nil {
		b = &keypairSet{
			slot:      "B",
			x509CA:    xb,
			jwtSigner: jb,
		}
	}
	return a, b
}

func (m *ManagerTestSuite) TestPersistence() {
	// initialize a new keypair set
	m.Require().NoError(m.m.Initialize(ctx))
	current1 := m.m.getCurrentKeypairSet()

	// "reload" the manager and assert the keypairs are the same
	m.m = NewManager(m.m.c)
	m.Require().NoError(m.m.Initialize(ctx))
	current2 := m.m.getCurrentKeypairSet()
	m.Require().Equal(current1, current2)

	// drop the keys, "reload" the manager, and assert the keypairs are new
	m.catalog.SetKeyManagers(memory.New())
	m.m = NewManager(m.m.c)
	m.Require().NoError(m.m.Initialize(ctx))
	current3 := m.m.getCurrentKeypairSet()
	m.Require().NotEqual(current2, current3)

	// load the old keys, "reload" the manager, and assert the keypairs are new
	m.catalog.SetKeyManagers(m.keymanager)
	m.m = NewManager(m.m.c)
	m.Require().NoError(m.m.Initialize(ctx))
	current4 := m.m.getCurrentKeypairSet()
	m.Require().NotEqual(current3, current4)
}

func (m *ManagerTestSuite) TestSelfSigning() {
	// generate a keypair make sure it was signed up upstream and that
	// the upstream cert is in the bundle
	m.Require().NoError(m.m.Initialize(ctx))
	a := m.m.getCurrentKeypairSet()
	m.Require().Equal(a.x509CA.Subject, a.x509CA.Issuer)
	m.Require().Equal(a.x509CA.Subject, a.jwtSigner.Issuer)
	m.requireBundle(a.x509CA, a.jwtSigner)
}

func (m *ManagerTestSuite) TestUpstreamSigning() {
	upstreamCA := fakeupstreamca.New(m.T(), "example.org")
	m.catalog.SetUpstreamCAs(upstreamCA)
	upstreamCert := upstreamCA.Cert()

	// generate a keypair make sure it was signed up upstream and that
	// the upstream cert is in the bundle
	m.Require().NoError(m.m.Initialize(ctx))
	a := m.m.getCurrentKeypairSet()
	m.Require().Equal(upstreamCert.Subject, a.x509CA.Issuer)
	m.Require().Equal(a.x509CA.Subject, a.jwtSigner.Issuer)
	m.requireBundle(upstreamCert, a.x509CA, a.jwtSigner)
}

func (m *ManagerTestSuite) TestRotation() {
	// initialize the current keypair set
	m.Require().NoError(m.m.Initialize(ctx))

	// assert that A has been created, is in use, and is stored in the bundle
	// and that B has not been created.
	a1, b1 := m.loadKeypairSets()
	m.Require().NotNil(a1)
	m.Require().Nil(b1)
	m.requireKeypairSet("A", a1)
	m.requireBundle(a1.x509CA, a1.jwtSigner)

	// advance up to the preparation threshold and assert nothing changes
	m.setTime(preparationThreshold(a1.x509CA))
	m.Require().NoError(m.m.rotateCAs(ctx))
	m.requireKeypairSet("A", a1)
	m.requireBundle(a1.x509CA, a1.jwtSigner)

	// advance past the preparation threshold and assert that B has been created
	// but that A is unchanged and still active.
	m.advanceTime(time.Second)
	m.Require().NoError(m.m.rotateCAs(ctx))
	a2, b2 := m.loadKeypairSets()
	m.Require().NotNil(a2)
	m.Require().NotNil(b2)
	m.Require().Equal(a2, a1)
	m.requireKeypairSet("A", a1)
	m.requireBundle(a1.x509CA, a1.jwtSigner, b2.x509CA, b2.jwtSigner)

	// advance to the activation threshold and assert nothing changes
	m.setTime(activationThreshold(a1.x509CA))
	m.Require().NoError(m.m.rotateCAs(ctx))
	m.requireKeypairSet("A", a1)
	m.requireBundle(a1.x509CA, a1.jwtSigner, b2.x509CA, b2.jwtSigner)

	// advance past to the activation threshold and assert that B is active
	// and A is reset
	m.advanceTime(time.Second)
	m.Require().NoError(m.m.rotateCAs(ctx))
	a3, b3 := m.loadKeypairSets()
	m.Require().Nil(a3)
	m.Require().NotNil(b3)
	m.Require().Equal(b3, b2)
	m.requireKeypairSet("B", b2)
	m.requireBundle(a1.x509CA, a1.jwtSigner, b2.x509CA, b2.jwtSigner)

	// now advance past both the preparation and activation threshold to make
	// sure B is rotated out and A is active. This makes sure that however
	// unlikely, preparation and activation can happen in the same pass, if
	// necessary.
	m.setTime(activationThreshold(b2.x509CA).Add(time.Second))
	m.Require().NoError(m.m.rotateCAs(ctx))
	a4, b4 := m.loadKeypairSets()
	m.Require().NotNil(a4)
	m.Require().Nil(b4)
	m.requireKeypairSet("A", a4)
	m.requireBundle(a1.x509CA, a1.jwtSigner, b2.x509CA, b2.jwtSigner, a4.x509CA, a4.jwtSigner)
}

func (m *ManagerTestSuite) TestPrune() {
	// Initialize and prepare an extra keypair set
	m.Require().NoError(m.m.Initialize(ctx))
	a := m.m.getCurrentKeypairSet()
	m.setTime(preparationThreshold(a.x509CA).Add(time.Second))
	m.Require().NoError(m.m.rotateCAs(ctx))
	b := m.m.getNextKeypairSet()

	// assert both certificates are in the bundle
	m.requireBundle(a.x509CA, a.jwtSigner, b.x509CA, b.jwtSigner)

	// prune and assert that nothing changed
	m.Require().NoError(m.m.pruneBundle(ctx))
	m.requireBundle(a.x509CA, a.jwtSigner, b.x509CA, b.jwtSigner)

	// advance after the expiration of the A, prune, and assert that nothing
	// changed (since we don't prune until the certificate has been expired
	// longer than the safety threshold)
	m.setTime(a.x509CA.NotAfter.Add(time.Second))
	m.Require().NoError(m.m.pruneBundle(ctx))
	m.requireBundle(a.x509CA, a.jwtSigner, b.x509CA, b.jwtSigner)

	// advance beyond the safety threshold, prune, and assert that A has been
	// pruned
	m.setTime(a.x509CA.NotAfter.Add(safetyThreshold))
	m.Require().NoError(m.m.pruneBundle(ctx))
	m.requireBundle(b.x509CA, b.jwtSigner)

	// advance beyond the B's safety threshold and assert that prune fails
	// because all certificates would be pruned and that B remains present
	// in the bundle
	m.setTime(b.x509CA.NotAfter.Add(safetyThreshold))
	m.Require().EqualError(m.m.pruneBundle(ctx), "would prune all certificates")
	m.requireBundle(b.x509CA, b.jwtSigner)
}

func (m *ManagerTestSuite) requireBundle(expectedCerts ...*x509.Certificate) {
	resp, err := m.datastore.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomain: m.m.c.TrustDomain.String(),
	})
	m.Require().NoError(err)
	m.Require().NotNil(resp.Bundle)
	actualCerts, err := x509.ParseCertificates(resp.Bundle.CaCerts)
	m.Require().NoError(err)
	m.Require().Equal(len(expectedCerts), len(actualCerts))
	for i := range actualCerts {
		m.Require().Equal(expectedCerts[i].Raw, actualCerts[i].Raw)
	}
}

func (m *ManagerTestSuite) requireKeypairSet(slot string, expected *keypairSet) {
	m.Require().Equal(expected, m.m.ca.getKeypairSet())
}
