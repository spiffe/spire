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

func (m *ManagerTestSuite) loadCertificates() (a, b *x509.Certificate) {
	certs, err := loadCertificates(m.certsPath())
	m.Require().NoError(err)
	a = certs["x509-CA-A"]
	m.Require().NotNil(a)
	b = certs["x509-CA-B"]
	m.Require().NotNil(b)
	return a, b
}

func (m *ManagerTestSuite) TestPersistence() {
	// initialize a new keypair set
	m.Require().NoError(m.m.Initialize(ctx))
	current1 := m.m.getCurrentKeypairSet()
	next1 := m.m.getNextKeypairSet()

	// "reload" the manager and assert the keypairs are the same
	m.m = NewManager(m.m.c)
	m.Require().NoError(m.m.Initialize(ctx))
	current2 := m.m.getCurrentKeypairSet()
	next2 := m.m.getNextKeypairSet()
	m.Require().Equal(current1, current2)
	m.Require().Equal(next1, next2)

	// drop the keys, "reload" the manager, and assert the keypairs are new
	m.catalog.SetKeyManagers(memory.New())
	m.m = NewManager(m.m.c)
	m.Require().NoError(m.m.Initialize(ctx))
	current3 := m.m.getCurrentKeypairSet()
	next3 := m.m.getNextKeypairSet()
	m.Require().NotEqual(current2, current3)
	m.Require().NotEqual(next2, next3)

	// load the old keys, "reload" the manager, and assert the keypairs are new
	m.catalog.SetKeyManagers(m.keymanager)
	m.m = NewManager(m.m.c)
	m.Require().NoError(m.m.Initialize(ctx))
	current4 := m.m.getCurrentKeypairSet()
	next4 := m.m.getNextKeypairSet()
	m.Require().NotEqual(current3, current4)
	m.Require().NotEqual(next3, next4)
}

func (m *ManagerTestSuite) TestUpstreamSigning() {
	upstreamCA := fakeupstreamca.New(m.T(), "example.org")
	m.catalog.SetUpstreamCAs(upstreamCA)

	m.Require().NoError(m.m.Initialize(ctx))
	a1, b1 := m.loadCertificates()
	m.requireBundle(upstreamCA.Cert(), a1, b1)
}

func (m *ManagerTestSuite) TestRotation() {
	// cause the initial rotation through initialization
	m.Require().NoError(m.m.Initialize(ctx))

	// assert that both the A and B keypairs are created, that A is in use,
	// and that both A and B certs have been added to the bundle
	a1, b1 := m.loadCertificates()
	m.requireKeypairSet("A", a1)
	m.requireBundle(a1, b1)

	// assert that B comes after A and that is active at the rotation
	// threshold minus the backdate
	m.Require().Equal(a1.NotAfter, m.nowHook().Add(DefaultCATTL))
	m.Require().WithinDuration(b1.NotBefore, rotationThreshold(a1).Add(-DefaultBackdate), time.Second)
	m.Require().WithinDuration(b1.NotAfter, rotationThreshold(a1).Add(DefaultCATTL), time.Second)

	// advance up to the rotation threshold and make sure nothing changes
	m.setTime(rotationThreshold(a1))
	m.Require().NoError(m.m.rotateCAs(ctx))
	m.requireKeypairSet("A", a1)
	m.requireBundle(a1, b1)

	// cross the threshold and assert that B is now in use and that A was
	// rotated and proceeds B
	m.advanceTime(time.Second)
	m.Require().NoError(m.m.rotateCAs(ctx))

	a2, b2 := m.loadCertificates()
	m.Require().Equal(b2, b1)
	m.requireKeypairSet("B", b2)
	m.requireBundle(a1, b1, a2)

	m.Require().WithinDuration(a2.NotBefore, rotationThreshold(b1).Add(-DefaultBackdate), time.Second)
	m.Require().WithinDuration(a2.NotAfter, rotationThreshold(b1).Add(DefaultCATTL), time.Second)

	// rotate once more for good measure
	m.setTime(rotationThreshold(b1).Add(time.Second))
	m.Require().NoError(m.m.rotateCAs(ctx))

	a3, b3 := m.loadCertificates()
	m.Require().Equal(a3, a2)
	m.requireKeypairSet("A", a3)
	m.requireBundle(a1, b1, a2, b3)
	m.Require().WithinDuration(b3.NotBefore, rotationThreshold(a2).Add(-DefaultBackdate), time.Second)
	m.Require().WithinDuration(b3.NotAfter, rotationThreshold(a2).Add(DefaultCATTL), time.Second)
}

func (m *ManagerTestSuite) TestPrune() {
	m.Require().NoError(m.m.Initialize(ctx))
	a1, b1 := m.loadCertificates()
	m.requireBundle(a1, b1)

	// prune and assert that nothing changed
	m.Require().NoError(m.m.pruneBundle(ctx))
	m.requireBundle(a1, b1)

	// advance after the expiration of the a1, prune, and assert that nothing
	// changed (since we don't prune until the certificate has been expired
	// longer than the safety threshold)
	m.setTime(a1.NotAfter.Add(time.Second))
	m.Require().NoError(m.m.pruneBundle(ctx))
	m.requireBundle(a1, b1)

	// advance beyond the safety threshold, prune, and assert that a1 has been
	// pruned
	m.setTime(a1.NotAfter.Add(safetyThreshold))
	m.Require().NoError(m.m.pruneBundle(ctx))
	m.requireBundle(b1)

	// advance beyond the b1's safety threshold and assert that prune fails
	// because all certificates would be pruned and that b1 remains present
	// in the bundle
	m.setTime(b1.NotAfter.Add(safetyThreshold))
	m.Require().EqualError(m.m.pruneBundle(ctx), "would prune all certificates")
	m.requireBundle(b1)
}

func (m *ManagerTestSuite) requireBundle(expectedCerts ...*x509.Certificate) {
	bundle, err := m.datastore.FetchBundle(ctx, &datastore.Bundle{
		TrustDomain: m.m.c.TrustDomain.String(),
	})
	m.Require().NoError(err)
	actualCerts, err := x509.ParseCertificates(bundle.CaCerts)
	m.Require().NoError(err)
	m.Require().Equal(len(expectedCerts), len(actualCerts))
	for i := range actualCerts {
		m.Require().Equal(expectedCerts[i].Raw, actualCerts[i].Raw)
	}
}

func (m *ManagerTestSuite) requireKeypairSet(slot string, x509CA *x509.Certificate) {
	kp := m.m.ca.getKeypairSet()
	m.Require().Equal(slot, kp.slot)
	m.Require().Equal(x509CA, kp.x509CA)
}
