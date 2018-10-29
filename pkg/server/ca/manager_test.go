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

	"github.com/golang/protobuf/proto"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/memory"
	"github.com/spiffe/spire/proto/common"
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

	m.newManager()
	m.m.hooks.now = m.nowHook
	m.now = time.Now().Truncate(time.Second).UTC()
}

func (m *ManagerTestSuite) TearDownTest() {
	os.RemoveAll(m.tmpDir)
}

func (m *ManagerTestSuite) newManager() {
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
	certs, publicKeys, err := m.m.loadKeypairData(m.certsPath(), nil)
	m.Require().NoError(err)
	xa := certs["x509-CA-A"]
	ja := publicKeys["JWT-Signer-A"]
	xb := certs["x509-CA-B"]
	jb := publicKeys["JWT-Signer-B"]
	m.Require().True((xa != nil) == (ja != nil))
	m.Require().True((xb != nil) == (jb != nil))

	if xa != nil {
		a = &keypairSet{
			slot:          "A",
			x509CA:        xa,
			jwtSigningKey: ja,
		}
	}
	if xb != nil {
		b = &keypairSet{
			slot:          "B",
			x509CA:        xb,
			jwtSigningKey: jb,
		}
	}
	return a, b
}

func (m *ManagerTestSuite) TestPersistence() {
	// initialize a new keypair set
	m.Require().NoError(m.m.Initialize(ctx))
	current1 := m.m.getCurrentKeypairSet()
	m.requireValidKeypairSet(current1)
	next1 := m.m.getNextKeypairSet()
	m.requireEmptyKeypairSet(next1)

	// "reload" the manager and assert the keypairs are the same
	m.newManager()
	m.Require().NoError(m.m.Initialize(ctx))
	current2 := m.m.getCurrentKeypairSet()
	next2 := m.m.getNextKeypairSet()
	m.requireKeypairSetKeysEqual(current1, current2)
	m.requireEmptyKeypairSet(next2)

	// drop the keys, "reload" the manager, and assert the keypairs are new
	m.catalog.SetKeyManagers(memory.New())
	m.newManager()
	m.Require().NoError(m.m.Initialize(ctx))
	current3 := m.m.getCurrentKeypairSet()
	next3 := m.m.getNextKeypairSet()
	m.requireKeypairSetKeysNotEqual(current2, current3)
	m.requireEmptyKeypairSet(next3)

	// load the old keys, "reload" the manager, and assert the keypairs are new
	m.catalog.SetKeyManagers(m.keymanager)
	m.newManager()
	m.Require().NoError(m.m.Initialize(ctx))
	current4 := m.m.getCurrentKeypairSet()
	next4 := m.m.getNextKeypairSet()
	m.requireKeypairSetKeysNotEqual(current3, current4)
	m.requireEmptyKeypairSet(next4)

	// prepare the next keypair, "reload" the manager, and assert "current"
	// and "next" are maintained.
	m.setTime(preparationThreshold(current4.x509CA.cert).Add(time.Second))
	m.Require().NoError(m.m.rotateCAs(ctx))
	current5 := m.m.getCurrentKeypairSet()
	next5 := m.m.getNextKeypairSet()
	m.requireKeypairSetKeysEqual(current4, current5)
	m.requireValidKeypairSet(next5)
	m.newManager()
	m.Require().NoError(m.m.Initialize(ctx))
	current6 := m.m.getCurrentKeypairSet()
	next6 := m.m.getNextKeypairSet()
	m.requireKeypairSetKeysEqual(current5, current6)
	m.requireKeypairSetKeysEqual(next5, next6)

	// activate the next keypair, "reload" the manager, and assert the new "current"
	// is maintained and "next" is empty (since it hasn't been prepared yet)
	m.setTime(activationThreshold(current6.x509CA.cert).Add(time.Second))
	m.Require().NoError(m.m.rotateCAs(ctx))
	current7 := m.m.getCurrentKeypairSet()
	next7 := m.m.getNextKeypairSet()
	m.requireKeypairSetKeysNotEqual(current6, current7)
	m.requireEmptyKeypairSet(next7)
	m.newManager()
	m.Require().NoError(m.m.Initialize(ctx))
	current8 := m.m.getCurrentKeypairSet()
	next8 := m.m.getNextKeypairSet()
	m.requireKeypairSetKeysEqual(current7, current8)
	m.requireEmptyKeypairSet(next8)
}

func (m *ManagerTestSuite) TestSelfSigning() {
	// generate a keypair make sure it was signed up upstream and that
	// the upstream cert is in the bundle
	m.Require().NoError(m.m.Initialize(ctx))
	a := m.m.getCurrentKeypairSet()
	m.Require().Equal(a.x509CA.cert.Subject, a.x509CA.cert.Issuer)
	m.requireBundleRootCAs(a.x509CA.cert)
	m.requireBundleJWTSigningKeys(a.jwtSigningKey)
}

func (m *ManagerTestSuite) TestUpstreamSigning() {
	upstreamCA := fakeupstreamca.New(m.T(), "example.org")
	m.catalog.SetUpstreamCAs(upstreamCA)
	upstreamCert := upstreamCA.Cert()

	// generate a keypair make sure it was signed up upstream and that
	// the upstream cert is in the bundle
	m.Require().NoError(m.m.Initialize(ctx))
	a := m.m.getCurrentKeypairSet()
	m.Require().Equal(upstreamCert.Subject, a.x509CA.cert.Issuer)
	m.requireBundleRootCAs(upstreamCert)
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
	m.requireBundleRootCAs(a1.x509CA.cert)
	m.requireBundleJWTSigningKeys(a1.jwtSigningKey)

	// advance up to the preparation threshold and assert nothing changes
	m.setTime(preparationThreshold(a1.x509CA.cert))
	m.Require().NoError(m.m.rotateCAs(ctx))
	m.requireKeypairSet("A", a1)
	m.requireBundleRootCAs(a1.x509CA.cert)
	m.requireBundleJWTSigningKeys(a1.jwtSigningKey)

	// advance past the preparation threshold and assert that B has been created
	// but that A is unchanged and still active.
	m.advanceTime(time.Second)
	m.Require().NoError(m.m.rotateCAs(ctx))
	a2, b2 := m.loadKeypairSets()
	m.Require().NotNil(a2)
	m.Require().NotNil(b2)
	m.Require().Equal(a2, a1)
	m.requireKeypairSet("A", a1)
	m.requireBundleRootCAs(a1.x509CA.cert, b2.x509CA.cert)
	m.requireBundleJWTSigningKeys(a1.jwtSigningKey, b2.jwtSigningKey)

	// advance to the activation threshold and assert nothing changes
	m.setTime(activationThreshold(a1.x509CA.cert))
	m.Require().NoError(m.m.rotateCAs(ctx))
	m.requireKeypairSet("A", a1)
	m.requireBundleRootCAs(a1.x509CA.cert, b2.x509CA.cert)
	m.requireBundleJWTSigningKeys(a1.jwtSigningKey, b2.jwtSigningKey)

	// advance past to the activation threshold and assert that B is active
	// and A is reset
	m.advanceTime(time.Second)
	m.Require().NoError(m.m.rotateCAs(ctx))
	a3, b3 := m.loadKeypairSets()
	m.Require().Nil(a3)
	m.Require().NotNil(b3)
	m.Require().Equal(b3, b2)
	m.requireKeypairSet("B", b2)
	m.requireBundleRootCAs(a1.x509CA.cert, b2.x509CA.cert)
	m.requireBundleJWTSigningKeys(a1.jwtSigningKey, b2.jwtSigningKey)

	// now advance past both the preparation and activation threshold to make
	// sure B is rotated out and A is active. This makes sure that however
	// unlikely, preparation and activation can happen in the same pass, if
	// necessary.
	m.setTime(activationThreshold(b2.x509CA.cert).Add(time.Second))
	m.Require().NoError(m.m.rotateCAs(ctx))
	a4, b4 := m.loadKeypairSets()
	m.Require().NotNil(a4)
	m.Require().Nil(b4)
	m.requireKeypairSet("A", a4)
	m.requireBundleRootCAs(a1.x509CA.cert, b2.x509CA.cert, a4.x509CA.cert)
	m.requireBundleJWTSigningKeys(a1.jwtSigningKey, b2.jwtSigningKey, a4.jwtSigningKey)
}

func (m *ManagerTestSuite) TestPrune() {
	// Initialize and prepare an extra keypair set
	m.Require().NoError(m.m.Initialize(ctx))
	a := m.m.getCurrentKeypairSet()
	m.setTime(preparationThreshold(a.x509CA.cert).Add(time.Second))
	m.Require().NoError(m.m.rotateCAs(ctx))
	b := m.m.getNextKeypairSet()

	// assert both certificates are in the bundle
	m.requireBundleRootCAs(a.x509CA.cert, b.x509CA.cert)
	m.requireBundleJWTSigningKeys(a.jwtSigningKey, b.jwtSigningKey)

	// prune and assert that nothing changed
	m.Require().NoError(m.m.pruneBundle(ctx))
	m.requireBundleRootCAs(a.x509CA.cert, b.x509CA.cert)
	m.requireBundleJWTSigningKeys(a.jwtSigningKey, b.jwtSigningKey)

	// advance after the expiration of the A, prune, and assert that nothing
	// changed (since we don't prune until the certificate has been expired
	// longer than the safety threshold)
	m.setTime(a.x509CA.cert.NotAfter.Add(time.Second))
	m.Require().NoError(m.m.pruneBundle(ctx))
	m.requireBundleRootCAs(a.x509CA.cert, b.x509CA.cert)
	m.requireBundleJWTSigningKeys(a.jwtSigningKey, b.jwtSigningKey)

	// advance beyond the safety threshold, prune, and assert that A has been
	// pruned
	m.setTime(a.x509CA.cert.NotAfter.Add(safetyThreshold))
	m.Require().NoError(m.m.pruneBundle(ctx))
	m.requireBundleRootCAs(b.x509CA.cert)
	m.requireBundleJWTSigningKeys(b.jwtSigningKey)

	// advance beyond the B's safety threshold and assert that prune fails
	// because all certificates would be pruned and that B remains present
	// in the bundle
	m.setTime(b.x509CA.cert.NotAfter.Add(safetyThreshold))
	m.Require().EqualError(m.m.pruneBundle(ctx), "would prune all certificates")
	m.requireBundleRootCAs(b.x509CA.cert)
	m.requireBundleJWTSigningKeys(b.jwtSigningKey)
}

func (m *ManagerTestSuite) requireBundleRootCAs(expectedCerts ...*x509.Certificate) {
	var expected []*common.Certificate
	for _, expectedCert := range expectedCerts {
		expected = append(expected, &common.Certificate{
			DerBytes: expectedCert.Raw,
		})
	}

	resp, err := m.datastore.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: m.m.c.TrustDomain.String(),
	})
	m.Require().NoError(err)
	m.Require().NotNil(resp.Bundle, "missing bundle for domain %q", m.m.c.TrustDomain.String())
	m.Require().Equal(expected, resp.Bundle.RootCas)
}

func (m *ManagerTestSuite) requireBundleJWTSigningKeys(expectedKeys ...*caPublicKey) {
	var expected []*common.PublicKey
	for _, expectedKey := range expectedKeys {
		expected = append(expected, expectedKey.PublicKey)
	}

	resp, err := m.datastore.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: m.m.c.TrustDomain.String(),
	})
	m.Require().NoError(err)
	m.Require().NotNil(resp.Bundle)
	m.requirePublicKeysEqual(expected, resp.Bundle.JwtSigningKeys)
}

func (m *ManagerTestSuite) requirePublicKeysEqual(as, bs []*common.PublicKey) {
	m.Require().Equal(len(as), len(bs))
	for i := range as {
		m.Require().True(proto.Equal(as[i], bs[i]))
	}
}

func (m *ManagerTestSuite) requireKeypairSet(slot string, expected *keypairSet) {
	actual := m.m.ca.getKeypairSet()
	m.Require().Equal(slot, actual.slot)
	m.requireKeypairSetKeysEqual(expected, actual)
}

func (m *ManagerTestSuite) requireKeypairSetKeysEqual(set1, set2 *keypairSet) {
	m.Require().Equal(set1.x509CA.chain, set2.x509CA.chain)
	m.Require().Equal(set1.jwtSigningKey.PublicKey.String(), set2.jwtSigningKey.PublicKey.String())
}

func (m *ManagerTestSuite) requireKeypairSetKeysNotEqual(set1, set2 *keypairSet) {
	m.requireValidKeypairSet(set1)
	m.requireValidKeypairSet(set2)
	m.Require().NotEqual(set1.x509CA.chain, set2.x509CA.chain)
	m.Assert().NotEqual(set1.jwtSigningKey.PublicKey.String(), set2.jwtSigningKey.PublicKey.String())
}

func (m *ManagerTestSuite) requireValidKeypairSet(set *keypairSet) {
	m.Require().NotNil(set)
	m.Require().NotNil(set.x509CA)
	m.Require().NotNil(set.jwtSigningKey)
}

func (m *ManagerTestSuite) requireEmptyKeypairSet(set *keypairSet) {
	m.Require().NotNil(set)
	m.Require().Nil(set.x509CA)
	m.Require().Nil(set.jwtSigningKey)
}
