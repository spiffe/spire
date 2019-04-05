package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/memory"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/server/datastore"
	"github.com/spiffe/spire/proto/spire/server/upstreamca"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeupstreamca"
	"github.com/spiffe/spire/test/spiretest"
)

const (
	testTrustDomain = "domain.test"
	testCATTL       = time.Hour
	activateAfter   = testCATTL - (testCATTL / 6)
	prepareAfter    = testCATTL - (testCATTL / 2)
)

var (
	testTrustDomainURL = url.URL{Scheme: "spiffe", Host: testTrustDomain}
)

func TestManager(t *testing.T) {
	spiretest.Run(t, new(ManagerSuite))
}

type ManagerSuite struct {
	spiretest.Suite

	clock   *clock.Mock
	ca      *fakeCA
	log     logrus.FieldLogger
	logHook *test.Hook
	dir     string
	km      *memory.KeyManager
	ds      *fakedatastore.DataStore
	cat     *fakeservercatalog.Catalog

	m *Manager
}

func (s *ManagerSuite) SetupTest() {
	s.clock = clock.NewMock(s.T())
	s.ca = new(fakeCA)
	s.log, s.logHook = test.NewNullLogger()
	s.km = memory.New()
	s.ds = fakedatastore.New()

	s.cat = fakeservercatalog.New()
	s.cat.SetKeyManager(s.km)
	s.cat.SetDataStore(s.ds)
	s.dir = s.TempDir()
}

func (s *ManagerSuite) TestPersistence() {
	s.initSelfSignedManager()
	firstX509CA, firstJWTKey := s.currentX509CA(), s.currentJWTKey()

	// reinitialize against the same storage
	s.initSelfSignedManager()
	s.requireX509CAEqual(firstX509CA, s.currentX509CA())
	s.requireJWTKeyEqual(firstJWTKey, s.currentJWTKey())
	s.Require().Nil(s.nextX509CA())
	s.Require().Nil(s.nextJWTKey())

	// prepare the next and reinitialize
	s.addTimeAndRotate(prepareAfter + time.Minute)
	secondX509CA, secondJWTKey := s.nextX509CA(), s.nextJWTKey()
	s.initSelfSignedManager()
	s.requireX509CAEqual(firstX509CA, s.currentX509CA())
	s.requireJWTKeyEqual(firstJWTKey, s.currentJWTKey())
	s.requireX509CAEqual(secondX509CA, s.nextX509CA())
	s.requireJWTKeyEqual(secondJWTKey, s.nextJWTKey())

	// activate the next and reinitialize
	s.addTimeAndRotate(activateAfter - prepareAfter)
	s.initSelfSignedManager()
	s.requireX509CAEqual(secondX509CA, s.currentX509CA())
	s.requireJWTKeyEqual(secondJWTKey, s.currentJWTKey())
	s.Require().Nil(s.nextX509CA())
	s.Require().Nil(s.nextJWTKey())
}

func (s *ManagerSuite) TestPersistenceFailsIfKeyManagerLosesKeys() {
	s.initSelfSignedManager()
	x509CA, jwtKey := s.currentX509CA(), s.currentJWTKey()

	// reset the key manager, reinitialize, and make sure the keys differ. this
	// simulates the key manager not having keys for the persisted pairs.
	s.cat.SetKeyManager(memory.New())
	s.initSelfSignedManager()
	s.requireX509CANotEqual(x509CA, s.currentX509CA())
	s.requireJWTKeyNotEqual(jwtKey, s.currentJWTKey())
}

func (s *ManagerSuite) TestPersistenceFailsIfJournalLost() {
	s.initSelfSignedManager()
	x509CA, jwtKey := s.currentX509CA(), s.currentJWTKey()

	// wipe the journal, reinitialize, and make sure the keys differ. this
	// simulates the the key manager having dangling keys.
	s.wipeJournal()
	s.initSelfSignedManager()
	s.requireX509CANotEqual(x509CA, s.currentX509CA())
	s.requireJWTKeyNotEqual(jwtKey, s.currentJWTKey())
}

func (s *ManagerSuite) TestSelfSigning() {
	s.initSelfSignedManager()

	x509CA := s.currentX509CA()
	s.NotNil(x509CA.Signer)
	s.False(x509CA.IsIntermediate)
	s.Len(x509CA.Chain, 1)
	s.Equal(x509CA.Chain[0].Subject, x509CA.Chain[0].Issuer)
}

func (s *ManagerSuite) TestUpstreamSignedWithoutUpstreamBundle() {
	s.testUpstreamSignedWithoutUpstreamBundle(false)
}

func (s *ManagerSuite) TestUpstreamSignedWithoutUpstreamBundleDeprecated() {
	s.testUpstreamSignedWithoutUpstreamBundle(true)
}

func (s *ManagerSuite) testUpstreamSignedWithoutUpstreamBundle(useDeprecatedFields bool) {
	upstreamCA := fakeupstreamca.New(s.T(), fakeupstreamca.Config{
		TrustDomain:         testTrustDomain,
		UseDeprecatedFields: useDeprecatedFields,
	})
	s.initUpstreamSignedManager(upstreamCA, false)

	// The X509CA should not be an intermediate and the chain should only
	// contain itself.
	x509CA := s.currentX509CA()
	s.NotNil(x509CA.Signer)
	s.False(x509CA.IsIntermediate)
	s.Len(x509CA.Chain, 1)
	s.NotEqual(x509CA.Chain[0].Subject, x509CA.Chain[0].Issuer)

	// The trust bundle should contain the CA cert itself
	s.requireBundleRootCAs(x509CA.Chain[0])
}

func (s *ManagerSuite) TestUpstreamSignedWithUpstreamBundle() {
	s.testUpstreamSignedWithUpstreamBundle(false)
}

func (s *ManagerSuite) TestUpstreamSignedWithUpstreamBundleDeprecated() {
	s.testUpstreamSignedWithUpstreamBundle(true)
}

func (s *ManagerSuite) testUpstreamSignedWithUpstreamBundle(useDeprecatedFields bool) {
	upstreamCA := fakeupstreamca.New(s.T(), fakeupstreamca.Config{
		TrustDomain:         testTrustDomain,
		UseDeprecatedFields: useDeprecatedFields,
	})
	s.initUpstreamSignedManager(upstreamCA, true)

	// X509 CA should be set up to be an intermediate but only have itself
	// in the chain since it was signed directly by the upstream root.
	x509CA := s.currentX509CA()
	s.NotNil(x509CA.Signer)
	s.True(x509CA.IsIntermediate)
	s.Len(x509CA.Chain, 1)
	s.Equal(upstreamCA.Root().Subject, x509CA.Chain[0].Issuer)

	// The trust bundle should contain the upstream root
	s.requireBundleRootCAs(upstreamCA.Root())
}

func (s *ManagerSuite) TestUpstreamIntermediateSignedWithUpstreamBundle() {
	s.testUpstreamIntermediateSignedWithUpstreamBundle(false)
}

func (s *ManagerSuite) TestUpstreamIntermediateSignedWithUpstreamBundleDeprecated() {
	s.testUpstreamIntermediateSignedWithUpstreamBundle(true)
}

func (s *ManagerSuite) testUpstreamIntermediateSignedWithUpstreamBundle(useDeprecatedFields bool) {
	upstreamCA := fakeupstreamca.New(s.T(), fakeupstreamca.Config{
		TrustDomain:         testTrustDomain,
		UseIntermediate:     true,
		UseDeprecatedFields: useDeprecatedFields,
	})
	s.initUpstreamSignedManager(upstreamCA, true)

	// X509 CA should be set up to be an intermediate and have two certs in
	// its chain: itself and the upstream intermediate that signed it.
	x509CA := s.currentX509CA()
	s.NotNil(x509CA.Signer)
	s.True(x509CA.IsIntermediate)
	s.Len(x509CA.Chain, 2)
	s.Equal(upstreamCA.Intermediate().Subject, x509CA.Chain[0].Issuer)
	s.Equal(upstreamCA.Intermediate().Subject, x509CA.Chain[1].Subject)

	// The trust bundle should contain the upstream root
	s.requireBundleRootCAs(upstreamCA.Root())
}

func (s *ManagerSuite) TestX509CARotation() {
	s.initSelfSignedManager()

	// CA TTL is an hour so we should be preparing after thirty minutes and
	// activating after 50 minutes.
	initTime := s.clock.Now()
	preparationTime1 := initTime.Add(prepareAfter)
	activationTime1 := initTime.Add(activateAfter)
	preparationTime2 := activationTime1.Add(prepareAfter)
	activationTime2 := activationTime1.Add(activateAfter)

	// after initialization, we should have a current X509CA but no next.
	first := s.currentX509CA()
	s.Nil(s.nextX509CA(), "second X509CA should not be prepared yet")
	s.requireBundleRootCAs(first.Chain[0])

	// move up to the preparation mark. nothing should change
	s.setTimeAndRotate(preparationTime1)
	s.requireX509CAEqual(first, s.currentX509CA())
	s.Nil(s.nextX509CA(), "second X509CA should not be prepared yet")
	s.requireBundleRootCAs(first.Chain[0])

	// move just past the preparation mark. the current X509CA should stay
	// the same but the next X509CA should have been prepared and added to
	// the trust bundle.
	s.addTimeAndRotate(time.Minute)
	s.requireX509CAEqual(first, s.currentX509CA())
	second := s.nextX509CA()
	s.NotNil(second, "second X509CA should have been prepared")
	s.requireBundleRootCAs(first.Chain[0], second.Chain[0])

	// move up to the activation mark. nothing should change.
	s.setTimeAndRotate(activationTime1)
	s.requireX509CAEqual(first, s.currentX509CA())
	s.requireX509CAEqual(second, s.nextX509CA())

	// move up to the activation mark. "next" should become "current" and
	// "next" should be reset.
	s.addTimeAndRotate(time.Minute)
	s.requireX509CAEqual(second, s.currentX509CA())
	s.Nil(s.nextX509CA())

	// move past the 2nd preparation mark. the current X509CA should stay
	// the same but the next X509CA should have been prepared and added to
	// the trust bundle.
	s.setTimeAndRotate(preparationTime2.Add(time.Minute))
	s.requireX509CAEqual(second, s.currentX509CA())
	third := s.nextX509CA()
	s.NotNil(second, "third X509CA should have been prepared")
	s.requireBundleRootCAs(first.Chain[0], second.Chain[0], third.Chain[0])

	// move past to 2nd activation mark. "next" should become "current" and
	// "next" should be reset.
	s.setTimeAndRotate(activationTime2.Add(time.Minute))
	s.requireX509CAEqual(third, s.currentX509CA())
	s.Nil(s.nextX509CA())
}

func (s *ManagerSuite) TestJWTKeyRotation() {
	s.initSelfSignedManager()

	// CA TTL is an hour so we should be preparing after thirty minutes and
	// activating after 50 minutes.
	initTime := s.clock.Now()
	preparationTime1 := initTime.Add(prepareAfter)
	activationTime1 := initTime.Add(activateAfter)
	preparationTime2 := activationTime1.Add(prepareAfter)
	activationTime2 := activationTime1.Add(activateAfter)

	// after initialization, we should have a current JWTKey but no next.
	first := s.currentJWTKey()
	s.Nil(s.nextJWTKey(), "second JWTKey should not be prepared yet")
	s.requireBundleJWTKeys(first)

	// move up to the preparation mark. nothing should change
	s.setTimeAndRotate(preparationTime1)
	s.requireJWTKeyEqual(first, s.currentJWTKey())
	s.Nil(s.nextJWTKey(), "second JWTKey should not be prepared yet")
	s.requireBundleJWTKeys(first)

	// move just past the preparation mark. the current JWTKey should stay
	// the same but the next JWTKey should have been prepared and added to
	// the trust bundle.
	s.addTimeAndRotate(time.Minute)
	s.requireJWTKeyEqual(first, s.currentJWTKey())
	second := s.nextJWTKey()
	s.NotNil(second, "second JWTKey should have been prepared")
	s.requireBundleJWTKeys(first, second)

	// move up to the activation mark. nothing should change.
	s.setTimeAndRotate(activationTime1)
	s.requireJWTKeyEqual(first, s.currentJWTKey())
	s.requireJWTKeyEqual(second, s.nextJWTKey())

	// move up to the activation mark. "next" should become "current" and
	// "next" should be reset.
	s.addTimeAndRotate(time.Minute)
	s.requireJWTKeyEqual(second, s.currentJWTKey())
	s.Nil(s.nextJWTKey())

	// move past the 2nd preparation mark. the current JWTKey should stay
	// the same but the next JWTKey should have been prepared and added to
	// the trust bundle.
	s.setTimeAndRotate(preparationTime2.Add(time.Minute))
	s.requireJWTKeyEqual(second, s.currentJWTKey())
	third := s.nextJWTKey()
	s.NotNil(second, "third JWTKey should have been prepared")
	s.requireBundleJWTKeys(first, second, third)

	// move past to 2nd activation mark. "next" should become "current" and
	// "next" should be reset.
	s.setTimeAndRotate(activationTime2.Add(time.Minute))
	s.requireJWTKeyEqual(third, s.currentJWTKey())
	s.Nil(s.nextJWTKey())
}

func (s *ManagerSuite) TestPrune() {
	s.initSelfSignedManager()

	initTime := s.clock.Now()
	prepareSecondTime := initTime.Add(prepareAfter)
	firstExpiresTime := initTime.Add(testCATTL)
	secondExpiresTime := prepareSecondTime.Add(testCATTL)

	// rotate so that we have two in the bundle
	s.setTimeAndRotate(prepareSecondTime.Add(time.Minute))
	firstX509CA := s.currentX509CA()
	firstJWTKey := s.currentJWTKey()
	secondX509CA := s.nextX509CA()
	secondJWTKey := s.nextJWTKey()
	s.requireBundleRootCAs(firstX509CA.Chain[0], secondX509CA.Chain[0])
	s.requireBundleJWTKeys(firstJWTKey, secondJWTKey)

	// advance just past the expiration time of the first and prune. nothing
	// should change.
	s.setTimeAndPrune(firstExpiresTime.Add(time.Minute))
	s.requireBundleRootCAs(firstX509CA.Chain[0], secondX509CA.Chain[0])
	s.requireBundleJWTKeys(firstJWTKey, secondJWTKey)

	// advance beyond the safety threshold of the first, prune, and assert that
	// the first has been pruned
	s.addTimeAndPrune(safetyThreshold)
	s.requireBundleRootCAs(secondX509CA.Chain[0])
	s.requireBundleJWTKeys(secondJWTKey)

	// advance beyond the second expiration time, prune, and assert nothing
	// changes because we can't prune out the whole bundle.
	s.clock.Set(secondExpiresTime.Add(time.Minute + safetyThreshold))
	s.Require().EqualError(s.m.pruneBundle(context.Background()), "would prune all certificates")
	s.requireBundleRootCAs(secondX509CA.Chain[0])
	s.requireBundleJWTKeys(secondJWTKey)
}

func (s *ManagerSuite) TestMigration() {
	// assert that we migrate on load by writing junk data to the old JSON file
	// and making sure initialization fails. The journal tests exercise this
	// code more carefully.
	s.Require().NoError(ioutil.WriteFile(filepath.Join(s.dir, "certs.json"), []byte("NOTJSON"), 0644))
	s.m = NewManager(s.selfSignedConfig())
	err := s.m.Initialize(context.Background())
	s.RequireErrorContains(err, "failed to migrate old JSON data: unable to decode JSON")
}

func (s *ManagerSuite) initSelfSignedManager() {
	s.cat.SetUpstreamCA(nil)
	s.m = NewManager(s.selfSignedConfig())
	s.NoError(s.m.Initialize(context.Background()))
}

func (s *ManagerSuite) initUpstreamSignedManager(upstreamCA upstreamca.UpstreamCA, upstreamBundle bool) {
	s.cat.SetUpstreamCA(upstreamCA)

	c := s.selfSignedConfig()
	c.UpstreamBundle = upstreamBundle
	s.m = NewManager(c)
	s.NoError(s.m.Initialize(context.Background()))
}

func (s *ManagerSuite) selfSignedConfig() ManagerConfig {
	return ManagerConfig{
		CA:          s.ca,
		Catalog:     s.cat,
		TrustDomain: testTrustDomainURL,
		CASubject: pkix.Name{
			CommonName: "SPIRE",
		},
		CATTL:   testCATTL,
		Dir:     s.dir,
		Metrics: telemetry.Blackhole{},
		Log:     s.log,
		Clock:   s.clock,
	}
}

func (s *ManagerSuite) requireX509CAEqual(expected, actual *X509CA, msgAndArgs ...interface{}) {
	s.Require().Equal(s.getX509CAInfo(expected), s.getX509CAInfo(actual), msgAndArgs...)
}

func (s *ManagerSuite) requireX509CANotEqual(expected, actual *X509CA, msgAndArgs ...interface{}) {
	s.Require().NotEqual(s.getX509CAInfo(expected), s.getX509CAInfo(actual), msgAndArgs...)
}

func (s *ManagerSuite) requireJWTKeyEqual(expected, actual *JWTKey, msgAndArgs ...interface{}) {
	s.Require().Equal(s.getJWTKeyInfo(expected), s.getJWTKeyInfo(actual), msgAndArgs...)
}

func (s *ManagerSuite) requireJWTKeyNotEqual(expected, actual *JWTKey, msgAndArgs ...interface{}) {
	s.Require().NotEqual(s.getJWTKeyInfo(expected), s.getJWTKeyInfo(actual), msgAndArgs...)
}

type x509CAInfo struct {
	Signer         signerInfo
	Chain          []*x509.Certificate
	IsIntermediate bool
}

type jwtKeyInfo struct {
	Signer   signerInfo
	Kid      string
	NotAfter time.Time
}

type signerInfo struct {
	KeyID     string
	PublicKey []byte
}

func (s *ManagerSuite) getX509CAInfo(x509CA *X509CA) x509CAInfo {
	return x509CAInfo{
		Signer:         s.getSignerInfo(x509CA.Signer),
		Chain:          x509CA.Chain,
		IsIntermediate: x509CA.IsIntermediate,
	}
}

func (s *ManagerSuite) getJWTKeyInfo(jwtKey *JWTKey) jwtKeyInfo {
	return jwtKeyInfo{
		Signer:   s.getSignerInfo(jwtKey.Signer),
		Kid:      jwtKey.Kid,
		NotAfter: jwtKey.NotAfter,
	}
}

func (s *ManagerSuite) getSignerInfo(signer crypto.Signer) signerInfo {
	ks, ok := signer.(interface{ KeyID() string })
	s.Require().True(ok, "signer is not a Key Manager")

	publicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	s.Require().NoError(err)
	return signerInfo{
		KeyID:     ks.KeyID(),
		PublicKey: publicKey,
	}
}

func (s *ManagerSuite) requireBundleRootCAs(rootCAs ...*x509.Certificate) {
	expected := &common.Bundle{}
	for _, rootCA := range rootCAs {
		expected.RootCas = append(expected.RootCas, &common.Certificate{
			DerBytes: rootCA.Raw,
		})
	}

	bundle := s.fetchBundle()
	s.RequireProtoEqual(expected, &common.Bundle{
		RootCas: bundle.RootCas,
	})
}

func (s *ManagerSuite) requireBundleJWTKeys(jwtKeys ...*JWTKey) {
	expected := &common.Bundle{}
	for _, jwtKey := range jwtKeys {
		publicKey, err := publicKeyFromJWTKey(jwtKey)
		s.Require().NoError(err)
		expected.JwtSigningKeys = append(expected.JwtSigningKeys, publicKey)
	}

	bundle := s.fetchBundle()
	s.RequireProtoEqual(expected, &common.Bundle{
		JwtSigningKeys: bundle.JwtSigningKeys,
	})
}

func (s *ManagerSuite) fetchBundle() *common.Bundle {
	resp, err := s.ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: testTrustDomainURL.String(),
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp.Bundle, "missing bundle for domain %q", testTrustDomainURL)
	return resp.Bundle
}

func (s *ManagerSuite) currentX509CA() *X509CA {
	// ensure that the "active" one matches the current before returning
	s.requireX509CAEqual(s.m.currentX509CA.x509CA, s.ca.X509CA(), "current X509CA is not active")
	return s.m.currentX509CA.x509CA
}

func (s *ManagerSuite) currentJWTKey() *JWTKey {
	s.requireJWTKeyEqual(s.m.currentJWTKey.jwtKey, s.ca.JWTKey(), "current JWTKey is not active")
	return s.m.currentJWTKey.jwtKey
}

func (s *ManagerSuite) nextX509CA() *X509CA {
	return s.m.nextX509CA.x509CA
}

func (s *ManagerSuite) nextJWTKey() *JWTKey {
	return s.m.nextJWTKey.jwtKey
}

func (s *ManagerSuite) setTimeAndRotate(t time.Time) {
	s.clock.Set(t)
	s.Require().NoError(s.m.rotate(context.Background()))
}

func (s *ManagerSuite) addTimeAndRotate(d time.Duration) {
	s.clock.Add(d)
	s.Require().NoError(s.m.rotate(context.Background()))
}

func (s *ManagerSuite) setTimeAndPrune(t time.Time) {
	s.clock.Set(t)
	s.Require().NoError(s.m.pruneBundle(context.Background()))
}

func (s *ManagerSuite) addTimeAndPrune(d time.Duration) {
	s.clock.Add(d)
	s.Require().NoError(s.m.pruneBundle(context.Background()))
}

func (s *ManagerSuite) wipeJournal() {
	s.Require().NoError(os.Remove(s.m.journalPath()))
}

type fakeCA struct {
	mu     sync.Mutex
	x509CA *X509CA
	jwtKey *JWTKey
}

func (s *fakeCA) X509CA() *X509CA {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.x509CA
}

func (s *fakeCA) SetX509CA(x509CA *X509CA) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.x509CA = x509CA
}

func (s *fakeCA) JWTKey() *JWTKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jwtKey
}

func (s *fakeCA) SetJWTKey(jwtKey *JWTKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwtKey = jwtKey
}
