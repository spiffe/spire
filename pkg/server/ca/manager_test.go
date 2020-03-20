package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/memory"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/fakes/fakenotifier"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeupstreamauthority"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
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
	if s.NotNil(x509CA.Certificate) {
		s.Equal(x509CA.Certificate.Subject, x509CA.Certificate.Issuer)
	}
	s.Empty(x509CA.UpstreamChain)
}

func (s *ManagerSuite) TestUpstreamSignedWithoutUpstreamBundle() {
	upstreamAuthority, _ := fakeupstreamauthority.Load(s.T(), fakeupstreamauthority.Config{
		TrustDomain: testTrustDomain,
	})

	s.initUpstreamSignedManager(upstreamAuthority, false)

	// The X509CA should not be an intermediate and the chain should only
	// contain itself.
	x509CA := s.currentX509CA()
	s.NotNil(x509CA.Signer)
	if s.NotNil(x509CA.Certificate) {
		s.NotEqual(x509CA.Certificate.Subject, x509CA.Certificate.Issuer)
	}
	s.Empty(x509CA.UpstreamChain)

	// The trust bundle should contain the CA cert itself
	s.requireBundleRootCAs(x509CA.Certificate)

	// We expect this warning because the UpstreamAuthority doesn't implements PublishJWTKey
	s.Equal(
		1,
		s.countLogEntries(logrus.WarnLevel, "UpstreamAuthority plugin does not support JWT-SVIDs. Workloads managed "+
			"by this server may have trouble communicating with workloads outside "+
			"this cluster when using JWT-SVIDs."),
	)
}

func (s *ManagerSuite) TestUpstreamSignedWithUpstreamBundle() {
	upstreamAuthority, fakeUA := fakeupstreamauthority.Load(s.T(), fakeupstreamauthority.Config{
		TrustDomain: testTrustDomain,
	})

	s.initUpstreamSignedManager(upstreamAuthority, true)

	// X509 CA should be set up to be an intermediate but only have itself
	// in the chain since it was signed directly by the upstream root.
	x509CA := s.currentX509CA()
	s.NotNil(x509CA.Signer)
	if s.NotNil(x509CA.Certificate) {
		s.Equal(fakeUA.Root().Subject, x509CA.Certificate.Issuer)
	}
	if s.Len(x509CA.UpstreamChain, 1) {
		s.Equal(x509CA.Certificate, x509CA.UpstreamChain[0])
	}

	// The trust bundle should contain the upstream root
	s.requireBundleRootCAs(fakeUA.Root())

	// We expect this warning because the UpstreamAuthority doesn't implements PublishJWTKey
	s.Equal(
		1,
		s.countLogEntries(logrus.WarnLevel, "UpstreamAuthority plugin does not support JWT-SVIDs. Workloads managed "+
			"by this server may have trouble communicating with workloads outside "+
			"this cluster when using JWT-SVIDs."),
	)
}

func (s *ManagerSuite) TestUpstreamIntermediateSignedWithUpstreamBundle() {
	upstreamAuthority, fakeUA := fakeupstreamauthority.Load(s.T(), fakeupstreamauthority.Config{
		TrustDomain:     testTrustDomain,
		UseIntermediate: true,
	})
	s.initUpstreamSignedManager(upstreamAuthority, true)

	// X509 CA should be set up to be an intermediate and have two certs in
	// its chain: itself and the upstream intermediate that signed it.
	x509CA := s.currentX509CA()
	s.NotNil(x509CA.Signer)
	if s.NotNil(x509CA.Certificate) {
		s.Equal(fakeUA.Intermediate().Subject, x509CA.Certificate.Issuer)
	}
	if s.Len(x509CA.UpstreamChain, 2) {
		s.Equal(x509CA.Certificate, x509CA.UpstreamChain[0])
		s.Equal(fakeUA.Intermediate(), x509CA.UpstreamChain[1])
	}

	// The trust bundle should contain the upstream root
	s.requireBundleRootCAs(fakeUA.Root())

	// We expect this warning because the UpstreamAuthority doesn't implements PublishJWTKey
	s.Equal(
		1,
		s.countLogEntries(logrus.WarnLevel, "UpstreamAuthority plugin does not support JWT-SVIDs. Workloads managed "+
			"by this server may have trouble communicating with workloads outside "+
			"this cluster when using JWT-SVIDs."),
	)
}

func (s *ManagerSuite) TestUpstreamAuthorityWithPublishJWTKeyImplemented() {
	bundle := s.createBundle()
	s.Require().Len(bundle.JwtSigningKeys, 0)

	jwtSigningKey, _ := pemutil.ParseSigner([]byte(`
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGZx/yLVskGyXAyIT
uDe7PI1X4Dt1boMWfysKPyOJeMuhRANCAARzgo1R4J4xtjGpmGFNl2KADaxDpgx3
KfDQqPUcYWUMm2JbwFyHxQfhJfSf+Mla5C4FnJG6Ksa7pWjITPf5KbHi
-----END PRIVATE KEY-----
`))
	pkixBytes, err := x509.MarshalPKIXPublicKey(jwtSigningKey.Public())
	s.Require().NoError(err)
	jwk := &common.PublicKey{
		Kid:       "kid",
		PkixBytes: pkixBytes,
	}
	upstreamAuthority, _ := fakeupstreamauthority.Load(s.T(), fakeupstreamauthority.Config{
		TrustDomain: testTrustDomain,
		PublishJWTKeyResponse: &upstreamauthority.PublishJWTKeyResponse{
			UpstreamJwtKeys: []*common.PublicKey{jwk},
		},
	})
	s.initUpstreamSignedManager(upstreamAuthority, true)

	bundle = s.fetchBundle()
	s.Len(bundle.JwtSigningKeys, 1)
	s.Equal("kid", bundle.JwtSigningKeys[0].Kid)
	s.Equal(
		0,
		s.countLogEntries(logrus.WarnLevel, "UpstreamAuthority plugin does not support JWT-SVIDs. Workloads managed "+
			"by this server may have trouble communicating with workloads outside "+
			"this cluster when using JWT-SVIDs."),
	)
}

func (s *ManagerSuite) TestX509CARotation() {
	notifier, notifyCh := fakenotifier.NotifyWaiter()
	s.setNotifier(notifier)
	s.initSelfSignedManager()

	// kick off a goroutine to service bundle update notifications. This is
	// typically handled by Run() but using it would complicate the test.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.m.dropBundleUpdated() // drop bundle update message produce by initialization
	go s.m.notifyOnBundleUpdate(ctx)

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
	s.requireBundleRootCAs(first.Certificate)

	// move up to the preparation mark. nothing should change
	s.setTimeAndRotateX509CA(preparationTime1)
	s.requireX509CAEqual(first, s.currentX509CA())
	s.Nil(s.nextX509CA(), "second X509CA should not be prepared yet")
	s.requireBundleRootCAs(first.Certificate)

	// move just past the preparation mark. the current X509CA should stay
	// the same but the next X509CA should have been prepared and added to
	// the trust bundle.
	s.addTimeAndRotateX509CA(time.Minute)
	s.requireX509CAEqual(first, s.currentX509CA())
	second := s.nextX509CA()
	s.NotNil(second, "second X509CA should have been prepared")
	s.requireBundleRootCAs(first.Certificate, second.Certificate)

	// we should now have a bundle update notification due to the preparation
	s.waitForBundleUpdatedNotification(notifyCh)

	// move up to the activation mark. nothing should change.
	s.setTimeAndRotateX509CA(activationTime1)
	s.requireX509CAEqual(first, s.currentX509CA())
	s.requireX509CAEqual(second, s.nextX509CA())

	// move up to the activation mark. "next" should become "current" and
	// "next" should be reset.
	s.addTimeAndRotateX509CA(time.Minute)
	s.requireX509CAEqual(second, s.currentX509CA())
	s.Nil(s.nextX509CA())

	// move past the 2nd preparation mark. the current X509CA should stay
	// the same but the next X509CA should have been prepared and added to
	// the trust bundle.
	s.setTimeAndRotateX509CA(preparationTime2.Add(time.Minute))
	s.requireX509CAEqual(second, s.currentX509CA())
	third := s.nextX509CA()
	s.NotNil(second, "third X509CA should have been prepared")
	s.requireBundleRootCAs(first.Certificate, second.Certificate, third.Certificate)

	// we should now have another bundle update notification due to the preparation
	s.waitForBundleUpdatedNotification(notifyCh)

	// move past to 2nd activation mark. "next" should become "current" and
	// "next" should be reset.
	s.setTimeAndRotateX509CA(activationTime2.Add(time.Minute))
	s.requireX509CAEqual(third, s.currentX509CA())
	s.Nil(s.nextX509CA())
}

func (s *ManagerSuite) TestX509CARotationMetric() {
	s.initSelfSignedManager()

	// use fake metric
	metrics := fakemetrics.New()
	s.m.c.Metrics = metrics

	initTime := s.clock.Now()

	// rotate CA to preparation mark
	s.setTimeAndRotateX509CA(initTime.Add(prepareAfter + time.Second))

	// reset the metrics rotate CA to activate mark
	metrics.Reset()
	s.setTimeAndRotateX509CA(initTime.Add(activateAfter + time.Second))

	// create expected metrics with ttl from certificate
	expected := fakemetrics.New()
	ttl := s.currentX509CA().Certificate.NotAfter.Sub(s.clock.Now())
	telemetry_server.IncrActivateX509CAManagerCounter(expected)
	telemetry_server.SetX509CARotateGauge(expected, s.m.c.TrustDomain.String(), float32(ttl.Seconds()))

	s.Require().Equal(expected.AllMetrics(), metrics.AllMetrics())
}

func (s *ManagerSuite) TestJWTKeyRotation() {
	notifier, notifyCh := fakenotifier.NotifyWaiter()
	s.setNotifier(notifier)
	s.initSelfSignedManager()

	// kick off a goroutine to service bundle update notifications. This is
	// typically handled by Run() but using it would complicate the test.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.m.dropBundleUpdated() // drop bundle update message produce by initialization
	go s.m.notifyOnBundleUpdate(ctx)

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
	s.setTimeAndRotateJWTKey(preparationTime1)
	s.requireJWTKeyEqual(first, s.currentJWTKey())
	s.Nil(s.nextJWTKey(), "second JWTKey should not be prepared yet")
	s.requireBundleJWTKeys(first)

	// move just past the preparation mark. the current JWTKey should stay
	// the same but the next JWTKey should have been prepared and added to
	// the trust bundle.
	s.addTimeAndRotateJWTKey(time.Minute)
	s.requireJWTKeyEqual(first, s.currentJWTKey())
	second := s.nextJWTKey()
	s.NotNil(second, "second JWTKey should have been prepared")
	s.requireBundleJWTKeys(first, second)

	// we should now have a bundle update notification due to the preparation
	s.waitForBundleUpdatedNotification(notifyCh)

	// move up to the activation mark. nothing should change.
	s.setTimeAndRotateJWTKey(activationTime1)
	s.requireJWTKeyEqual(first, s.currentJWTKey())
	s.requireJWTKeyEqual(second, s.nextJWTKey())

	// move up to the activation mark. "next" should become "current" and
	// "next" should be reset.
	s.addTimeAndRotateJWTKey(time.Minute)
	s.requireJWTKeyEqual(second, s.currentJWTKey())
	s.Nil(s.nextJWTKey())

	// move past the 2nd preparation mark. the current JWTKey should stay
	// the same but the next JWTKey should have been prepared and added to
	// the trust bundle.
	s.setTimeAndRotateJWTKey(preparationTime2.Add(time.Minute))
	s.requireJWTKeyEqual(second, s.currentJWTKey())
	third := s.nextJWTKey()
	s.NotNil(second, "third JWTKey should have been prepared")
	s.requireBundleJWTKeys(first, second, third)

	// we should now have a bundle update notification due to the preparation
	s.waitForBundleUpdatedNotification(notifyCh)

	// move past to 2nd activation mark. "next" should become "current" and
	// "next" should be reset.
	s.setTimeAndRotateJWTKey(activationTime2.Add(time.Minute))
	s.requireJWTKeyEqual(third, s.currentJWTKey())
	s.Nil(s.nextJWTKey())
}

func (s *ManagerSuite) TestPrune() {
	notifier, notifyCh := fakenotifier.NotifyWaiter()
	s.setNotifier(notifier)
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
	s.requireBundleRootCAs(firstX509CA.Certificate, secondX509CA.Certificate)
	s.requireBundleJWTKeys(firstJWTKey, secondJWTKey)

	// kick off a goroutine to service bundle update notifications. This is
	// typically handled by Run() but using it would complicate the test.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.m.dropBundleUpdated() // drop bundle update message produce by initialization
	go s.m.notifyOnBundleUpdate(ctx)

	// advance just past the expiration time of the first and prune. nothing
	// should change.
	s.setTimeAndPrune(firstExpiresTime.Add(time.Minute))
	s.requireBundleRootCAs(firstX509CA.Certificate, secondX509CA.Certificate)
	s.requireBundleJWTKeys(firstJWTKey, secondJWTKey)

	// advance beyond the safety threshold of the first, prune, and assert that
	// the first has been pruned
	s.addTimeAndPrune(safetyThreshold)
	s.requireBundleRootCAs(secondX509CA.Certificate)
	s.requireBundleJWTKeys(secondJWTKey)

	// we should now have a bundle update notification due to the pruning
	s.waitForBundleUpdatedNotification(notifyCh)

	// advance beyond the second expiration time, prune, and assert nothing
	// changes because we can't prune out the whole bundle.
	s.clock.Set(secondExpiresTime.Add(time.Minute + safetyThreshold))
	s.Require().EqualError(s.m.pruneBundle(context.Background()), "unable to prune bundle: prune failed: would prune all certificates")
	s.requireBundleRootCAs(secondX509CA.Certificate)
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

func (s *ManagerSuite) TestRunNotifiesBundleLoaded() {
	s.initSelfSignedManager()

	// time out in a minute if the bundle loaded never happens
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	var actual *common.Bundle
	s.setNotifier(fakenotifier.New(fakenotifier.Config{
		OnNotifyAndAdvise: func(req *notifier.NotifyAndAdviseRequest) (*notifier.NotifyAndAdviseResponse, error) {
			if event, ok := req.Event.(*notifier.NotifyAndAdviseRequest_BundleLoaded); ok {
				actual = event.BundleLoaded.Bundle
			}
			// cancel immediately
			cancel()
			return &notifier.NotifyAndAdviseResponse{}, nil
		},
	}))

	s.Require().NoError(s.m.Run(ctx))

	// make sure the event contained the bundle
	expected := s.fetchBundle()
	s.RequireProtoEqual(expected, actual)
}

func (s *ManagerSuite) TestRunFailsIfNotifierFails() {
	s.m = NewManager(s.selfSignedConfig())
	s.setNotifier(fakenotifier.New(fakenotifier.Config{
		OnNotifyAndAdvise: func(req *notifier.NotifyAndAdviseRequest) (*notifier.NotifyAndAdviseResponse, error) {
			return nil, errors.New("ohno")
		},
	}))

	err := s.m.Initialize(ctx)
	s.Require().NoError(err)

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	err = s.m.Run(ctx)
	s.Require().EqualError(err, "one or more notifiers returned an error: ohno")

	entry := s.logHook.LastEntry()
	s.Equal("fake", entry.Data["notifier"])
	s.Equal("bundle loaded", entry.Data["event"])
	s.Equal("ohno", fmt.Sprintf("%v", entry.Data["error"]))
	s.Equal("Notifier failed to handle event", entry.Message)
}

func (s *ManagerSuite) TestPreparationThresholdCap() {
	issuedAt := time.Now()
	notAfter := issuedAt.Add(365 * 24 * time.Hour)

	// Expect the preparation threshold to get capped since 1/2 of the lifetime
	// exceeds the thirty day cap.
	threshold := preparationThreshold(issuedAt, notAfter)
	s.Require().Equal(thirtyDays, notAfter.Sub(threshold))
}

func (s *ManagerSuite) TestActivationThreshholdCap() {
	issuedAt := time.Now()
	notAfter := issuedAt.Add(365 * 24 * time.Hour)

	// Expect the activation threshold to get capped since 1/6 of the lifetime
	// exceeds the seven day cap.
	threshold := KeyActivationThreshold(issuedAt, notAfter)
	s.Require().Equal(sevenDays, notAfter.Sub(threshold))
}

func (s *ManagerSuite) TestAlternateKeyTypes() {
	ua, _ := fakeupstreamauthority.Load(s.T(), fakeupstreamauthority.Config{
		TrustDomain: testTrustDomain,
	})

	upstreamAuthority := fakeservercatalog.UpstreamAuthority(
		"fakeupstreamauthority", ua)

	expectRSA := func(t *testing.T, signer crypto.Signer, keySize int) {
		publicKey, ok := signer.Public().(*rsa.PublicKey)
		t.Logf("PUBLIC KEY TYPE: %T", signer.Public())
		if assert.True(t, ok, "Signer is not RSA") {
			assert.Equal(t, keySize, publicKey.Size(), "Incorrect key size")
		}
	}

	expectRSA2048 := func(t *testing.T, signer crypto.Signer) {
		expectRSA(t, signer, 256)
	}

	expectRSA4096 := func(t *testing.T, signer crypto.Signer) {
		expectRSA(t, signer, 512)
	}

	expectEC := func(t *testing.T, signer crypto.Signer, keySize int) {
		publicKey, ok := signer.Public().(*ecdsa.PublicKey)
		t.Logf("PUBLIC KEY TYPE: %T", signer.Public())
		if assert.True(t, ok, "Signer is not ECDSA") {
			assert.Equal(t, keySize, publicKey.Params().BitSize, "Incorrect key bit size")
		}
	}

	expectEC256 := func(t *testing.T, signer crypto.Signer) {
		expectEC(t, signer, 256)
	}

	expectEC384 := func(t *testing.T, signer crypto.Signer) {
		expectEC(t, signer, 384)
	}

	testCases := []struct {
		name              string
		upstreamAuthority *catalog.UpstreamAuthority
		x509CAKeyType     keymanager.KeyType
		jwtKeyType        keymanager.KeyType
		checkX509CA       func(*testing.T, crypto.Signer)
		checkJWTKey       func(*testing.T, crypto.Signer)
	}{
		{
			name:        "self-signed with defaults",
			checkX509CA: expectEC384,
			checkJWTKey: expectEC256,
		},
		{
			name:          "self-signed with RSA 2048",
			x509CAKeyType: keymanager.KeyType_RSA_2048,
			jwtKeyType:    keymanager.KeyType_RSA_2048,
			checkX509CA:   expectRSA2048,
			checkJWTKey:   expectRSA2048,
		},
		{
			name:          "self-signed with RSA 4096",
			x509CAKeyType: keymanager.KeyType_RSA_4096,
			jwtKeyType:    keymanager.KeyType_RSA_4096,
			checkX509CA:   expectRSA4096,
			checkJWTKey:   expectRSA4096,
		},
		{
			name:          "self-signed with EC P256",
			x509CAKeyType: keymanager.KeyType_EC_P256,
			jwtKeyType:    keymanager.KeyType_EC_P256,
			checkX509CA:   expectEC256,
			checkJWTKey:   expectEC256,
		},
		{
			name:          "self-signed with EC P384",
			x509CAKeyType: keymanager.KeyType_EC_P384,
			jwtKeyType:    keymanager.KeyType_EC_P384,
			checkX509CA:   expectEC384,
			checkJWTKey:   expectEC384,
		},
		{
			name:              "upstream-signed with defaults",
			upstreamAuthority: upstreamAuthority,
			checkX509CA:       expectEC384,
			checkJWTKey:       expectEC256,
		},
		{
			name:              "upstream-signed with RSA 2048",
			upstreamAuthority: upstreamAuthority,
			x509CAKeyType:     keymanager.KeyType_RSA_2048,
			jwtKeyType:        keymanager.KeyType_RSA_2048,
			checkX509CA:       expectRSA2048,
			checkJWTKey:       expectRSA2048,
		},
		{
			name:              "upstream-signed with RSA 4096",
			upstreamAuthority: upstreamAuthority,
			x509CAKeyType:     keymanager.KeyType_RSA_4096,
			jwtKeyType:        keymanager.KeyType_RSA_4096,
			checkX509CA:       expectRSA4096,
			checkJWTKey:       expectRSA4096,
		},
		{
			name:              "upstream-signed with EC P256",
			upstreamAuthority: upstreamAuthority,
			x509CAKeyType:     keymanager.KeyType_EC_P256,
			jwtKeyType:        keymanager.KeyType_EC_P256,
			checkX509CA:       expectEC256,
			checkJWTKey:       expectEC256,
		},
		{
			name:              "upstream-signed with EC P384",
			upstreamAuthority: upstreamAuthority,
			x509CAKeyType:     keymanager.KeyType_EC_P384,
			jwtKeyType:        keymanager.KeyType_EC_P384,
			checkX509CA:       expectEC384,
			checkJWTKey:       expectEC384,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		s.T().Run(testCase.name, func(t *testing.T) {
			c := s.selfSignedConfig()
			c.X509CAKeyType = testCase.x509CAKeyType
			c.JWTKeyType = testCase.jwtKeyType
			c.UpstreamBundle = false

			// Reset the key manager for each test case to ensure a fresh
			// rotation.
			s.cat.SetKeyManager(memory.New())

			// Optionally provide an upstream authority
			s.cat.SetUpstreamAuthority(testCase.upstreamAuthority)

			s.m = NewManager(c)
			assert.NoError(t, s.m.Initialize(context.Background()))

			testCase.checkX509CA(t, s.currentX509CA().Signer)
			testCase.checkJWTKey(t, s.currentJWTKey().Signer)
		})
	}
}

func (s *ManagerSuite) initSelfSignedManager() {
	s.cat.SetUpstreamAuthority(nil)
	s.m = NewManager(s.selfSignedConfig())
	s.NoError(s.m.Initialize(context.Background()))
}

func (s *ManagerSuite) initUpstreamSignedManager(upstreamAuthority upstreamauthority.UpstreamAuthority, upstreamBundle bool) {
	s.cat.SetUpstreamAuthority(fakeservercatalog.UpstreamAuthority("fakeupstreamauthority", upstreamAuthority))

	c := s.selfSignedConfig()
	c.UpstreamBundle = upstreamBundle
	s.m = NewManager(c)
	s.NoError(s.m.Initialize(context.Background()))
}

func (s *ManagerSuite) setNotifier(notifier notifier.Notifier) {
	s.cat.AddNotifier(fakeservercatalog.Notifier("fake", notifier))
}

func (s *ManagerSuite) selfSignedConfig() ManagerConfig {
	return s.selfSignedConfigWithKeyTypes(0, 0)
}

func (s *ManagerSuite) selfSignedConfigWithKeyTypes(x509CAKeyType, jwtKeyType keymanager.KeyType) ManagerConfig {
	return ManagerConfig{
		CA:          s.ca,
		Catalog:     s.cat,
		TrustDomain: testTrustDomainURL,
		CASubject: pkix.Name{
			CommonName: "SPIRE",
		},
		CATTL:         testCATTL,
		X509CAKeyType: x509CAKeyType,
		JWTKeyType:    jwtKeyType,
		Dir:           s.dir,
		Metrics:       telemetry.Blackhole{},
		Log:           s.log,
		Clock:         s.clock,
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
	Signer        signerInfo
	Certificate   *x509.Certificate
	UpstreamChain []*x509.Certificate
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
		Signer:        s.getSignerInfo(x509CA.Signer),
		Certificate:   x509CA.Certificate,
		UpstreamChain: x509CA.UpstreamChain,
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

func (s *ManagerSuite) createBundle() *common.Bundle {
	resp, err := s.ds.CreateBundle(ctx, &datastore.CreateBundleRequest{
		Bundle: &common.Bundle{
			TrustDomainId: testTrustDomainURL.String(),
		},
	})
	s.Require().NoError(err)
	return resp.Bundle
}

func (s *ManagerSuite) fetchBundle() *common.Bundle {
	return s.fetchBundleForTrustDomain(testTrustDomainURL.String())
}

func (s *ManagerSuite) fetchBundleForTrustDomain(trustDomainID string) *common.Bundle {
	resp, err := s.ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: trustDomainID,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp.Bundle, "missing bundle for trust domain %q", trustDomainID)
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

func (s *ManagerSuite) setTimeAndRotateX509CA(t time.Time) {
	s.clock.Set(t)
	s.Require().NoError(s.m.rotateX509CA(context.Background()))
}

func (s *ManagerSuite) addTimeAndRotateX509CA(d time.Duration) {
	s.clock.Add(d)
	s.Require().NoError(s.m.rotateX509CA(context.Background()))
}

func (s *ManagerSuite) setTimeAndRotateJWTKey(t time.Time) {
	s.clock.Set(t)
	s.Require().NoError(s.m.rotateJWTKey(context.Background()))
}

func (s *ManagerSuite) addTimeAndRotateJWTKey(d time.Duration) {
	s.clock.Add(d)
	s.Require().NoError(s.m.rotateJWTKey(context.Background()))
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

func (s *ManagerSuite) waitForBundleUpdatedNotification(ch <-chan *notifier.NotifyRequest) {
	select {
	case <-time.After(time.Minute):
		s.FailNow("timed out waiting for bundle update notification")
	case req := <-ch:
		event, ok := req.Event.(*notifier.NotifyRequest_BundleUpdated)
		s.Require().True(ok, "expected a bundle updated notification")
		actual := event.BundleUpdated.Bundle
		expected := s.fetchBundle()
		s.RequireProtoEqual(expected, actual)
	}
}

func (s *ManagerSuite) countLogEntries(level logrus.Level, message string) int { //nolint
	count := 0
	for _, e := range s.logHook.AllEntries() {
		if e.Message == message && level == e.Level {
			count++
		}
	}
	return count
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
