package manager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/credvalidator"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/fakes/fakenotifier"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeserverkeymanager"
	"github.com/spiffe/spire/test/fakes/fakeupstreamauthority"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testCATTL     = time.Hour
	activateAfter = testCATTL - (testCATTL / 6)
	prepareAfter  = testCATTL - (testCATTL / 2)
)

var (
	testTrustDomain = spiffeid.RequireTrustDomainFromString("domain.test")
)

func TestGetCurrentJWTKeySlot(t *testing.T) {
	ctx := context.Background()

	test := setupTest(t)
	test.initSelfSignedManager()

	t.Run("no authority created", func(t *testing.T) {
		currentSlot := test.m.GetCurrentJWTKeySlot()

		slot := currentSlot.(*JwtKeySlot)

		require.True(t, slot.IsEmpty())
		require.Empty(t, slot.issuedAt)
		require.Empty(t, slot.authorityID)
		require.Empty(t, slot.notAfter)
	})

	t.Run("slot returned", func(t *testing.T) {
		expectIssuedAt := test.clock.Now()
		expectNotAfter := expectIssuedAt.Add(test.m.caTTL)

		require.NoError(t, test.m.PrepareJWTKey(ctx))

		currentSlot := test.m.GetCurrentJWTKeySlot()
		slot := currentSlot.(*JwtKeySlot)
		require.NotNil(t, slot.jwtKey)
		require.NotEmpty(t, slot.authorityID)
		require.Equal(t, expectIssuedAt, slot.issuedAt)
		require.Equal(t, expectNotAfter, slot.notAfter)
	})
}

func TestGetNextJWTKeySlot(t *testing.T) {
	ctx := context.Background()

	test := setupTest(t)
	test.initAndActivateSelfSignedManager(ctx)

	t.Run("no next created", func(t *testing.T) {
		nextSlot := test.m.GetNextJWTKeySlot()
		slot := nextSlot.(*JwtKeySlot)

		require.Nil(t, slot.jwtKey)
		require.Empty(t, slot.issuedAt)
		require.Empty(t, slot.authorityID)
		require.Empty(t, slot.notAfter)
	})

	t.Run("next returned", func(t *testing.T) {
		expectIssuedAt := test.clock.Now()
		expectNotAfter := expectIssuedAt.Add(test.m.caTTL)

		require.NoError(t, test.m.PrepareJWTKey(ctx))

		nextSlot := test.m.GetNextJWTKeySlot()
		slot := nextSlot.(*JwtKeySlot)
		require.NotNil(t, slot.jwtKey)
		require.NotEmpty(t, slot.authorityID)
		require.Equal(t, expectIssuedAt, slot.issuedAt)
		require.Equal(t, expectNotAfter, slot.notAfter)
	})
}

func TestGetCurrentX509CASlot(t *testing.T) {
	ctx := context.Background()

	test := setupTest(t)
	test.initSelfSignedManager()

	t.Run("no authority created", func(t *testing.T) {
		currentSlot := test.m.GetCurrentX509CASlot()

		slot := currentSlot.(*X509CASlot)
		require.Nil(t, slot.x509CA)
		require.Empty(t, slot.authorityID)
		require.Empty(t, slot.issuedAt)
		require.Empty(t, slot.publicKey)
		require.Empty(t, slot.notAfter)
	})

	t.Run("slot returned", func(t *testing.T) {
		expectIssuedAt := test.clock.Now()
		expectNotAfter := expectIssuedAt.Add(test.m.caTTL).UTC()

		require.NoError(t, test.m.PrepareX509CA(ctx))

		currentSlot := test.m.GetCurrentX509CASlot()
		slot := currentSlot.(*X509CASlot)
		require.NotNil(t, slot.x509CA)
		require.NotEmpty(t, slot.authorityID)
		require.NotNil(t, slot.publicKey)
		require.Equal(t, expectIssuedAt, slot.issuedAt)
		require.Equal(t, expectNotAfter, slot.notAfter)
	})
}

func TestGetNextX509CASlot(t *testing.T) {
	ctx := context.Background()

	test := setupTest(t)
	test.initAndActivateSelfSignedManager(ctx)

	t.Run("no next created", func(t *testing.T) {
		nextSlot := test.m.GetNextX509CASlot()
		slot := nextSlot.(*X509CASlot)

		require.Nil(t, slot.x509CA)
		require.Empty(t, slot.authorityID)
		require.Empty(t, slot.issuedAt)
		require.Empty(t, slot.publicKey)
		require.Empty(t, slot.notAfter)
	})

	t.Run("next returned", func(t *testing.T) {
		expectIssuedAt := test.clock.Now()
		expectNotAfter := expectIssuedAt.Add(test.m.caTTL).UTC()

		require.NoError(t, test.m.PrepareX509CA(ctx))

		nextSlot := test.m.GetNextX509CASlot()
		slot := nextSlot.(*X509CASlot)
		require.NotNil(t, slot.x509CA)
		require.NotEmpty(t, slot.authorityID)
		require.NotNil(t, slot.publicKey)
		require.Equal(t, expectIssuedAt, slot.issuedAt)
		require.Equal(t, expectNotAfter, slot.notAfter)
	})
}

func TestPersistence(t *testing.T) {
	ctx := context.Background()

	test := setupTest(t)

	// No entries on journal
	test.initSelfSignedManager()
	require.Nil(t, test.currentJWTKey())
	require.Nil(t, test.currentX509CA())

	// Prepare authority and activate authority
	require.NoError(t, test.m.PrepareJWTKey(ctx))
	test.m.ActivateJWTKey()
	require.NoError(t, test.m.PrepareX509CA(ctx))
	test.m.ActivateX509CA()

	firstX509CA, firstJWTKey := test.currentX509CA(), test.currentJWTKey()

	// reinitialize against the same storage
	test.initSelfSignedManager()
	test.requireX509CAEqual(t, firstX509CA, test.currentX509CA())
	test.requireJWTKeyEqual(t, firstJWTKey, test.currentJWTKey())

	require.Nil(t, test.nextX509CA())
	require.Nil(t, test.nextJWTKey())

	// prepare the next and reinitialize, move time
	test.clock.Add(prepareAfter + time.Minute)
	require.NoError(t, test.m.PrepareJWTKey(ctx))
	require.NoError(t, test.m.PrepareX509CA(ctx))

	secondX509CA, secondJWTKey := test.nextX509CA(), test.nextJWTKey()
	test.initSelfSignedManager()
	test.requireX509CAEqual(t, firstX509CA, test.currentX509CA())
	test.requireJWTKeyEqual(t, firstJWTKey, test.currentJWTKey())
	test.requireX509CAEqual(t, secondX509CA, test.nextX509CA())
	test.requireJWTKeyEqual(t, secondJWTKey, test.nextJWTKey())
}

func TestSlotLoadedWhenJournalIsLost(t *testing.T) {
	ctx := context.Background()

	test := setupTest(t)
	test.initAndActivateSelfSignedManager(ctx)
	x509CA, jwtKey := test.currentX509CA(), test.currentJWTKey()

	// After reinitialize keep current still there
	test.initSelfSignedManager()
	test.requireX509CAEqual(t, x509CA, test.currentX509CA())
	test.requireJWTKeyEqual(t, jwtKey, test.currentJWTKey())

	// wipe the journal, reinitialize, and make sure the keys differ. this
	// simulates the key manager having dangling keys.
	test.wipeJournal(t)
	test.initSelfSignedManager()
	// After journal is lost no slot is found
	require.True(t, test.m.GetCurrentJWTKeySlot().IsEmpty())
	require.True(t, test.m.GetCurrentX509CASlot().IsEmpty())
}

func TestSelfSigning(t *testing.T) {
	ctx := context.Background()
	test := setupTest(t)
	test.initAndActivateSelfSignedManager(ctx)

	x509CA := test.currentX509CA()
	require.NotNil(t, x509CA.Signer)
	if assert.NotNil(t, x509CA.Certificate) {
		require.Equal(t, x509CA.Certificate.Subject, x509CA.Certificate.Issuer)
	}
	assert.Empty(t, x509CA.UpstreamChain)
	require.Equal(t, 1, x509CA.Certificate.SerialNumber.Cmp(big.NewInt(0)))
	require.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, x509CA.Certificate.KeyUsage)

	// Assert that the self-signed X.509 CA produces a valid certificate chain
	test.validateSelfSignedX509CA(x509CA.Certificate, x509CA.Signer)
}

func TestUpstreamSigned(t *testing.T) {
	ctx := context.Background()
	test := setupTest(t)

	upstreamAuthority, fakeUA := fakeupstreamauthority.Load(t, fakeupstreamauthority.Config{
		TrustDomain:           testTrustDomain,
		DisallowPublishJWTKey: true,
	})

	test.initAndActivateUpstreamSignedManager(ctx, upstreamAuthority)

	// X509 CA should be set up to be an intermediate but only have itself
	// in the chain since it was signed directly by the upstream root.
	x509CA := test.currentX509CA()
	assert.NotNil(t, x509CA.Signer)
	if assert.NotNil(t, x509CA.Certificate) {
		assert.Equal(t, fakeUA.X509Root().Subject, x509CA.Certificate.Issuer)
	}
	if assert.Len(t, x509CA.UpstreamChain, 1) {
		assert.Equal(t, x509CA.Certificate, x509CA.UpstreamChain[0])
	}

	// The trust bundle should contain the upstream root
	test.requireBundleRootCAs(ctx, t, fakeUA.X509Root())

	// We expect this warning because the UpstreamAuthority doesn't implement PublishJWTKey
	assert.Equal(t,
		1,
		test.countLogEntries(logrus.WarnLevel, "UpstreamAuthority plugin does not support JWT-SVIDs. Workloads managed "+
			"by this server may have trouble communicating with workloads outside "+
			"this cluster when using JWT-SVIDs."),
	)
}

func TestUpstreamSignedProducesInvalidChain(t *testing.T) {
	ctx := context.Background()
	test := setupTest(t)
	upstreamAuthority, _ := fakeupstreamauthority.Load(t, fakeupstreamauthority.Config{
		TrustDomain: testTrustDomain,
		// The verification code relies on go-spiffe, which for compat reasons,
		// does not currently validate SPIFFE conformance beyond the leaf
		// certificate. The manager relies on other layers to produce a valid
		// leaf SVID, making it difficult to influence the leaf to produce an
		// invalid chain without some refactoring. For now, to produce an
		// invalid chain, we'll set a key usage on the intermediate CA that is
		// not allowed by RFC 5280 for signing certificates. This will cause
		// the go x509 stack to reject the signature on the leaf when the
		// manager does the validation.
		//
		// We want to ensure that the manager is verifying the chain via
		// go-spiffe, and the error message produced has go-spiffe specific
		// markers in it. This is probably good enough.
		KeyUsage: x509.KeyUsageDigitalSignature,
	})

	test.cat.SetUpstreamAuthority(upstreamAuthority)

	manager, err := NewManager(ctx, test.selfSignedConfig())
	require.NoError(t, err)
	require.NotNil(t, manager)

	err = manager.PrepareX509CA(ctx)
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, `X509 CA minted by upstream authority is invalid: X509 CA produced an invalid X509-SVID chain: x509svid: could not verify leaf certificate: x509: certificate signed by unknown authority (possibly because of "x509: invalid signature: parent certificate cannot sign this kind of certificate" while trying to verify candidate authority certificate "FAKEUPSTREAMAUTHORITY-ROOT")`)
}

func TestUpstreamIntermediateSigned(t *testing.T) {
	ctx := context.Background()
	test := setupTest(t)
	upstreamAuthority, fakeUA := fakeupstreamauthority.Load(t, fakeupstreamauthority.Config{
		TrustDomain:           testTrustDomain,
		DisallowPublishJWTKey: true,
		UseIntermediate:       true,
	})
	test.initAndActivateUpstreamSignedManager(ctx, upstreamAuthority)

	// X509 CA should be set up to be an intermediate and have two certs in
	// its chain: itself and the upstream intermediate that signed it.
	x509CA := test.currentX509CA()
	assert.NotNil(t, x509CA.Signer)
	if assert.NotNil(t, x509CA.Certificate) {
		assert.Equal(t, fakeUA.X509Intermediate().Subject, x509CA.Certificate.Issuer)
	}
	if assert.Len(t, x509CA.UpstreamChain, 2) {
		assert.Equal(t, x509CA.Certificate, x509CA.UpstreamChain[0])
		assert.Equal(t, fakeUA.X509Intermediate(), x509CA.UpstreamChain[1])
	}

	// The trust bundle should contain the upstream root
	test.requireBundleRootCAs(ctx, t, fakeUA.X509Root())

	// We expect this warning because the UpstreamAuthority doesn't implements PublishJWTKey
	assert.Equal(t,
		1,
		test.countLogEntries(logrus.WarnLevel, "UpstreamAuthority plugin does not support JWT-SVIDs. Workloads managed "+
			"by this server may have trouble communicating with workloads outside "+
			"this cluster when using JWT-SVIDs."),
	)
}

func TestUpstreamAuthorityWithPublishJWTKeyImplemented(t *testing.T) {
	ctx := context.Background()
	test := setupTest(t)
	bundle := test.createBundle(ctx)
	require.Len(t, bundle.JwtSigningKeys, 0)

	upstreamAuthority, ua := fakeupstreamauthority.Load(t, fakeupstreamauthority.Config{
		TrustDomain: testTrustDomain,
	})
	test.initAndActivateUpstreamSignedManager(ctx, upstreamAuthority)

	spiretest.AssertProtoListEqual(t, ua.JWTKeys(), test.fetchBundle(ctx).JwtSigningKeys)
	assert.Equal(t,
		0,
		test.countLogEntries(logrus.WarnLevel, "UpstreamAuthority plugin does not support JWT-SVIDs. Workloads managed "+
			"by this server may have trouble communicating with workloads outside "+
			"this cluster when using JWT-SVIDs."),
	)
}

func TestX509CARotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	test := setupTest(t)

	notifier, notifyCh := fakenotifier.NotifyBundleUpdatedWaiter(t)
	test.setNotifier(notifier)
	test.initAndActivateSelfSignedManager(ctx)

	// Clean updates

	// kick off a goroutine to service bundle update notifications. This is
	// typically handled by Run() but using it would complicate the test.
	test.m.dropBundleUpdated()
	go test.m.NotifyOnBundleUpdate(ctx)

	// after initialization, we should have a current X509CA but no next.
	first := test.currentX509CA()
	require.Equal(t, journal.Status_ACTIVE, test.currentX509CAStatus())
	assert.Nil(t, test.nextX509CA(), "second X509CA should not be prepared yet")
	require.Equal(t, journal.Status_UNKNOWN, test.nextX509CAStatus())
	test.requireBundleRootCAs(ctx, t, first.Certificate)

	// Prepare new X509CA. the current X509CA should stay
	// the same but the next X509CA should have been prepared and added to
	// the trust bundle.
	require.NoError(t, test.m.PrepareX509CA(ctx))
	test.requireX509CAEqual(t, first, test.currentX509CA())
	require.Equal(t, journal.Status_ACTIVE, test.currentX509CAStatus())

	second := test.nextX509CA()
	assert.NotNil(t, second, "second X509CA should have been prepared")
	require.Equal(t, journal.Status_PREPARED, test.nextX509CAStatus())
	test.requireBundleRootCAs(ctx, t, first.Certificate, second.Certificate)

	// we should now have a bundle update notification due to the preparation
	test.waitForBundleUpdatedNotification(ctx, notifyCh)

	// Rotate "next" should become "current" and
	// "next" should be reset.
	test.m.RotateX509CA()
	test.requireX509CAEqual(t, second, test.currentX509CA())
	require.Equal(t, journal.Status_ACTIVE, test.currentX509CAStatus())
	assert.Nil(t, test.nextX509CA())
	require.Equal(t, journal.Status_OLD, test.nextX509CAStatus())

	// Prepare new X509CA. the current X509CA should stay
	// the same but the next X509CA should have been prepared and added to
	// the trust bundle.
	require.NoError(t, test.m.PrepareX509CA(ctx))
	test.requireX509CAEqual(t, second, test.currentX509CA())
	require.Equal(t, journal.Status_ACTIVE, test.currentX509CAStatus())
	third := test.nextX509CA()
	assert.NotNil(t, third, "third X509CA should have been prepared")
	require.Equal(t, journal.Status_PREPARED, test.nextX509CAStatus())
	test.requireBundleRootCAs(ctx, t, first.Certificate, second.Certificate, third.Certificate)

	// we should now have another bundle update notification due to the preparation
	test.waitForBundleUpdatedNotification(ctx, notifyCh)

	// Rotate again, "next" should become "current" and
	// "next" should be reset.
	test.m.RotateX509CA()
	test.requireX509CAEqual(t, third, test.currentX509CA())
	require.Equal(t, journal.Status_ACTIVE, test.currentX509CAStatus())
	assert.Nil(t, test.nextX509CA())
	require.Equal(t, journal.Status_OLD, test.nextX509CAStatus())
}

func TestX509CARotationMetric(t *testing.T) {
	ctx := context.Background()
	test := setupTest(t)

	test.initAndActivateSelfSignedManager(ctx)

	// prepare next
	require.NoError(t, test.m.PrepareX509CA(ctx))

	// reset the metrics rotate CA to activate mark
	test.metrics.Reset()
	test.m.RotateX509CA()

	// create expected metrics with ttl from certificate
	expected := fakemetrics.New()
	ttl := test.currentX509CA().Certificate.NotAfter.Sub(test.clock.Now())
	telemetry_server.IncrActivateX509CAManagerCounter(expected)
	telemetry_server.SetX509CARotateGauge(expected, test.m.c.TrustDomain.Name(), float32(ttl.Seconds()))

	require.Equal(t, expected.AllMetrics(), test.metrics.AllMetrics())
}

func TestJWTKeyRotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	test := setupTest(t)

	notifier, notifyCh := fakenotifier.NotifyBundleUpdatedWaiter(t)
	test.setNotifier(notifier)
	test.initAndActivateSelfSignedManager(ctx)

	// kick off a goroutine to service bundle update notifications. This is
	// typically handled by Run() but using it would complicate the test.
	test.m.dropBundleUpdated() // drop bundle update message produce by initialization
	go test.m.NotifyOnBundleUpdate(ctx)

	// after initialization, we should have a current JWTKey but no next.
	first := test.currentJWTKey()
	require.Equal(t, journal.Status_ACTIVE, test.currentJWTKeyStatus())
	assert.Nil(t, test.nextJWTKey(), "second JWTKey should not be prepared yet")
	require.Equal(t, journal.Status_UNKNOWN, test.nextJWTKeyStatus())
	test.requireBundleJWTKeys(ctx, t, first)

	// prepare next. the current JWTKey should stay
	// the same but the next JWTKey should have been prepared and added to
	// the trust bundle.
	require.NoError(t, test.m.PrepareJWTKey(ctx))
	test.requireJWTKeyEqual(t, first, test.currentJWTKey())
	require.Equal(t, journal.Status_ACTIVE, test.currentJWTKeyStatus())
	second := test.nextJWTKey()
	require.Equal(t, journal.Status_PREPARED, test.nextJWTKeyStatus())
	assert.NotNil(t, second, "second JWTKey should have been prepared")
	test.requireBundleJWTKeys(ctx, t, first, second)

	// we should now have a bundle update notification due to the preparation
	test.waitForBundleUpdatedNotification(ctx, notifyCh)

	// rotate, "next" should become "current" and
	// "next" should be reset.
	test.m.RotateJWTKey()
	test.requireJWTKeyEqual(t, second, test.currentJWTKey())
	require.Equal(t, journal.Status_ACTIVE, test.currentJWTKeyStatus())
	assert.Nil(t, test.nextJWTKey())
	require.Equal(t, journal.Status_OLD, test.nextJWTKeyStatus())

	// Prepare next, the current JWTKey should stay
	// the same but the next JWTKey should have been prepared and added to
	// the trust bundle.
	require.NoError(t, test.m.PrepareJWTKey(ctx))
	test.requireJWTKeyEqual(t, second, test.currentJWTKey())
	require.Equal(t, journal.Status_ACTIVE, test.currentJWTKeyStatus())
	third := test.nextJWTKey()
	assert.NotNil(t, second, "third JWTKey should have been prepared")
	require.Equal(t, journal.Status_PREPARED, test.nextJWTKeyStatus())
	test.requireBundleJWTKeys(ctx, t, first, second, third)

	// we should now have a bundle update notification due to the preparation
	test.waitForBundleUpdatedNotification(ctx, notifyCh)

	// rotate again. "next" should become "current" and
	// "next" should be reset.
	test.m.RotateJWTKey()
	test.requireJWTKeyEqual(t, third, test.currentJWTKey())
	require.Equal(t, journal.Status_ACTIVE, test.currentJWTKeyStatus())
	assert.Nil(t, test.nextJWTKey())
	require.Equal(t, journal.Status_OLD, test.nextJWTKeyStatus())
}

func TestPruneBundle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	test := setupTest(t)

	notifier, notifyCh := fakenotifier.NotifyBundleUpdatedWaiter(t)
	test.setNotifier(notifier)
	test.initAndActivateSelfSignedManager(ctx)

	initTime := test.clock.Now()
	prepareSecondTime := initTime.Add(prepareAfter)
	firstExpiresTime := initTime.Add(testCATTL)
	secondExpiresTime := prepareSecondTime.Add(testCATTL)

	// set to change certificate times
	test.clock.Set(prepareSecondTime.Add(time.Minute))

	// prepare to have two bundles
	require.NoError(t, test.m.PrepareJWTKey(ctx))
	require.NoError(t, test.m.PrepareX509CA(ctx))

	firstX509CA := test.currentX509CA()
	firstJWTKey := test.currentJWTKey()
	secondX509CA := test.nextX509CA()
	secondJWTKey := test.nextJWTKey()
	test.requireBundleRootCAs(ctx, t, firstX509CA.Certificate, secondX509CA.Certificate)
	test.requireBundleJWTKeys(ctx, t, firstJWTKey, secondJWTKey)

	// kick off a goroutine to service bundle update notifications. This is
	// typically handled by Run() but using it would complicate the test.
	test.m.dropBundleUpdated() // drop bundle update message produce by initialization
	go test.m.NotifyOnBundleUpdate(ctx)

	// advance just past the expiration time of the first and prune. nothing
	// should change.
	test.setTimeAndPrune(firstExpiresTime.Add(time.Minute))
	test.requireBundleRootCAs(ctx, t, firstX509CA.Certificate, secondX509CA.Certificate)
	test.requireBundleJWTKeys(ctx, t, firstJWTKey, secondJWTKey)

	// advance beyond the safety threshold of the first, prune, and assert that
	// the first has been pruned
	test.addTimeAndPrune(safetyThreshold)
	test.requireBundleRootCAs(ctx, t, secondX509CA.Certificate)
	test.requireBundleJWTKeys(ctx, t, secondJWTKey)

	// we should now have a bundle update notification due to the pruning
	test.waitForBundleUpdatedNotification(ctx, notifyCh)

	// advance beyond the second expiration time, prune, and assert nothing
	// changes because we can't prune out the whole bundle.
	test.clock.Set(secondExpiresTime.Add(time.Minute + safetyThreshold))
	require.EqualError(t, test.m.PruneBundle(context.Background()), "unable to prune bundle: rpc error: code = Unknown desc = prune failed: would prune all certificates")
	test.requireBundleRootCAs(ctx, t, secondX509CA.Certificate)
	test.requireBundleJWTKeys(ctx, t, secondJWTKey)
}

func TestRunNotifiesBundleLoaded(t *testing.T) {
	test := setupTest(t)
	test.initAndActivateSelfSignedManager(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// time out in a minute if the bundle loaded never happens
	var actual *common.Bundle
	test.setNotifier(fakenotifier.New(t, fakenotifier.Config{
		OnNotifyAndAdviseBundleLoaded: func(bundle *common.Bundle) error {
			actual = bundle
			cancel()
			return nil
		},
	}))

	// The bundle loaded handler above will cancel the
	// context. This will usually be observed as an error returned from the
	// notifier, but not always, depending on the timing of the cancellation.
	// When the notifier does not return an error, Run will return without an
	// error when the canceled context is passed internally to run the tasks.
	err := test.m.NotifyBundleLoaded(ctx)
	require.EqualError(t, err, "one or more notifiers returned an error: rpc error: code = Canceled desc = notifier(fake): context canceled")

	// make sure the event contained the bundle
	expected := test.fetchBundle(context.Background())
	spiretest.RequireProtoEqual(t, expected, actual)
}

func TestRunFailsIfNotifierFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	test := setupTest(t)
	test.initAndActivateSelfSignedManager(ctx)
	// manager, err := NewManager(ctx, test.selfSignedConfig())
	// require.NoError(t, err)

	// test.m = manager
	test.setNotifier(fakenotifier.New(t, fakenotifier.Config{
		OnNotifyAndAdviseBundleLoaded: func(bundle *common.Bundle) error {
			return errors.New("ohno")
		},
	}))

	err := test.m.NotifyBundleLoaded(ctx)
	require.EqualError(t, err, "one or more notifiers returned an error: rpc error: code = Unknown desc = notifier(fake): ohno")

	entry := test.logHook.LastEntry()
	assert.Equal(t, "fake", entry.Data["notifier"])
	assert.Equal(t, "bundle loaded", entry.Data["event"])
	assert.Equal(t, "rpc error: code = Unknown desc = notifier(fake): ohno", fmt.Sprintf("%v", entry.Data["error"]))
	assert.Equal(t, "Notifier failed to handle event", entry.Message)
}

func TestPreparationThresholdCap(t *testing.T) {
	issuedAt := time.Now()
	notAfter := issuedAt.Add(365 * 24 * time.Hour)

	// Expect the preparation threshold to get capped since 1/2 of the lifetime
	// exceeds the thirty day cap.
	threshold := preparationThreshold(issuedAt, notAfter)
	require.Equal(t, thirtyDays, notAfter.Sub(threshold))
}

func TestActivationThreshholdCap(t *testing.T) {
	issuedAt := time.Now()
	notAfter := issuedAt.Add(365 * 24 * time.Hour)

	// Expect the activation threshold to get capped since 1/6 of the lifetime
	// exceeds the seven day cap.
	threshold := keyActivationThreshold(issuedAt, notAfter)
	require.Equal(t, sevenDays, notAfter.Sub(threshold))
}

func TestAlternateKeyTypes(t *testing.T) {
	upstreamAuthority, _ := fakeupstreamauthority.Load(t, fakeupstreamauthority.Config{
		TrustDomain: testTrustDomain,
	})

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
		upstreamAuthority upstreamauthority.UpstreamAuthority
		x509CAKeyType     keymanager.KeyType
		jwtKeyType        keymanager.KeyType
		checkX509CA       func(*testing.T, crypto.Signer)
		checkJWTKey       func(*testing.T, crypto.Signer)
	}{
		{
			name:          "self-signed with RSA 2048",
			x509CAKeyType: keymanager.RSA2048,
			jwtKeyType:    keymanager.RSA2048,
			checkX509CA:   expectRSA2048,
			checkJWTKey:   expectRSA2048,
		},
		{
			name:          "self-signed with RSA 4096",
			x509CAKeyType: keymanager.RSA4096,
			jwtKeyType:    keymanager.RSA4096,
			checkX509CA:   expectRSA4096,
			checkJWTKey:   expectRSA4096,
		},
		{
			name:          "self-signed with EC P256",
			x509CAKeyType: keymanager.ECP256,
			jwtKeyType:    keymanager.ECP256,
			checkX509CA:   expectEC256,
			checkJWTKey:   expectEC256,
		},
		{
			name:          "self-signed with EC P384",
			x509CAKeyType: keymanager.ECP384,
			jwtKeyType:    keymanager.ECP384,
			checkX509CA:   expectEC384,
			checkJWTKey:   expectEC384,
		},
		{
			name:          "self-signed JWT with RSA 2048 and X509 with EC P384",
			x509CAKeyType: keymanager.ECP384,
			jwtKeyType:    keymanager.RSA2048,
			checkX509CA:   expectEC384,
			checkJWTKey:   expectRSA2048,
		},
		{
			name:              "upstream-signed with RSA 2048",
			upstreamAuthority: upstreamAuthority,
			x509CAKeyType:     keymanager.RSA2048,
			jwtKeyType:        keymanager.RSA2048,
			checkX509CA:       expectRSA2048,
			checkJWTKey:       expectRSA2048,
		},
		{
			name:              "upstream-signed with RSA 4096",
			upstreamAuthority: upstreamAuthority,
			x509CAKeyType:     keymanager.RSA4096,
			jwtKeyType:        keymanager.RSA4096,
			checkX509CA:       expectRSA4096,
			checkJWTKey:       expectRSA4096,
		},
		{
			name:              "upstream-signed with EC P256",
			upstreamAuthority: upstreamAuthority,
			x509CAKeyType:     keymanager.ECP256,
			jwtKeyType:        keymanager.ECP256,
			checkX509CA:       expectEC256,
			checkJWTKey:       expectEC256,
		},
		{
			name:              "upstream-signed with EC P384",
			upstreamAuthority: upstreamAuthority,
			x509CAKeyType:     keymanager.ECP384,
			jwtKeyType:        keymanager.ECP384,
			checkX509CA:       expectEC384,
			checkJWTKey:       expectEC384,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()

			test := setupTest(t)
			c := test.selfSignedConfig()
			c.X509CAKeyType = testCase.x509CAKeyType
			c.JWTKeyType = testCase.jwtKeyType

			// Reset the key manager for each test case to ensure a fresh
			// rotation.
			test.cat.SetKeyManager(fakeserverkeymanager.New(t))

			// Optionally provide an upstream authority
			test.cat.SetUpstreamAuthority(testCase.upstreamAuthority)

			manager, err := NewManager(ctx, c)
			require.NoError(t, err)
			test.m = manager

			// Prepare and activate a bundle
			require.NoError(t, test.m.PrepareJWTKey(ctx))
			test.m.ActivateJWTKey()
			require.NoError(t, test.m.PrepareX509CA(ctx))
			test.m.activateX509CA()

			testCase.checkX509CA(t, test.currentX509CA().Signer)
			testCase.checkJWTKey(t, test.currentJWTKey().Signer)
		})
	}
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

type managerTest struct {
	t       *testing.T
	clock   *clock.Mock
	ca      *fakeCA
	log     logrus.FieldLogger
	logHook *test.Hook
	metrics *fakemetrics.FakeMetrics
	dir     string
	km      keymanager.KeyManager
	ds      *fakedatastore.DataStore
	cat     *fakeservercatalog.Catalog

	m *Manager
}

func setupTest(t *testing.T) *managerTest {
	clock := clock.NewMock(t)
	ca := new(fakeCA)

	log, logHook := test.NewNullLogger()
	metrics := fakemetrics.New()
	km := fakeserverkeymanager.New(t)
	ds := fakedatastore.New(t)

	cat := fakeservercatalog.New()
	cat.SetKeyManager(km)
	cat.SetDataStore(ds)

	dir := t.TempDir()

	return &managerTest{
		t:       t,
		clock:   clock,
		ca:      ca,
		log:     log,
		logHook: logHook,
		metrics: metrics,
		ds:      ds,
		cat:     cat,
		dir:     dir,
		km:      km,
	}
}

func (m *managerTest) initSelfSignedManager() {
	m.cat.SetUpstreamAuthority(nil)
	manager, err := NewManager(context.Background(), m.selfSignedConfig())
	require.NoError(m.t, err)
	m.m = manager
}

func (m *managerTest) initAndActivateSelfSignedManager(ctx context.Context) {
	m.cat.SetUpstreamAuthority(nil)
	manager, err := NewManager(context.Background(), m.selfSignedConfig())
	require.NoError(m.t, err)

	require.NoError(m.t, manager.PrepareJWTKey(ctx))
	manager.ActivateJWTKey()
	require.NoError(m.t, manager.PrepareX509CA(ctx))
	manager.ActivateX509CA()

	m.m = manager
}

func (m *managerTest) setNotifier(notifier notifier.Notifier) {
	m.cat.AddNotifier(notifier)
}

func (m *managerTest) initUpstreamSignedManager(upstreamAuthority upstreamauthority.UpstreamAuthority) {
	m.cat.SetUpstreamAuthority(upstreamAuthority)

	c := m.selfSignedConfig()
	manager, err := NewManager(context.Background(), c)
	require.NoError(m.t, err)

	m.m = manager
}

func (m *managerTest) initAndActivateUpstreamSignedManager(ctx context.Context, upstreamAuthority upstreamauthority.UpstreamAuthority) {
	m.initUpstreamSignedManager(upstreamAuthority)

	require.NoError(m.t, m.m.PrepareJWTKey(ctx))
	m.m.ActivateJWTKey()
	require.NoError(m.t, m.m.PrepareX509CA(ctx))
	m.m.ActivateX509CA()
}

func (m *managerTest) selfSignedConfig() Config {
	return m.selfSignedConfigWithKeyTypes(keymanager.ECP256, keymanager.ECP256)
}

func (m *managerTest) selfSignedConfigWithKeyTypes(x509CAKeyType, jwtKeyType keymanager.KeyType) Config {
	credBuilder, err := credtemplate.NewBuilder(credtemplate.Config{
		TrustDomain:   testTrustDomain,
		X509CASubject: pkix.Name{CommonName: "SPIRE"},
		Clock:         m.clock,
		X509CATTL:     testCATTL,
	})
	require.NoError(m.t, err)

	credValidator, err := credvalidator.New(credvalidator.Config{
		TrustDomain: testTrustDomain,
		Clock:       m.clock,
	})
	require.NoError(m.t, err)

	return Config{
		CA:            m.ca,
		Catalog:       m.cat,
		TrustDomain:   testTrustDomain,
		X509CAKeyType: x509CAKeyType,
		JWTKeyType:    jwtKeyType,
		Dir:           m.dir,
		Metrics:       m.metrics,
		Log:           m.log,
		Clock:         m.clock,
		CredBuilder:   credBuilder,
		CredValidator: credValidator,
	}
}

func (m *managerTest) requireX509CAEqual(t *testing.T, expected, actual *ca.X509CA, msgAndArgs ...interface{}) {
	require.Equal(t, m.getX509CAInfo(expected), m.getX509CAInfo(actual), msgAndArgs...)
}

func (m *managerTest) requireJWTKeyEqual(t *testing.T, expected, actual *ca.JWTKey, msgAndArgs ...interface{}) {
	require.Equal(t, m.getJWTKeyInfo(expected), m.getJWTKeyInfo(actual), msgAndArgs...)
}

func (m *managerTest) getX509CAInfo(x509CA *ca.X509CA) x509CAInfo {
	if x509CA == nil {
		return x509CAInfo{}
	}
	return x509CAInfo{
		Signer:        m.getSignerInfo(x509CA.Signer),
		Certificate:   x509CA.Certificate,
		UpstreamChain: x509CA.UpstreamChain,
	}
}

func (m *managerTest) getJWTKeyInfo(jwtKey *ca.JWTKey) jwtKeyInfo {
	if jwtKey == nil {
		return jwtKeyInfo{}
	}
	return jwtKeyInfo{
		Signer:   m.getSignerInfo(jwtKey.Signer),
		Kid:      jwtKey.Kid,
		NotAfter: jwtKey.NotAfter,
	}
}

func (m *managerTest) getSignerInfo(signer crypto.Signer) signerInfo {
	ks, ok := signer.(interface{ ID() string })
	require.True(m.t, ok, "signer is not a Key Manager")

	publicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	require.NoError(m.t, err)
	return signerInfo{
		KeyID:     ks.ID(),
		PublicKey: publicKey,
	}
}

func (m *managerTest) requireBundleRootCAs(ctx context.Context, t *testing.T, rootCAs ...*x509.Certificate) {
	expected := &common.Bundle{}
	for _, rootCA := range rootCAs {
		expected.RootCas = append(expected.RootCas, &common.Certificate{
			DerBytes: rootCA.Raw,
		})
	}

	bundle := m.fetchBundle(ctx)
	spiretest.RequireProtoEqual(t, expected, &common.Bundle{
		RootCas: bundle.RootCas,
	})
}

func (m *managerTest) requireBundleJWTKeys(ctx context.Context, t *testing.T, jwtKeys ...*ca.JWTKey) {
	expected := &common.Bundle{}
	for _, jwtKey := range jwtKeys {
		publicKey, err := publicKeyFromJWTKey(jwtKey)
		require.NoError(m.t, err)
		expected.JwtSigningKeys = append(expected.JwtSigningKeys, publicKey)
	}

	bundle := m.fetchBundle(ctx)
	spiretest.RequireProtoEqual(t, expected, &common.Bundle{
		JwtSigningKeys: bundle.JwtSigningKeys,
	})
}

func (m *managerTest) createBundle(ctx context.Context) *common.Bundle {
	bundle, err := m.ds.CreateBundle(ctx, &common.Bundle{
		TrustDomainId: testTrustDomain.IDString(),
	})
	require.NoError(m.t, err)
	return bundle
}

func (m *managerTest) fetchBundle(ctx context.Context) *common.Bundle {
	return m.fetchBundleForTrustDomain(ctx, testTrustDomain)
}

func (m *managerTest) fetchBundleForTrustDomain(ctx context.Context, trustDomain spiffeid.TrustDomain) *common.Bundle {
	bundle, err := m.ds.FetchBundle(ctx, trustDomain.IDString())
	require.NoError(m.t, err)
	require.NotNil(m.t, bundle, "missing bundle for trust domain %q", trustDomain.IDString())
	return bundle
}

func (m *managerTest) currentX509CA() *ca.X509CA {
	// ensure that the "active" one matches the current before returning
	m.requireX509CAEqual(m.t, m.m.currentX509CA.x509CA, m.ca.X509CA(), "current X509CA is not active")
	return m.m.currentX509CA.x509CA
}

func (m *managerTest) currentX509CAStatus() journal.Status {
	return m.m.currentX509CA.status
}

func (m *managerTest) currentJWTKey() *ca.JWTKey {
	m.requireJWTKeyEqual(m.t, m.m.currentJWTKey.jwtKey, m.ca.JWTKey(), "current JWTKey is not active")
	return m.m.currentJWTKey.jwtKey
}

func (m *managerTest) currentJWTKeyStatus() journal.Status {
	return m.m.currentJWTKey.status
}

func (m *managerTest) nextX509CA() *ca.X509CA {
	return m.m.nextX509CA.x509CA
}

func (m *managerTest) nextX509CAStatus() journal.Status {
	return m.m.nextX509CA.status
}

func (m *managerTest) nextJWTKey() *ca.JWTKey {
	return m.m.nextJWTKey.jwtKey
}

func (m *managerTest) nextJWTKeyStatus() journal.Status {
	return m.m.nextJWTKey.status
}

func (m *managerTest) setTimeAndPrune(t time.Time) {
	m.clock.Set(t)
	require.NoError(m.t, m.m.PruneBundle(context.Background()))
}

func (m *managerTest) addTimeAndPrune(d time.Duration) {
	m.clock.Add(d)
	require.NoError(m.t, m.m.PruneBundle(context.Background()))
}

func (m *managerTest) wipeJournal(t *testing.T) {
	require.NoError(t, os.Remove(filepath.Join(m.m.c.Dir, "journal.pem")))
}

func (m *managerTest) waitForBundleUpdatedNotification(ctx context.Context, ch <-chan *common.Bundle) {
	select {
	case <-ctx.Done():
		assert.FailNow(m.t, "timed out waiting for bundle update notification")
	case actual := <-ch:
		expected := m.fetchBundle(ctx)
		spiretest.RequireProtoEqual(m.t, expected, actual)
	}
}

func (m *managerTest) countLogEntries(level logrus.Level, message string) int {
	count := 0
	for _, e := range m.logHook.AllEntries() {
		if e.Message == message && level == e.Level {
			count++
		}
	}
	return count
}

func (m *managerTest) validateSelfSignedX509CA(bundle *x509.Certificate, signer crypto.Signer) {
	credValidator, err := credvalidator.New(credvalidator.Config{
		TrustDomain: testTrustDomain,
		Clock:       m.clock,
	})
	require.NoError(m.t, err)

	validator := ca.X509CAValidator{
		TrustDomain:   testTrustDomain,
		CredValidator: credValidator,
		Signer:        signer,
	}
	require.NoError(m.t, validator.ValidateSelfSignedX509CA(bundle))
}

type fakeCA struct {
	mu     sync.Mutex
	x509CA *ca.X509CA
	jwtKey *ca.JWTKey
}

func (s *fakeCA) X509CA() *ca.X509CA {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.x509CA
}

func (s *fakeCA) SetX509CA(x509CA *ca.X509CA) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.x509CA = x509CA
}

func (s *fakeCA) JWTKey() *ca.JWTKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jwtKey
}

func (s *fakeCA) SetJWTKey(jwtKey *ca.JWTKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwtKey = jwtKey
}
