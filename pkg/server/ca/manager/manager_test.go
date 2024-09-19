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
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/credvalidator"
	"github.com/spiffe/spire/pkg/server/datastore"
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
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
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
	require.False(t, test.m.IsUpstreamAuthority())

	t.Run("no authority created", func(t *testing.T) {
		currentSlot := test.m.GetCurrentJWTKeySlot()

		slot := currentSlot.(*jwtKeySlot)

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
		slot := currentSlot.(*jwtKeySlot)
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
		slot := nextSlot.(*jwtKeySlot)

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
		slot := nextSlot.(*jwtKeySlot)
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

		slot := currentSlot.(*x509CASlot)
		require.Nil(t, slot.x509CA)
		require.Empty(t, slot.authorityID)
		require.Empty(t, slot.upstreamAuthorityID)
		require.Empty(t, slot.issuedAt)
		require.Empty(t, slot.publicKey)
		require.Empty(t, slot.notAfter)
	})

	t.Run("slot returned", func(t *testing.T) {
		expectIssuedAt := test.clock.Now()
		expectNotAfter := expectIssuedAt.Add(test.m.caTTL).UTC()

		require.NoError(t, test.m.PrepareX509CA(ctx))

		currentSlot := test.m.GetCurrentX509CASlot()
		slot := currentSlot.(*x509CASlot)
		require.NotNil(t, slot.x509CA)
		require.NotEmpty(t, slot.authorityID)
		require.Empty(t, slot.upstreamAuthorityID)
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
		slot := nextSlot.(*x509CASlot)

		require.Nil(t, slot.x509CA)
		require.Empty(t, slot.authorityID)
		require.Empty(t, slot.upstreamAuthorityID)
		require.Empty(t, slot.issuedAt)
		require.Empty(t, slot.publicKey)
		require.Empty(t, slot.notAfter)
	})

	t.Run("next returned", func(t *testing.T) {
		expectIssuedAt := test.clock.Now()
		expectNotAfter := expectIssuedAt.Add(test.m.caTTL).UTC()

		require.NoError(t, test.m.PrepareX509CA(ctx))

		nextSlot := test.m.GetNextX509CASlot()
		slot := nextSlot.(*x509CASlot)
		require.NotNil(t, slot.x509CA)
		require.NotEmpty(t, slot.authorityID)
		require.Empty(t, slot.upstreamAuthorityID)
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
	test.m.ActivateJWTKey(ctx)
	require.NoError(t, test.m.PrepareX509CA(ctx))
	test.m.ActivateX509CA(ctx)

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

func TestNotifyTaintedX509Authority(t *testing.T) {
	ctx := context.Background()
	test := setupTest(t)
	test.initSelfSignedManager()

	// Create a test CA
	ca := testca.New(t, testTrustDomain)
	cert := ca.X509Authorities()[0]
	bundle, err := test.ds.CreateBundle(ctx, &common.Bundle{
		TrustDomainId: testTrustDomain.IDString(),
		RootCas: []*common.Certificate{
			{
				DerBytes:   cert.Raw,
				TaintedKey: true,
			},
		},
	})
	require.NoError(t, err)

	t.Run("notify tainted authority", func(t *testing.T) {
		err = test.m.NotifyTaintedX509Authority(ctx, ca.GetSubjectKeyID())
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()

		expectedTaintedAuthorities := []*x509.Certificate{cert}
		select {
		case taintedAuthorities := <-test.ca.taintedAuthoritiesCh:
			require.Equal(t, expectedTaintedAuthorities, taintedAuthorities)
		case <-ctx.Done():
			assert.Fail(t, "no notification received")
		}
	})

	// Untaint authority
	bundle.RootCas[0].TaintedKey = false
	bundle, err = test.ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	t.Run("no tainted authority", func(t *testing.T) {
		err := test.m.NotifyTaintedX509Authority(ctx, ca.GetSubjectKeyID())

		expectedErr := fmt.Sprintf("no tainted root CA found with authority ID: %q", ca.GetSubjectKeyID())
		require.EqualError(t, err, expectedErr)
	})

	bundle.RootCas = append(bundle.RootCas, &common.Certificate{
		DerBytes:   []byte("foh"),
		TaintedKey: true,
	})
	_, err = test.ds.UpdateBundle(ctx, bundle, nil)
	require.NoError(t, err)

	t.Run("malformed root CA", func(t *testing.T) {
		err := test.m.NotifyTaintedX509Authority(ctx, ca.GetSubjectKeyID())
		require.EqualError(t, err, "failed to parse RootCA: x509: malformed certificate")
	})
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

	upstreamAuthority, fakeUA := test.newFakeUpstreamAuthority(t, fakeupstreamauthority.Config{
		TrustDomain:           testTrustDomain,
		DisallowPublishJWTKey: true,
	})

	test.initAndActivateUpstreamSignedManager(ctx, upstreamAuthority)
	require.True(t, test.m.IsUpstreamAuthority())

	// X509 CA should be set up to be an intermediate but only have itself
	// in the chain since it was signed directly by the upstream root.
	x509CA := test.currentX509CA()
	assert.NotNil(t, x509CA.Signer)
	if assert.NotNil(t, x509CA.Certificate) {
		assert.Equal(t, fakeUA.X509Root().Certificate.Subject, x509CA.Certificate.Issuer)
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

	// Taint first root
	err := fakeUA.TaintAuthority(0)
	require.NoError(t, err)

	// Get the roots again and verify that the first X.509 authority is tainted
	x509Roots := fakeUA.X509Roots()
	require.True(t, x509Roots[0].Tainted)

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	select {
	case taintedAuthorities := <-test.m.taintedUpstreamAuthoritiesCh:
		expectedTaintedAuthorities := []*x509.Certificate{x509Roots[0].Certificate}
		require.Equal(t, expectedTaintedAuthorities, taintedAuthorities)
	case <-ctx.Done():
		assert.Fail(t, "no notification received")
	}
}

func TestUpstreamProcessTaintedAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	test := setupTest(t)

	upstreamAuthority, fakeUA := fakeupstreamauthority.Load(t, fakeupstreamauthority.Config{
		TrustDomain:           testTrustDomain,
		DisallowPublishJWTKey: true,
	})

	test.initAndActivateUpstreamSignedManager(ctx, upstreamAuthority)
	require.True(t, test.m.IsUpstreamAuthority())

	// Prepared must be tainted too
	err := test.m.PrepareX509CA(ctx)
	require.NoError(t, err)

	go test.m.ProcessBundleUpdates(ctx)

	// Taint first root
	err = fakeUA.TaintAuthority(0)
	require.NoError(t, err)

	// Get the roots again and verify that the first X.509 authority is tainted
	x509Roots := fakeUA.X509Roots()
	require.True(t, x509Roots[0].Tainted)

	expectedTaintedAuthorities := []*x509.Certificate{x509Roots[0].Certificate}
	select {
	case received := <-test.ca.taintedAuthoritiesCh:
		require.Equal(t, expectedTaintedAuthorities, received)
	case <-ctx.Done():
		assert.Fail(t, "deadline reached")
	}

	bundle := test.fetchBundle(ctx)
	expectRootCas := x509certificate.RequireToCommonProtos(x509Roots)
	spiretest.AssertProtoListEqual(t, expectRootCas, bundle.RootCas)
}

func TestUpstreamProcessTaintedAuthorityBackoff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	test := setupTest(t)

	upstreamAuthority, fakeUA := fakeupstreamauthority.Load(t, fakeupstreamauthority.Config{
		TrustDomain:           testTrustDomain,
		DisallowPublishJWTKey: true,
	})

	test.initAndActivateUpstreamSignedManager(ctx, upstreamAuthority)
	require.True(t, test.m.IsUpstreamAuthority())

	test.m.triggerBackOffCh = make(chan error, 1)

	// Prepared must be tainted too
	go test.m.ProcessBundleUpdates(ctx)

	// Set an invalid key type to make prepare fails
	test.m.c.X509CAKeyType = 123
	err := test.m.PrepareX509CA(ctx)
	require.Error(t, err)

	// Taint first root
	err = fakeUA.TaintAuthority(0)
	require.NoError(t, err)

	// Get the roots again and verify that the first X.509 authority is tainted
	x509Roots := fakeUA.X509Roots()
	require.True(t, x509Roots[0].Tainted)

	expectBackoffErr := func(t *testing.T) {
		select {
		case receivedErr := <-test.m.triggerBackOffCh:
			require.EqualError(t, receivedErr, "failed to prepare x509 authority: rpc error: code = Internal desc = keymanager(fake): facade does not support key type \"UNKNOWN(123)\"")
		case <-ctx.Done():
			assert.Fail(t, "deadline reached")
		}
	}

	// Must fail due to the invalid key type
	expectBackoffErr(t)

	// Try again; expect to fail
	test.clock.Add(6 * time.Second)
	expectBackoffErr(t)

	// Restore to a valid key type, and advance time again
	test.m.c.X509CAKeyType = keymanager.ECP256
	test.clock.Add(10 * time.Second)

	expectedTaintedAuthorities := []*x509.Certificate{x509Roots[0].Certificate}
	select {
	case received := <-test.ca.taintedAuthoritiesCh:
		require.Equal(t, expectedTaintedAuthorities, received)
	case <-ctx.Done():
		assert.Fail(t, "deadline reached")
	}

	bundle := test.fetchBundle(ctx)
	expectRootCas := x509certificate.RequireToCommonProtos(x509Roots)
	spiretest.AssertProtoListEqual(t, expectRootCas, bundle.RootCas)
}

func TestGetCurrentX509CASlotUpstreamSigned(t *testing.T) {
	ctx := context.Background()

	test := setupTest(t)

	upstreamAuthority, ua := test.newFakeUpstreamAuthority(t, fakeupstreamauthority.Config{
		TrustDomain:           testTrustDomain,
		DisallowPublishJWTKey: true,
	})

	test.initAndActivateUpstreamSignedManager(ctx, upstreamAuthority)

	expectIssuedAt := test.clock.Now()
	expectNotAfter := expectIssuedAt.Add(test.m.caTTL).UTC()
	expectUpstreamAuthorityID := x509util.SubjectKeyIDToString(ua.X509Root().Certificate.SubjectKeyId)

	require.NoError(t, test.m.PrepareX509CA(ctx))

	currentSlot := test.m.GetCurrentX509CASlot()
	slot := currentSlot.(*x509CASlot)
	require.NotNil(t, slot.x509CA)
	require.NotEmpty(t, slot.authorityID)
	require.Equal(t, expectUpstreamAuthorityID, slot.upstreamAuthorityID)
	require.NotNil(t, slot.publicKey)
	require.Equal(t, expectIssuedAt, slot.issuedAt)
	require.Equal(t, expectNotAfter, slot.notAfter)
}

func TestGetNextX509CASlotUpstreamSigned(t *testing.T) {
	ctx := context.Background()

	test := setupTest(t)
	upstreamAuthority, ua := test.newFakeUpstreamAuthority(t, fakeupstreamauthority.Config{
		TrustDomain:           testTrustDomain,
		DisallowPublishJWTKey: true,
	})

	test.initAndActivateUpstreamSignedManager(ctx, upstreamAuthority)

	expectIssuedAt := test.clock.Now()
	expectNotAfter := expectIssuedAt.Add(test.m.caTTL).UTC()
	expectUpstreamAuthorityID := x509util.SubjectKeyIDToString(ua.X509Root().Certificate.SubjectKeyId)

	require.NoError(t, test.m.PrepareX509CA(ctx))

	nextSlot := test.m.GetNextX509CASlot()
	slot := nextSlot.(*x509CASlot)
	require.NotNil(t, slot.x509CA)
	require.NotEmpty(t, slot.authorityID)
	require.Equal(t, expectUpstreamAuthorityID, slot.upstreamAuthorityID)
	require.NotNil(t, slot.publicKey)
	require.Equal(t, expectIssuedAt, slot.issuedAt)
	require.Equal(t, expectNotAfter, slot.notAfter)
}

func TestUpstreamSignedProducesInvalidChain(t *testing.T) {
	ctx := context.Background()
	test := setupTest(t)
	upstreamAuthority, _ := test.newFakeUpstreamAuthority(t, fakeupstreamauthority.Config{
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
	upstreamAuthority, fakeUA := test.newFakeUpstreamAuthority(t, fakeupstreamauthority.Config{
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

	upstreamAuthority, ua := test.newFakeUpstreamAuthority(t, fakeupstreamauthority.Config{
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
	go test.m.ProcessBundleUpdates(ctx)

	// after initialization, we should have a current X509CA but no next.
	first := test.currentX509CA()
	require.Equal(t, journal.Status_ACTIVE, test.currentX509CAStatus())
	assert.Nil(t, test.nextX509CA(), "second X509CA should not be prepared yet")
	require.Equal(t, journal.Status_UNKNOWN, test.nextX509CAStatus())
	test.requireIntermediateRootCA(ctx, t, first.Certificate)

	// Prepare new X509CA. the current X509CA should stay
	// the same but the next X509CA should have been prepared and added to
	// the trust bundle.
	require.NoError(t, test.m.PrepareX509CA(ctx))
	test.requireX509CAEqual(t, first, test.currentX509CA())
	require.Equal(t, journal.Status_ACTIVE, test.currentX509CAStatus())

	second := test.nextX509CA()
	assert.NotNil(t, second, "second X509CA should have been prepared")
	require.Equal(t, journal.Status_PREPARED, test.nextX509CAStatus())
	test.requireIntermediateRootCA(ctx, t, first.Certificate, second.Certificate)

	// we should now have a bundle update notification due to the preparation
	test.waitForBundleUpdatedNotification(ctx, notifyCh)

	// Rotate "next" should become "current" and
	// "next" should be reset.
	test.m.RotateX509CA(ctx)
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
	test.requireIntermediateRootCA(ctx, t, first.Certificate, second.Certificate, third.Certificate)

	// we should now have another bundle update notification due to the preparation
	test.waitForBundleUpdatedNotification(ctx, notifyCh)

	// Rotate again, "next" should become "current" and
	// "next" should be reset.
	test.m.RotateX509CA(ctx)
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
	test.m.RotateX509CA(ctx)

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
	go test.m.ProcessBundleUpdates(ctx)

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
	test.m.RotateJWTKey(ctx)
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
	test.m.RotateJWTKey(ctx)
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
	test.requireIntermediateRootCA(ctx, t, firstX509CA.Certificate, secondX509CA.Certificate)
	test.requireBundleJWTKeys(ctx, t, firstJWTKey, secondJWTKey)

	// kick off a goroutine to service bundle update notifications. This is
	// typically handled by Run() but using it would complicate the test.
	test.m.dropBundleUpdated() // drop bundle update message produce by initialization
	go test.m.ProcessBundleUpdates(ctx)

	// advance just past the expiration time of the first and prune. nothing
	// should change.
	test.setTimeAndPrune(firstExpiresTime.Add(time.Minute))
	test.requireIntermediateRootCA(ctx, t, firstX509CA.Certificate, secondX509CA.Certificate)
	test.requireBundleJWTKeys(ctx, t, firstJWTKey, secondJWTKey)

	// advance beyond the safety threshold of the first, prune, and assert that
	// the first has been pruned
	test.addTimeAndPrune(safetyThresholdBundle)
	test.requireIntermediateRootCA(ctx, t, secondX509CA.Certificate)
	test.requireBundleJWTKeys(ctx, t, secondJWTKey)

	// we should now have a bundle update notification due to the pruning
	test.waitForBundleUpdatedNotification(ctx, notifyCh)

	// advance beyond the second expiration time, prune, and assert nothing
	// changes because we can't prune out the whole bundle.
	test.clock.Set(secondExpiresTime.Add(time.Minute + safetyThresholdBundle))
	require.EqualError(t, test.m.PruneBundle(context.Background()), "unable to prune bundle: rpc error: code = Unknown desc = prune failed: would prune all certificates")
	test.requireIntermediateRootCA(ctx, t, secondX509CA.Certificate)
	test.requireBundleJWTKeys(ctx, t, secondJWTKey)
}

func TestPruneCAJournals(t *testing.T) {
	test := setupTest(t)
	test.initSelfSignedManager()

	type testJournal struct {
		Journal
		shouldBePruned bool
	}

	timeNow := test.clock.Now()
	now := timeNow.Unix()
	tomorrow := timeNow.Add(time.Hour * 24).Unix()
	beforeThreshold := timeNow.Add(-safetyThresholdCAJournals).Add(-time.Minute).Unix()

	jc := &journalConfig{
		cat: test.cat,
		log: test.log,
	}
	testCases := []struct {
		name         string
		entries      *journal.Entries
		testJournals []*testJournal
	}{
		{
			name: "no journals with CAs expired before the threshold - no journals to be pruned",
			testJournals: []*testJournal{
				{
					Journal: Journal{
						config: jc,
						entries: &journal.Entries{
							X509CAs: []*journal.X509CAEntry{{NotAfter: now}, {NotAfter: tomorrow}},
							JwtKeys: []*journal.JWTKeyEntry{{NotAfter: now}, {NotAfter: tomorrow}},
						},
					},
				},
				{
					Journal: Journal{
						config: jc,
						entries: &journal.Entries{
							X509CAs: []*journal.X509CAEntry{{NotAfter: now}, {NotAfter: tomorrow}},
							JwtKeys: []*journal.JWTKeyEntry{{NotAfter: now}, {NotAfter: tomorrow}},
						},
					},
				},
			},
		},
		{
			name: "some journals with CAs expired before the threshold, but not all - no journals to be pruned",
			testJournals: []*testJournal{
				{
					Journal: Journal{
						config: jc,
						entries: &journal.Entries{
							X509CAs: []*journal.X509CAEntry{{NotAfter: tomorrow}, {NotAfter: beforeThreshold}},
							JwtKeys: []*journal.JWTKeyEntry{{NotAfter: beforeThreshold}, {NotAfter: tomorrow}},
						},
					},
				},
				{
					Journal: Journal{
						config: jc,
						entries: &journal.Entries{
							X509CAs: []*journal.X509CAEntry{{NotAfter: tomorrow}, {NotAfter: beforeThreshold}},
							JwtKeys: []*journal.JWTKeyEntry{{NotAfter: beforeThreshold}, {NotAfter: tomorrow}},
						},
					},
				},
			},
		},
		{
			name: "all CAs expired before the threshold in a journal - one journal to be pruned",
			testJournals: []*testJournal{
				{
					shouldBePruned: true,
					Journal: Journal{
						config: jc,
						entries: &journal.Entries{
							X509CAs: []*journal.X509CAEntry{{NotAfter: beforeThreshold}, {NotAfter: beforeThreshold}},
							JwtKeys: []*journal.JWTKeyEntry{{NotAfter: beforeThreshold}, {NotAfter: beforeThreshold}},
						},
					},
				},
				{
					Journal: Journal{
						config: jc,
						entries: &journal.Entries{
							X509CAs: []*journal.X509CAEntry{{NotAfter: tomorrow}, {NotAfter: beforeThreshold}},
							JwtKeys: []*journal.JWTKeyEntry{{NotAfter: beforeThreshold}, {NotAfter: tomorrow}},
						},
					},
				},
			},
		},
	}

	var expectedCAJournals []*datastore.CAJournal
	for _, testCase := range testCases {
		testCase := testCase
		expectedCAJournals = []*datastore.CAJournal{}
		t.Run(testCase.name, func(t *testing.T) {
			// Have a fresh data store in each test case
			test.ds = fakedatastore.New(t)
			test.m.c.Catalog.(*fakeservercatalog.Catalog).SetDataStore(test.ds)

			for _, j := range testCase.testJournals {
				entriesBytes, err := proto.Marshal(j.entries)
				require.NoError(t, err)
				caJournal, err := test.ds.SetCAJournal(ctx, &datastore.CAJournal{
					ActiveX509AuthorityID: "",
					Data:                  entriesBytes,
				})
				require.NoError(t, err)

				if !j.shouldBePruned {
					expectedCAJournals = append(expectedCAJournals, caJournal)
				}
			}

			require.NoError(t, test.m.PruneCAJournals(ctx))
			caJournals, err := test.ds.ListCAJournalsForTesting(ctx)
			require.NoError(t, err)
			require.ElementsMatch(t, expectedCAJournals, caJournals)
		})
	}
}

func TestRunNotifiesBundleLoaded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	test := setupTest(t)
	test.initAndActivateSelfSignedManager(ctx)

	var actual *common.Bundle
	test.setNotifier(fakenotifier.New(t, fakenotifier.Config{
		OnNotifyAndAdviseBundleLoaded: func(bundle *common.Bundle) error {
			actual = bundle
			return nil
		},
	}))

	err := test.m.NotifyBundleLoaded(ctx)
	require.NoError(t, err)

	// make sure the event contained the bundle
	expected := test.fetchBundle(ctx)
	spiretest.RequireProtoEqual(t, expected, actual)
}

func TestRunFailsIfNotifierFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	test := setupTest(t)
	test.initAndActivateSelfSignedManager(ctx)
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

func TestActivationThresholdCap(t *testing.T) {
	issuedAt := time.Now()
	notAfter := issuedAt.Add(365 * 24 * time.Hour)

	// Expect the activation threshold to get capped since 1/6 of the lifetime
	// exceeds the seven day cap.
	threshold := keyActivationThreshold(issuedAt, notAfter)
	require.Equal(t, sevenDays, notAfter.Sub(threshold))
}

func TestAlternateKeyTypes(t *testing.T) {
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
		upstreamAuthority bool
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
			upstreamAuthority: true,
			x509CAKeyType:     keymanager.RSA2048,
			jwtKeyType:        keymanager.RSA2048,
			checkX509CA:       expectRSA2048,
			checkJWTKey:       expectRSA2048,
		},
		{
			name:              "upstream-signed with RSA 4096",
			upstreamAuthority: true,
			x509CAKeyType:     keymanager.RSA4096,
			jwtKeyType:        keymanager.RSA4096,
			checkX509CA:       expectRSA4096,
			checkJWTKey:       expectRSA4096,
		},
		{
			name:              "upstream-signed with EC P256",
			upstreamAuthority: true,
			x509CAKeyType:     keymanager.ECP256,
			jwtKeyType:        keymanager.ECP256,
			checkX509CA:       expectEC256,
			checkJWTKey:       expectEC256,
		},
		{
			name:              "upstream-signed with EC P384",
			upstreamAuthority: true,
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
			if testCase.upstreamAuthority {
				upstreamAuthority, _ := test.newFakeUpstreamAuthority(t, fakeupstreamauthority.Config{
					TrustDomain: testTrustDomain,
				})
				test.cat.SetUpstreamAuthority(upstreamAuthority)
			}

			manager, err := NewManager(ctx, c)
			require.NoError(t, err)
			test.m = manager

			// Prepare and activate a bundle
			require.NoError(t, test.m.PrepareJWTKey(ctx))
			test.m.ActivateJWTKey(ctx)
			require.NoError(t, test.m.PrepareX509CA(ctx))
			test.m.activateX509CA(ctx)

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
	ca := &fakeCA{
		taintedAuthoritiesCh: make(chan []*x509.Certificate, 1),
	}

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

func (m *managerTest) newFakeUpstreamAuthority(t *testing.T, config fakeupstreamauthority.Config) (upstreamauthority.UpstreamAuthority, *fakeupstreamauthority.UpstreamAuthority) {
	config.Clock = m.clock
	return fakeupstreamauthority.Load(t, config)
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
	manager.ActivateJWTKey(ctx)
	require.NoError(m.t, manager.PrepareX509CA(ctx))
	manager.ActivateX509CA(ctx)

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
	m.m.ActivateJWTKey(ctx)
	require.NoError(m.t, m.m.PrepareX509CA(ctx))
	m.m.ActivateX509CA(ctx)
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
		Metrics:       m.metrics,
		Log:           m.log,
		Clock:         m.clock,
		CredBuilder:   credBuilder,
		CredValidator: credValidator,
	}
}

func (m *managerTest) requireX509CAEqual(t *testing.T, expected, actual *ca.X509CA, msgAndArgs ...any) {
	require.Equal(t, m.getX509CAInfo(expected), m.getX509CAInfo(actual), msgAndArgs...)
}

func (m *managerTest) requireJWTKeyEqual(t *testing.T, expected, actual *ca.JWTKey, msgAndArgs ...any) {
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

func (m *managerTest) requireIntermediateRootCA(ctx context.Context, t *testing.T, rootCAs ...*x509.Certificate) {
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

func (m *managerTest) requireBundleRootCAs(ctx context.Context, t *testing.T, rootCAs ...*x509certificate.X509Authority) {
	expected := &common.Bundle{}
	for _, rootCA := range rootCAs {
		expected.RootCas = append(expected.RootCas, &common.Certificate{
			DerBytes:   rootCA.Certificate.Raw,
			TaintedKey: rootCA.Tainted,
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
	// Have a clean datastore.
	m.ds = fakedatastore.New(t)
	m.cat.SetDataStore(m.ds)
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

	taintedAuthoritiesCh chan []*x509.Certificate
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

func (s *fakeCA) NotifyTaintedX509Authorities(taintedAuthorities []*x509.Certificate) {
	s.taintedAuthoritiesCh <- taintedAuthorities
}
