package ca_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeupstreamauthority"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

var (
	csr, _      = ca.GenerateServerCACSR(testkey.MustEC256(), spiffeid.RequireTrustDomainFromString("example.org"), pkix.Name{CommonName: "FAKE CA"})
	trustDomain = spiffeid.RequireTrustDomainFromString("example.org")
)

func TestUpstreamClientMintX509CA_HandlesBundleUpdates(t *testing.T) {
	client, updater, ua := setUpUpstreamClientTest(t, fakeupstreamauthority.Config{
		TrustDomain:     trustDomain,
		UseIntermediate: true,
	})

	x509CA, err := client.MintX509CA(context.Background(), csr, 0, func(_, _ []*x509.Certificate) error {
		return nil
	})
	require.NoError(t, err)
	require.Len(t, x509CA, 2)

	// Assert that the initial bundle update happened.
	require.Equal(t, ua.X509Roots(), updater.WaitForAppendedX509Roots(t))

	// Trigger an update to the upstream bundle by rotating the root
	// certificate and wait for the bundle updater to receive the update.
	ua.RotateX509CA()
	require.Equal(t, ua.X509Roots(), updater.WaitForAppendedX509Roots(t))
}

func TestUpstreamClientMintX509CA_FailsOnBadFirstResponse(t *testing.T) {
	for _, tt := range []struct {
		name       string
		mutate     func(*upstreamauthorityv1.MintX509CAResponse)
		validator  func(_, _ []*x509.Certificate) error
		expectCode codes.Code
		expectMsg  string
	}{
		{
			name: "missing X.509 CA chain",
			mutate: func(resp *upstreamauthorityv1.MintX509CAResponse) {
				resp.X509CaChain = nil
			},
			expectCode: codes.Internal,
			expectMsg:  "plugin response missing X.509 CA chain",
		},
		{
			name: "malformed X.509 CA chain",
			mutate: func(resp *upstreamauthorityv1.MintX509CAResponse) {
				resp.X509CaChain = []*plugintypes.X509Certificate{{Asn1: []byte{0x00}}}
			},
			expectCode: codes.Internal,
			expectMsg:  "plugin response has malformed X.509 CA chain:",
		},
		{
			name: "missing X.509 roots",
			mutate: func(resp *upstreamauthorityv1.MintX509CAResponse) {
				resp.UpstreamX509Roots = nil
			},
			expectCode: codes.Internal,
			expectMsg:  "plugin response missing upstream X.509 roots",
		},
		{
			name: "malformed X.509 roots",
			mutate: func(resp *upstreamauthorityv1.MintX509CAResponse) {
				resp.UpstreamX509Roots = []*plugintypes.X509Certificate{{Asn1: []byte{0x00}}}
			},
			expectCode: codes.Internal,
			expectMsg:  "plugin response has malformed upstream X.509 roots:",
		},
		{
			name: "validation fails",
			validator: func(_, _ []*x509.Certificate) error {
				return errors.New("oh no")
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "X509 CA minted by upstream authority is invalid: oh no",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			client, _, _ := setUpUpstreamClientTest(t, fakeupstreamauthority.Config{
				TrustDomain:              trustDomain,
				MutateMintX509CAResponse: tt.mutate,
			})

			validator := func(_, _ []*x509.Certificate) error {
				return nil
			}
			if tt.validator != nil {
				validator = tt.validator
			}

			_, err := client.MintX509CA(context.Background(), csr, 0, validator)
			spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
		})
	}
}

func TestUpstreamClientPublishJWTKey_HandlesBundleUpdates(t *testing.T) {
	client, updater, ua := setUpUpstreamClientTest(t, fakeupstreamauthority.Config{
		TrustDomain: trustDomain,
	})

	key1 := makePublicKey(t, "KEY1")
	key2 := makePublicKey(t, "KEY2")

	jwtKeys, err := client.PublishJWTKey(context.Background(), key1)
	require.NoError(t, err)
	spiretest.RequireProtoListEqual(t, jwtKeys, ua.JWTKeys())

	// Assert that the initial bundle update happened.
	spiretest.RequireProtoListEqual(t, []*common.PublicKey{key1}, updater.WaitForAppendedJWTKeys(t))

	// Now trigger an update to the bundle by appending another key and wait
	// for the bundle to receive the update.
	ua.AppendJWTKey(key2)
	spiretest.RequireProtoListEqual(t, []*common.PublicKey{key1, key2}, updater.WaitForAppendedJWTKeys(t))
}

func TestUpstreamClientPublishJWTKey_NotImplemented(t *testing.T) {
	client, _, _ := setUpUpstreamClientTest(t, fakeupstreamauthority.Config{
		TrustDomain:           trustDomain,
		DisallowPublishJWTKey: true,
	})

	jwtKeys, err := client.PublishJWTKey(context.Background(), makePublicKey(t, "KEY"))
	spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "upstreamauthority(fake): disallowed")
	require.Nil(t, jwtKeys)
}

func setUpUpstreamClientTest(t *testing.T, config fakeupstreamauthority.Config) (*ca.UpstreamClient, *fakeBundleUpdater, *fakeupstreamauthority.UpstreamAuthority) {
	plugin, upstreamAuthority := fakeupstreamauthority.Load(t, config)
	updater := newFakeBundleUpdater()

	client := ca.NewUpstreamClient(ca.UpstreamClientConfig{
		UpstreamAuthority: plugin,
		BundleUpdater:     updater,
	})
	t.Cleanup(func() {
		assert.NoError(t, client.Close())
	})

	return client, updater, upstreamAuthority
}

type bundleUpdateErr struct {
	err error
	msg string
}

type fakeBundleUpdater struct {
	x509RootsCh chan []*x509.Certificate
	jwtKeysCh   chan []*common.PublicKey
	errorCh     chan bundleUpdateErr
}

func newFakeBundleUpdater() *fakeBundleUpdater {
	return &fakeBundleUpdater{
		x509RootsCh: make(chan []*x509.Certificate, 1),
		jwtKeysCh:   make(chan []*common.PublicKey, 1),
		errorCh:     make(chan bundleUpdateErr, 1),
	}
}

func (u *fakeBundleUpdater) AppendX509Roots(ctx context.Context, x509Roots []*x509.Certificate) error {
	select {
	case u.x509RootsCh <- x509Roots:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (u *fakeBundleUpdater) WaitForAppendedX509Roots(t *testing.T) []*x509.Certificate {
	select {
	case <-time.After(time.Minute):
		require.FailNow(t, "timed out waiting for X.509 roots to be appended")
		return nil // unreachable
	case x509Roots := <-u.x509RootsCh:
		return x509Roots
	}
}

func (u *fakeBundleUpdater) AppendJWTKeys(ctx context.Context, jwtKeys []*common.PublicKey) ([]*common.PublicKey, error) {
	select {
	case u.jwtKeysCh <- jwtKeys:
		return jwtKeys, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (u *fakeBundleUpdater) WaitForAppendedJWTKeys(t *testing.T) []*common.PublicKey {
	select {
	case <-time.After(time.Minute):
		require.FailNow(t, "timed out waiting for JWT keys to be appended")
		return nil // unreachable
	case jwtKeys := <-u.jwtKeysCh:
		return jwtKeys
	}
}

func (u *fakeBundleUpdater) LogError(err error, msg string) {
	e := bundleUpdateErr{
		err: err,
		msg: msg,
	}
	select {
	case u.errorCh <- e:
	default:
	}
}

func (u *fakeBundleUpdater) WaitForError(t *testing.T) (msg string, err error) {
	select {
	case <-time.After(time.Minute):
		require.FailNow(t, "timed out waiting for error to be logged")
		return "", nil // unreachable
	case e := <-u.errorCh:
		return e.msg, e.err
	}
}

func makePublicKey(t *testing.T, kid string) *common.PublicKey {
	key := testkey.NewEC256(t)
	pkixBytes, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	return &common.PublicKey{
		Kid:       kid,
		PkixBytes: pkixBytes,
	}
}
