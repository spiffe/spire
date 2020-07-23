package ca_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeupstreamauthority"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

var (
	csr, _ = ca.GenerateServerCACSR(testkey.MustEC256(), "example.org", pkix.Name{CommonName: "FAKE CA"})
)

func TestUpstreamClientMintX509CA_HandlesBundleUpdates(t *testing.T) {
	client, updater, ua, uaDone := setUpUpstreamClientTest(t, fakeupstreamauthority.Config{
		TrustDomain:     "example.org",
		UseIntermediate: true,
	})
	defer client.Close()
	defer uaDone()

	x509CA, err := client.MintX509CA(context.Background(), csr, 0)
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
		name   string
		mutate func(*upstreamauthority.MintX509CAResponse)
		err    string
	}{
		{
			name: "missing X.509 CA chain",
			mutate: func(resp *upstreamauthority.MintX509CAResponse) {
				resp.X509CaChain = nil
			},
			err: "upstream authority returned empty X.509 CA chain",
		},
		{
			name: "malformed X.509 CA chain",
			mutate: func(resp *upstreamauthority.MintX509CAResponse) {
				resp.X509CaChain = [][]byte{{0x00}}
			},
			err: "malformed X.509 CA chain:",
		},
		{
			name: "missing X.509 roots",
			mutate: func(resp *upstreamauthority.MintX509CAResponse) {
				resp.UpstreamX509Roots = nil
			},
			err: "upstream authority returned no upstream X.509 roots",
		},
		{
			name: "malformed X.509 roots",
			mutate: func(resp *upstreamauthority.MintX509CAResponse) {
				resp.UpstreamX509Roots = [][]byte{{0x00}}
			},
			err: "malformed upstream X.509 roots:",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			client, _, _, uaDone := setUpUpstreamClientTest(t, fakeupstreamauthority.Config{
				TrustDomain:              "example.org",
				MutateMintX509CAResponse: tt.mutate,
			})
			defer client.Close()
			defer uaDone()

			_, err := client.MintX509CA(context.Background(), csr, 0)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.err)
		})
	}
}

func TestUpstreamClientMintX509CA_LogsOnBadSubsequentResponses(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*upstreamauthority.MintX509CAResponse)
		err    string
	}{
		{
			name: "has X.509 CA chain",
			mutate: func(resp *upstreamauthority.MintX509CAResponse) {
				resp.X509CaChain = [][]byte{{0x00}}
			},
			err: "upstream authority returned an X.509 CA chain after the first response",
		},
		{
			name: "missing X.509 roots",
			mutate: func(resp *upstreamauthority.MintX509CAResponse) {
				resp.UpstreamX509Roots = nil
			},
			err: "upstream authority returned no upstream X.509 roots",
		},
		{
			name: "malformed X.509 roots",
			mutate: func(resp *upstreamauthority.MintX509CAResponse) {
				resp.UpstreamX509Roots = [][]byte{{0x00}}
			},
			err: "malformed upstream X.509 roots:",
		},
	} {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			var first bool
			client, updater, ua, uaDone := setUpUpstreamClientTest(t, fakeupstreamauthority.Config{
				TrustDomain: "example.org",
				MutateMintX509CAResponse: func(resp *upstreamauthority.MintX509CAResponse) {
					if !first {
						first = true
						return
					}
					tt.mutate(resp)
				},
			})
			defer client.Close()
			defer uaDone()

			x509CA, err := client.MintX509CA(context.Background(), csr, 0)
			require.NoError(t, err)
			require.NotNil(t, x509CA)

			// Rotating the upstream CA. This change won't be picked up because
			// we are mutating the response in the test hook to ensure the
			// bad response is ignored.
			ua.RotateX509CA()

			msg, err := updater.WaitForError(t)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.err)
			require.Equal(t, msg, "Failed to parse an X.509 root update from the upstream authority plugin. Please report this bug.")
		})
	}
}

func TestUpstreamClientPublishJWTKey_HandlesBundleUpdates(t *testing.T) {
	client, updater, ua, uaDone := setUpUpstreamClientTest(t, fakeupstreamauthority.Config{
		TrustDomain: "example.org",
	})
	defer client.Close()
	defer uaDone()

	key1 := &common.PublicKey{
		Kid: "KEY1",
	}
	key2 := &common.PublicKey{
		Kid: "KEY2",
	}

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
	client, _, _, uaDone := setUpUpstreamClientTest(t, fakeupstreamauthority.Config{
		TrustDomain:           "example.org",
		DisallowPublishJWTKey: true,
	})
	defer client.Close()
	defer uaDone()

	jwtKeys, err := client.PublishJWTKey(context.Background(), &common.PublicKey{Kid: "KEY"})
	spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "disallowed")
	require.Nil(t, jwtKeys)
}

func setUpUpstreamClientTest(t *testing.T, config fakeupstreamauthority.Config) (*ca.UpstreamClient, *fakeBundleUpdater, *fakeupstreamauthority.UpstreamAuthority, func()) {
	plugin, upstreamAuthority, done := fakeupstreamauthority.Load(t, config)
	updater := newFakeBundleUpdater()

	return ca.NewUpstreamClient(ca.UpstreamClientConfig{
		UpstreamAuthority: plugin,
		BundleUpdater:     updater,
	}), updater, upstreamAuthority, done
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
