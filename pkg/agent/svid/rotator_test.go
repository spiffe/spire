package svid

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakeagentkeymanager"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRotator(t *testing.T) {
	caCert, caKey := testca.CreateCACertificate(t, nil, nil)

	for _, tt := range []struct {
		name         string
		notAfter     time.Duration
		checkAfter   time.Duration
		shouldRotate bool
	}{
		{
			name:         "not expired at startup",
			notAfter:     time.Minute,
			shouldRotate: false,
		},
		{
			name:         "expired at startup",
			notAfter:     0,
			shouldRotate: true,
		},
		{
			name:         "expires after startup",
			notAfter:     2 * time.Minute,
			checkAfter:   2*time.Minute + time.Second,
			shouldRotate: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svidKM := keymanager.ForSVID(fakeagentkeymanager.New(t, ""))
			clk := clock.NewMock(t)
			log, _ := test.NewNullLogger()
			mockClient := &fakeClient{clk: clk, caCert: caCert, caKey: caKey}

			// Create the starting SVID
			svidKey, err := svidKM.GenerateKey(context.Background(), nil)
			require.NoError(t, err)
			svid := createTestSVID(t, svidKey, caCert, caKey, clk.Now(), clk.Now().Add(tt.notAfter))

			// Initialize the rotator
			rotator, _ := newRotator(&RotatorConfig{
				SVIDKeyManager: svidKM,
				Log:            log,
				Metrics:        telemetry.Blackhole{},
				TrustDomain:    spiffeid.RequireTrustDomainFromString("example.org"),
				BundleStream:   cache.NewBundleStream(observer.NewProperty([]*x509.Certificate(nil)).Observe()),
				Clk:            clk,
				SVID:           svid,
				SVIDKey:        svidKey,
			})
			rotator.client = mockClient

			// Hook the rotation loop so we can determine when the rotator
			// has finished a rotation evaluation (does not imply anything
			// was actually rotated, just that the rotator evaluated the
			// SVID expiration and attempted rotation if needed).
			rotationDone := make(chan struct{}, 1)
			rotator.SetRotationFinishedHook(func() {
				select {
				case rotationDone <- struct{}{}:
				default:
				}
			})

			// Subscribe to SVID changes and run the rotator
			stream := rotator.Subscribe()

			ctx, cancel := context.WithCancel(context.Background())
			errCh := make(chan error, 1)
			go func() {
				errCh <- rotator.Run(ctx)
			}()

			// Wait for the initial rotation check to finish
			select {
			case <-time.After(time.Minute):
				t.Fatal("timed out waiting for rotation check to finish")
			case <-rotationDone:
				clk.WaitForAfter(time.Minute, "timed out waiting for rotation loop to start waiting")
			}

			// Optionally advance the clock by the specified amount
			// and wait for another rotation check to finish.
			if tt.checkAfter != 0 {
				require.Greater(t, tt.checkAfter, DefaultRotatorInterval, "checkAfter should be larger than the default rotator interval")
				clk.Add(tt.checkAfter)
				select {
				case <-time.After(time.Minute):
					t.Fatal("timed out waiting for rotation check to finish after clock adjustment")
				case <-rotationDone:
					clk.WaitForAfter(time.Minute, "timed out waiting for rotation loop to start waiting after clock adjustment")
				}
			}

			// Shut down the rotator
			cancel()
			select {
			case <-time.After(time.Minute):
				t.Fatal("timed out waiting for the rotator to shut down")
			case err = <-errCh:
				require.True(t, errors.Is(err, context.Canceled), "expected %v, not %v", context.Canceled, err)
			}

			// If rotation was supposed to happen, wait for the SVID changes
			// on the state stream.
			if tt.shouldRotate {
				require.True(t, stream.HasNext(), "SVID stream should have changes")
				stream.Next()
			} else {
				require.False(t, stream.HasNext(), "SVID stream should not have changes")
			}

			// Assert that rotation happened and that the client was released
			// the appropriate number of times.
			state := stream.Value().(State)
			require.Len(t, state.SVID, 1)
			if tt.shouldRotate {
				assert.NotEqual(t, svid, state.SVID)
				assert.NotEqual(t, svidKey, state.Key)
				assert.Equal(t, 2, mockClient.releaseCount, "client might not released after rotation")
			} else {
				assert.Equal(t, svid, state.SVID)
				assert.Equal(t, svidKey, state.Key)
				assert.Equal(t, 1, mockClient.releaseCount)
			}
		})
	}
}

func TestRotationFails(t *testing.T) {
	caCert, caKey := testca.CreateCACertificate(t, nil, nil)

	expiredStatus := status.New(codes.PermissionDenied, "agent is not active")
	expiredStatus, err := expiredStatus.WithDetails(&types.PermissionDeniedDetails{
		Reason: types.PermissionDeniedDetails_AGENT_NOT_ACTIVE,
	})
	require.NoError(t, err)

	bannedStatus := status.New(codes.PermissionDenied, "agent is banned")
	bannedStatus, err = bannedStatus.WithDetails(&types.PermissionDeniedDetails{
		Reason: types.PermissionDeniedDetails_AGENT_BANNED,
	})
	require.NoError(t, err)

	for _, tt := range []struct {
		name       string
		err        error
		expectErr  string
		expiration time.Duration
	}{
		{
			name:       "svid is expired",
			expiration: -time.Second,
			err:        errors.New("oh no"),
			expectErr:  "current SVID has already expired and rotation failed: oh no",
		},
		{
			name:      "expired agent",
			err:       fmt.Errorf("client fails: %w", expiredStatus.Err()),
			expectErr: "client fails: rpc error: code = PermissionDenied desc = agent is not active",
		},
		{
			name:      "banned agent",
			err:       fmt.Errorf("client fails: %w", bannedStatus.Err()),
			expectErr: "client fails: rpc error: code = PermissionDenied desc = agent is banned",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svidKM := keymanager.ForSVID(fakeagentkeymanager.New(t, ""))
			clk := clock.NewMock(t)
			log, _ := test.NewNullLogger()
			mockClient := &fakeClient{
				clk:      clk,
				caCert:   caCert,
				caKey:    caKey,
				renewErr: tt.err,
			}

			// Create the starting SVID
			svidKey, err := svidKM.GenerateKey(context.Background(), nil)
			require.NoError(t, err)
			svid := createTestSVID(t, svidKey, caCert, caKey, clk.Now(), clk.Now().Add(tt.expiration))

			// Initialize the rotator
			rotator, _ := newRotator(&RotatorConfig{
				SVIDKeyManager: svidKM,
				Log:            log,
				Metrics:        telemetry.Blackhole{},
				TrustDomain:    spiffeid.RequireTrustDomainFromString("example.org"),
				BundleStream:   cache.NewBundleStream(observer.NewProperty([]*x509.Certificate(nil)).Observe()),
				Clk:            clk,
				SVID:           svid,
				SVIDKey:        svidKey,
			})
			rotator.client = mockClient

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			err = rotator.Run(ctx)
			spiretest.RequireErrorPrefix(t, err, tt.expectErr)
		})
	}
}

type fakeClient struct {
	clk          clock.Clock
	caCert       *x509.Certificate
	caKey        crypto.Signer
	releaseCount int
	renewErr     error
}

func (c *fakeClient) RenewSVID(ctx context.Context, csrBytes []byte) (*client.X509SVID, error) {
	if c.renewErr != nil {
		return nil, c.renewErr
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    c.clk.Now(),
		NotAfter:     c.clk.Now().Add(time.Hour),
	}

	svid, err := x509.CreateCertificate(rand.Reader, tmpl, c.caCert, csr.PublicKey, c.caKey)
	if err != nil {
		return nil, err
	}

	return &client.X509SVID{
		CertChain: svid,
		ExpiresAt: tmpl.NotAfter.Unix(),
	}, nil
}

func (c *fakeClient) Release() {
	c.releaseCount++
}

func createTestSVID(t *testing.T, svidKey crypto.Signer, ca *x509.Certificate, caKey crypto.Signer, notBefore time.Time, notAfter time.Time) []*x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		URIs:         []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/spire/agent/test"}},
	}
	svidBytes, err := x509.CreateCertificate(rand.Reader, tmpl, ca, svidKey.Public(), caKey)
	require.NoError(t, err)
	svid, err := x509.ParseCertificate(svidBytes)
	require.NoError(t, err)
	return []*x509.Certificate{svid}
}
