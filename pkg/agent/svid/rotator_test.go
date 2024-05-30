package svid

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakeagentkeymanager"
	"github.com/spiffe/spire/test/fakes/fakeagentnodeattestor"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

var (
	trustDomain    = spiffeid.RequireTrustDomainFromString("example.org")
	badTrustDomain = spiffeid.RequireTrustDomainFromString("badexample.org")
	bundleError    = "bundle not found"
	testTimeout    = time.Minute
)

func TestRotator(t *testing.T) {
	caCert, caKey := testca.CreateCACertificate(t, nil, nil)
	serverCert, serverKey := testca.CreateX509Certificate(t, caCert, caKey, testca.WithID(idutil.RequireServerID(trustDomain)))

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{serverCert.Raw},
				PrivateKey:  serverKey,
			},
		},
		MinVersion: tls.VersionTLS12,
	}

	for _, tt := range []struct {
		name          string
		notAfter      time.Duration
		shouldRotate  bool
		reattest      bool
		forceRotation bool
	}{
		{
			name:         "not expired at startup",
			notAfter:     time.Minute,
			shouldRotate: false,
		},
		{
			name:         "renew expired at startup",
			notAfter:     0,
			shouldRotate: true,
		},
		{
			name:         "renew expires after startup",
			notAfter:     2 * time.Minute,
			shouldRotate: true,
		},
		{
			name:         "reattest expired at startup",
			notAfter:     0,
			shouldRotate: true,
			reattest:     true,
		},
		{
			name:         "reattest expires after startup",
			notAfter:     2 * time.Minute,
			shouldRotate: true,
			reattest:     true,
		},
		{
			name:          "reattest when requested",
			notAfter:      time.Minute,
			shouldRotate:  false,
			reattest:      true,
			forceRotation: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svidKM := keymanager.ForSVID(fakeagentkeymanager.New(t, ""))
			clk := clock.NewMock(t)
			log, hook := test.NewNullLogger()
			mockClient := &fakeClient{
				clk:    clk,
				caCert: caCert,
				caKey:  caKey,
			}

			// Create the bundle
			bundle := make(map[spiffeid.TrustDomain]*spiffebundle.Bundle)
			bundle[trustDomain] = spiffebundle.FromX509Authorities(trustDomain, []*x509.Certificate{caCert})

			// Create the starting SVID
			svidKey, err := svidKM.GenerateKey(context.Background(), nil)
			require.NoError(t, err)
			svid, err := createTestSVID(svidKey.Public(), caCert, caKey, clk.Now(), clk.Now().Add(tt.notAfter))
			require.NoError(t, err)

			// Advance the clock by one second so SVID will always be expired
			// at startup for the "expired at startup" tests
			clk.Add(time.Second)

			// Create the attestor
			attestor := fakeagentnodeattestor.New(t, fakeagentnodeattestor.Config{})

			// Create the server
			mockAgentService := &fakeAgentService{
				clk:     clk,
				svidKM:  svidKM,
				svidKey: svidKey,
				caCert:  caCert,
				caKey:   caKey,
			}
			listener := createTestListener(t, mockAgentService, tlsConfig)

			// Initialize the rotator
			rotator, _ := newRotator(&RotatorConfig{
				SVIDKeyManager:   svidKM,
				Log:              log,
				Metrics:          telemetry.Blackhole{},
				TrustDomain:      trustDomain,
				BundleStream:     cache.NewBundleStream(observer.NewProperty(bundle).Observe()),
				Clk:              clk,
				SVID:             svid,
				SVIDKey:          svidKey,
				Reattestable:     tt.reattest,
				NodeAttestor:     attestor,
				ServerAddr:       listener.Addr().String(),
				RotationStrategy: rotationutil.NewRotationStrategy(0),
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

			// All tests should get through one rotation loop or error
			select {
			case <-clk.WaitForAfterCh():
			case err = <-errCh:
				t.Fatalf("unexpected error during first rotation loop: %v", err)
			case <-time.After(testTimeout):
				if hook.LastEntry() != nil && hook.LastEntry().Level == logrus.ErrorLevel {
					t.Fatalf("timed out waiting for first rotation loop to finish: %s", hook.LastEntry().Message)
				}
				t.Fatal("timed out waiting for first rotation loop to finish")
			}

			// Wait for the rotation check to finish
			if tt.shouldRotate {
				// Optionally advance the clock by the specified amount
				// before waiting for the rotation check to finish.
				if tt.notAfter != 0 {
					require.Greaterf(t, tt.notAfter, DefaultRotatorInterval, "notAfter must be larger than %v", DefaultRotatorInterval)
					clk.Add(tt.notAfter)
				}

				select {
				case <-rotationDone:
				case err = <-errCh:
					t.Fatalf("unexpected error during rotation: %v", err)
				case <-time.After(testTimeout):
					if hook.LastEntry() != nil && hook.LastEntry().Level == logrus.ErrorLevel {
						t.Fatalf("timed out waiting for rotation check to finish: %s", hook.LastEntry().Message)
					}
					t.Fatal("timed out waiting for rotation check to finish")
				}
			} else if tt.forceRotation {
				err := rotator.Reattest(context.Background())
				require.NoError(t, err)
			}

			// Shut down the rotator
			cancel()
			select {
			case err = <-errCh:
				require.True(t, errors.Is(err, context.Canceled), "expected %v, not %v", context.Canceled, err)
			case <-time.After(testTimeout):
				t.Fatal("timed out waiting for the rotator to shut down")
			}

			// If rotation was supposed to happen, wait for the SVID changes
			// on the state stream.
			if tt.shouldRotate || tt.forceRotation {
				require.True(t, stream.HasNext(), "SVID stream should have changes")
				stream.Next()
			} else {
				require.False(t, stream.HasNext(), "SVID stream should not have changes")
			}

			// Assert that rotation happened and that the client was released
			// the appropriate number of times.
			state := stream.Value().(State)
			require.Len(t, state.SVID, 1)
			if tt.shouldRotate || tt.forceRotation {
				assert.NotEqual(t, svid, state.SVID)
				assert.NotEqual(t, svidKey, state.Key)
				assert.Equal(t, 2, mockClient.releaseCount, "client might not released after rotation")
			} else {
				assert.Equal(t, svid, state.SVID)
				assert.Equal(t, svidKey, state.Key)
				assert.Equal(t, 1, mockClient.releaseCount)
			}

			assert.Equal(t, tt.reattest, mockAgentService.attested)
		})
	}
}

func TestRotationFails(t *testing.T) {
	caCert, caKey := testca.CreateCACertificate(t, nil, nil)
	serverCert, serverKey := testca.CreateX509Certificate(t, caCert, caKey, testca.WithID(idutil.RequireServerID(trustDomain)))

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{serverCert.Raw},
				PrivateKey:  serverKey,
			},
		},
		MinVersion: tls.VersionTLS12,
	}

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
		name              string
		reattest          bool
		err               error
		expectErr         string
		expiration        time.Duration
		bundleTrustDomain spiffeid.TrustDomain
	}{
		{
			name:              "renew svid is expired",
			expiration:        -time.Second,
			bundleTrustDomain: trustDomain,
			err:               errors.New("oh no"),
			expectErr:         "current SVID has already expired and rotate agent SVID failed: oh no",
		},
		{
			name:              "expired agent",
			bundleTrustDomain: trustDomain,
			err:               fmt.Errorf("client fails: %w", expiredStatus.Err()),
			expectErr:         "client fails: rpc error: code = PermissionDenied desc = agent is not active",
		},
		{
			name:              "banned agent",
			bundleTrustDomain: trustDomain,
			err:               fmt.Errorf("client fails: %w", bannedStatus.Err()),
			expectErr:         "client fails: rpc error: code = PermissionDenied desc = agent is banned",
		},
		{
			name:              "reattest svid is expired",
			expiration:        -time.Second,
			reattest:          true,
			bundleTrustDomain: trustDomain,
			err:               errors.New("reattestation failed by test"),
			expectErr: "current SVID has already expired and reattest agent failed: failed to receive attestation response: " +
				"rpc error: code = Unknown desc = reattestation failed by test",
		},
		{
			name:              "reattest bad bundle",
			expiration:        -time.Second,
			reattest:          true,
			bundleTrustDomain: badTrustDomain,
			err:               errors.New(bundleError),
			expectErr:         "current SVID has already expired and reattest agent failed: bundle not found",
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

			// Create the bundle
			bundle := make(map[spiffeid.TrustDomain]*spiffebundle.Bundle)
			bundle[tt.bundleTrustDomain] = spiffebundle.FromX509Authorities(trustDomain, []*x509.Certificate{caCert})

			// Create the starting SVID
			svidKey, err := svidKM.GenerateKey(context.Background(), nil)
			require.NoError(t, err)
			svid, err := createTestSVID(svidKey.Public(), caCert, caKey, clk.Now(), clk.Now().Add(tt.expiration))
			require.NoError(t, err)

			// Create the attestor
			attestor := fakeagentnodeattestor.New(t, fakeagentnodeattestor.Config{})

			// Create the server
			mockAgentService := &fakeAgentService{
				clk:         clk,
				svidKM:      svidKM,
				svidKey:     svidKey,
				caCert:      caCert,
				caKey:       caKey,
				reattestErr: tt.err,
			}
			listener := createTestListener(t, mockAgentService, tlsConfig)

			// Initialize the rotator
			rotator, _ := newRotator(&RotatorConfig{
				SVIDKeyManager:   svidKM,
				Log:              log,
				Metrics:          telemetry.Blackhole{},
				TrustDomain:      trustDomain,
				BundleStream:     cache.NewBundleStream(observer.NewProperty(bundle).Observe()),
				Clk:              clk,
				Reattestable:     tt.reattest,
				SVID:             svid,
				SVIDKey:          svidKey,
				NodeAttestor:     attestor,
				ServerAddr:       listener.Addr().String(),
				RotationStrategy: rotationutil.NewRotationStrategy(0),
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

func (c *fakeClient) RenewSVID(_ context.Context, csrBytes []byte) (*client.X509SVID, error) {
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

	notAfter := c.clk.Now().Add(time.Hour)
	svidBytes, err := createTestSVIDBytes(csr.PublicKey, c.caCert, c.caKey, c.clk.Now(), notAfter)
	if err != nil {
		return nil, err
	}

	return &client.X509SVID{
		CertChain: svidBytes,
		ExpiresAt: notAfter.Unix(),
	}, nil
}

func (c *fakeClient) Release() {
	c.releaseCount++
}

type fakeAgentService struct {
	agentv1.AgentServer

	clk         clock.Clock
	attested    bool
	svidKM      keymanager.SVIDKeyManager
	svidKey     keymanager.Key
	caCert      *x509.Certificate
	caKey       crypto.Signer
	reattestErr error
}

func (n *fakeAgentService) AttestAgent(stream agentv1.Agent_AttestAgentServer) error {
	_, err := stream.Recv()
	if err != nil {
		return err
	}

	if n.reattestErr != nil {
		return n.reattestErr
	}

	key, err := n.svidKM.GenerateKey(context.Background(), n.svidKey)
	if err != nil {
		return err
	}

	svidBytes, err := createTestSVIDBytes(key.Public(), n.caCert, n.caKey, n.clk.Now(), n.clk.Now().Add(time.Hour))
	if err != nil {
		return err
	}

	n.attested = true

	return stream.Send(&agentv1.AttestAgentResponse{
		Step: &agentv1.AttestAgentResponse_Result_{
			Result: &agentv1.AttestAgentResponse_Result{
				Svid: &types.X509SVID{
					CertChain: [][]byte{svidBytes},
				},
			},
		},
	})
}

func createTestListener(t *testing.T, agentService agentv1.AgentServer, tlsConfig *tls.Config) net.Listener {
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	agentv1.RegisterAgentServer(server, agentService)

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	spiretest.ServeGRPCServerOnListener(t, server, listener)

	return listener
}

func createTestSVID(svidKey crypto.PublicKey, ca *x509.Certificate, caKey crypto.Signer, notBefore, notAfter time.Time) ([]*x509.Certificate, error) {
	svidBytes, err := createTestSVIDBytes(svidKey, ca, caKey, notBefore, notAfter)
	if err != nil {
		return nil, err
	}
	svidParsed, err := x509.ParseCertificate(svidBytes)
	if err != nil {
		return nil, err
	}

	return []*x509.Certificate{svidParsed}, nil
}

func createTestSVIDBytes(svidKey crypto.PublicKey, ca *x509.Certificate, caKey crypto.Signer, notBefore, notAfter time.Time) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		URIs:         []*url.URL{{Scheme: "spiffe", Host: trustDomain.Name(), Path: "/spire/agent/test"}},
	}

	return x509.CreateCertificate(rand.Reader, tmpl, ca, svidKey, caKey)
}
