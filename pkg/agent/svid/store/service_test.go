package store

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/manager/pipe"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	test := setupServiceTest()
	defer test.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	go func() {
		_ = test.service.Run(ctx)
	}()

	cert, key, err := util.LoadSVIDFixture()
	require.NoError(t, err)

	keyData, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	bundles, err := util.LoadBundleFixture()
	require.NoError(t, err)

	domainTD := spiffeid.RequireTrustDomainFromString("spiffe://domain.test")
	svidBundle := bundleutil.BundleFromRootCA(domainTD, bundles[0])
	otherDomainTD := spiffeid.RequireTrustDomainFromString("spiffe://otherdomain.test")
	federatedBundle := bundleutil.BundleFromRootCA(otherDomainTD, bundles[0])

	for _, tt := range []struct {
		name string

		fails      bool
		update     *pipe.SVIDUpdate
		req        *svidstore.PutX509SVIDRequest
		expectLogs []spiretest.LogEntry
		storeErr   error
	}{
		{
			name: "success",
			update: &pipe.SVIDUpdate{
				Entry: &common.RegistrationEntry{
					EntryExpiry: 1234,
					EntryId:     "FOO",
					Selectors:   []*common.Selector{{Type: "a", Value: "1"}},
					SpiffeId:    "spiffe://domain.test/foo",
				},
				SVID:       []*x509.Certificate{cert},
				PrivateKey: key,
				Bundle:     svidBundle,
				FederatedBundles: map[spiffeid.TrustDomain]*bundleutil.Bundle{
					otherDomainTD: federatedBundle,
				},
			},
			req: &svidstore.PutX509SVIDRequest{
				Svid: &svidstore.X509SVID{
					ExpiresAt:  1234,
					SpiffeID:   "spiffe://domain.test/foo",
					CertChain:  [][]byte{cert.Raw},
					PrivateKey: keyData,
					Bundle:     [][]byte{bundles[0].Raw},
				},
				Selectors: []*common.Selector{{Type: "a", Value: "1"}},
				FederatedBundles: map[string][]byte{
					"spiffe://otherdomain.test": bundles[0].Raw,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "X509-SVID stored successfully",
					Data: logrus.Fields{
						telemetry.Entry: "FOO",
					},
				},
			},
		},
		{
			name:  "store plugin fails",
			fails: true,
			update: &pipe.SVIDUpdate{
				Entry: &common.RegistrationEntry{
					EntryExpiry: 1234,
					EntryId:     "FOO",
					Selectors:   []*common.Selector{{Type: "a", Value: "1"}},
					SpiffeId:    "spiffe://domain.test/foo",
				},
				SVID:       []*x509.Certificate{cert},
				PrivateKey: key,
				Bundle:     svidBundle,
				FederatedBundles: map[spiffeid.TrustDomain]*bundleutil.Bundle{
					otherDomainTD: federatedBundle,
				},
			},
			storeErr: errors.New("some error"),
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to store X509-SVID",
					Data: logrus.Fields{
						telemetry.Entry: "FOO",
						logrus.ErrorKey: "some error",
					},
				},
			},
		},
		{
			name:  "malformed update",
			fails: true,
			update: &pipe.SVIDUpdate{
				Entry: &common.RegistrationEntry{
					EntryExpiry: 1234,
					EntryId:     "FOO",
					Selectors:   []*common.Selector{{Type: "a", Value: "1"}},
					SpiffeId:    "spiffe://domain.test/foo",
				},
				SVID:   []*x509.Certificate{cert},
				Bundle: svidBundle,
				FederatedBundles: map[spiffeid.TrustDomain]*bundleutil.Bundle{
					otherDomainTD: federatedBundle,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to create request from update",
					Data: logrus.Fields{
						telemetry.Entry: "FOO",
						logrus.ErrorKey: "failed to marshal key for entry ID \"FOO\": x509: unknown key type while marshaling PKCS#8: <nil>",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()
			test.store.err = tt.storeErr

			test.in.Push(tt.update)

			select {
			case <-test.stored:
			case <-ctx.Done():
				require.Fail(t, "context canceled")
			}

			if !tt.fails {
				spiretest.AssertProtoEqual(t, tt.req, test.store.req)
			}
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
		})
	}
}

func setupServiceTest() *serviceTest {
	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	in, out := pipe.BufferedPipe(2)
	fakeStore := &fakeSVIDStore{}

	config := &Config{
		Log:       log,
		PipeOut:   out,
		Metrics:   telemetry.Blackhole{},
		SVIDStore: fakeStore,
	}

	stored := make(chan struct{})

	s := service{
		c: config,
	}
	s.hooks.stored = stored

	return &serviceTest{
		in:      in,
		logHook: logHook,
		service: s,
		store:   fakeStore,
		stored:  stored,
	}
}

type serviceTest struct {
	in      pipe.In
	logHook *test.Hook
	service service
	store   *fakeSVIDStore
	stored  chan struct{}
}

func (s *serviceTest) Close() {
	s.in.Close()
	close(s.stored)
}

type fakeSVIDStore struct {
	req *svidstore.PutX509SVIDRequest
	err error
}

func (s *fakeSVIDStore) PutX509SVID(ctx context.Context, req *svidstore.PutX509SVIDRequest) (*svidstore.PutX509SVIDResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.req = req
	return &svidstore.PutX509SVIDResponse{}, nil
}
