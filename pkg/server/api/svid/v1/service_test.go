package svid_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/api/svid/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestServiceMintX509SVID(t *testing.T) {
	// Add logger to context
	log, logHook := test.NewNullLogger()
	ctx := rpccontext.WithLogger(context.Background(), log)

	spiffeID := spiffeid.Must("example.org", "workload1")

	// Create Service
	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	fakeServerCA := fakeserverca.New(t, trustDomain.String(), &fakeserverca.Options{})
	service := svid.New(svid.Config{
		ServerCA:    fakeServerCA,
		TrustDomain: trustDomain,
	})

	key := testkey.NewEC256(t)
	x509CA := fakeServerCA.X509CA()
	now := fakeServerCA.Clock().Now().UTC()
	expiredAt := now.Add(fakeServerCA.X509SVIDTTL())

	testCases := []struct {
		name        string
		code        codes.Code
		createCsr   func(tb testing.TB) *x509.CertificateRequest
		dns         []string
		err         string
		expiredAt   time.Time
		msg         string
		spiffeID    spiffeid.ID
		subject     string
		ttl         time.Duration
		failMinting bool
	}{
		{
			name: "success",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{spiffeID.URL()},
				}
				return createCsr(t, template, key)
			},
			expiredAt: expiredAt,
			spiffeID:  spiffeID,
			subject:   "O=SPIRE,C=US",
		}, {
			name: "custom ttl",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{spiffeID.URL()},
				}
				return createCsr(t, template, key)
			},
			expiredAt: now.Add(10 * time.Second),
			spiffeID:  spiffeID,
			subject:   "O=SPIRE,C=US",
			ttl:       10 * time.Second,
		}, {
			name: "custom dns",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{spiffeID.URL()},
					DNSNames:           []string{"dns1", "dns2"},
				}
				return createCsr(t, template, key)
			},
			dns:       []string{"dns1", "dns2"},
			expiredAt: expiredAt,
			spiffeID:  spiffeID,
			subject:   "CN=dns1,O=SPIRE,C=US",
		}, {
			name: "custom subject",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{spiffeID.URL()},
					Subject: pkix.Name{
						Country:      []string{"US", "EN"},
						Organization: []string{"ORG"},
					},
				}
				return createCsr(t, template, key)
			},
			expiredAt: expiredAt,
			spiffeID:  spiffeID,
			subject:   "O=ORG,C=US+C=EN",
		}, {
			name: "custom subject and dns",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{spiffeID.URL()},
					DNSNames:           []string{"dns1", "dns2"},
					Subject: pkix.Name{
						Country:      []string{"US", "EN"},
						Organization: []string{"ORG"},
					},
				}
				return createCsr(t, template, key)
			},
			dns:       []string{"dns1", "dns2"},
			expiredAt: expiredAt,
			spiffeID:  spiffeID,
			subject:   "CN=dns1,O=ORG,C=US+C=EN",
		}, {
			name: "invalid signature",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				return &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{spiffeID.URL()},
				}
			},
			code: codes.InvalidArgument,
			err:  "invalid CSR: signature verify failed",
			msg:  "Invalid CSR: signature verify failed",
		}, {
			name: "no URIs",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{},
				}

				return createCsr(tb, template, key)
			},
			code: codes.InvalidArgument,
			err:  "invalid CSR: URI SAN is required",
			msg:  "Invalid CSR: URI SAN is required",
		}, {
			name: "multiple URIs",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs: []*url.URL{
						spiffeID.URL(),
						spiffeid.Must("examples.org", "workload2").URL(),
					},
				}

				return createCsr(tb, template, key)
			},
			code: codes.InvalidArgument,
			err:  "invalid CSR: only one URI SAN is expected",
			msg:  "Invalid CSR: only one URI SAN is expected",
		}, {
			name: "invalid SPIFFE ID",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs: []*url.URL{
						{Scheme: "http", Host: "localhost"},
					},
				}

				return createCsr(tb, template, key)
			},
			code: codes.InvalidArgument,
			err:  "invalid CSR: URI SAN is not a valid SPIFFE ID: spiffeid: invalid scheme",
			msg:  "Invalid CSR: URI SAN is not a valid SPIFFE ID",
		}, {
			name: "different trust domain",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs: []*url.URL{
						spiffeid.Must("another.org", "workload1").URL(),
					},
				}

				return createCsr(tb, template, key)
			},
			code: codes.InvalidArgument,
			err:  "invalid CSR: SPIFFE ID is not a member of the server trust domain",
			msg:  "Invalid CSR: SPIFFE ID is not a member of the server trust domain",
		}, {
			name: "invalid DNS",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{spiffeID.URL()},
					DNSNames:           []string{"abc-"},
				}

				return createCsr(tb, template, key)
			},
			code: codes.InvalidArgument,
			err:  "invalid CSR: DNS name is not valid: label does not match regex: abc-",
			msg:  "Invalid CSR: DNS name is not valid",
		}, {
			name: "serverCA fails",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{spiffeID.URL()},
				}

				return createCsr(tb, template, key)
			},
			code:        codes.Internal,
			err:         "failed to sign X509-SVID: X509 CA is not available for signing",
			failMinting: true,
			msg:         "Failed to sign X509-SVID",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			// Set x509CA used when signing SVID
			fakeServerCA.CA.SetX509CA(x509CA)
			if testCase.failMinting {
				fakeServerCA.CA.SetX509CA(nil)
			}

			// Mint CSR
			resp, err := service.MintX509SVID(ctx, testCase.createCsr(t), testCase.ttl)

			if testCase.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, testCase.code, testCase.err)
				require.Nil(t, resp)
				require.Equal(t, testCase.msg, logHook.LastEntry().Message)

				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)

			// Verify Response
			require.Equal(t, testCase.spiffeID, resp.ID)
			require.Equal(t, testCase.expiredAt, resp.ExpiresAt)

			// Verify Certificate
			svid := resp.CertChain[0]
			require.NotNil(t, svid)

			require.Equal(t, []*url.URL{spiffeID.URL()}, svid.URIs)
			require.Equal(t, testCase.expiredAt, svid.NotAfter)
			if len(testCase.dns) > 0 {
				require.Equal(t, testCase.dns[0], svid.Subject.CommonName)
			}
			require.Equal(t, testCase.dns, svid.DNSNames)
			require.Equal(t, testCase.subject, svid.Subject.String())
		})
	}
}

func TestServiceBatchNewX509SVID(t *testing.T) {
	// Add logger to context
	log, logHook := test.NewNullLogger()

	trustDomain := spiffeid.RequireTrustDomainFromString("examples.org")
	agentID := trustDomain.NewID("agent")

	spiffeID := trustDomain.NewID("workload1")

	ctx := context.Background()
	entry1 := &types.Entry{
		Id:       "entry1",
		ParentId: api.SpiffeIDToProto(agentID),
		SpiffeId: api.SpiffeIDToProto(spiffeID),
	}

	spiffeIDDns := trustDomain.NewID("dns")
	entryDns := &types.Entry{
		Id:       "entryDns",
		ParentId: api.SpiffeIDToProto(agentID),
		SpiffeId: api.SpiffeIDToProto(spiffeIDDns),
		DnsNames: []string{"entryDNS1", "entryDNS2"},
	}

	spiffeIDTtl := trustDomain.NewID("ttl")
	entryTtl := &types.Entry{
		Id:       "entryTtl",
		ParentId: api.SpiffeIDToProto(agentID),
		SpiffeId: api.SpiffeIDToProto(spiffeIDTtl),
		Ttl:      10,
	}

	// Create Service
	fakeServerCA := fakeserverca.New(t, trustDomain.String(), &fakeserverca.Options{})

	key := testkey.NewEC256(t)
	x509CA := fakeServerCA.X509CA()
	now := fakeServerCA.Clock().Now().UTC()
	expiredAt := now.Add(fakeServerCA.X509SVIDTTL())

	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		URIs:               []*url.URL{spiffeID.URL()},
	}
	csr := createCsr(t, template, key)

	testCases := []struct {
		name         string
		code         codes.Code
		createReq    func(tb testing.TB) []*svid.X509SVIDParams
		err          string
		expectLogs   []spiretest.LogEntry
		failCallerID bool
		failMinting  bool
		fetcherErr   string
		resp         []*svid.X509SVIDResult
	}{
		{
			name: "success",
			createReq: func(tb testing.TB) []*svid.X509SVIDParams {
				return []*svid.X509SVIDParams{
					{
						EntryID: entry1.Id,
						Csr:     csr,
					},
				}
			},
			resp: []*svid.X509SVIDResult{
				{
					Svid: &api.X509SVID{

						ID:        spiffeID,
						ExpiresAt: expiredAt,
						CertChain: []*x509.Certificate{
							{
								URIs:     []*url.URL{spiffeID.URL()},
								NotAfter: expiredAt,
								Subject: pkix.Name{
									Country:      []string{"US"},
									Organization: []string{"SPIRE"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "entry ttl",
			createReq: func(tb testing.TB) []*svid.X509SVIDParams {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{spiffeIDTtl.URL()},
				}
				return []*svid.X509SVIDParams{
					{
						EntryID: entryTtl.Id,
						Csr:     createCsr(t, template, key),
					},
				}
			},
			resp: []*svid.X509SVIDResult{
				{
					Svid: &api.X509SVID{

						ID:        spiffeIDTtl,
						ExpiresAt: now.Add(10 * time.Second),
						CertChain: []*x509.Certificate{
							{
								URIs:     []*url.URL{spiffeIDTtl.URL()},
								NotAfter: now.Add(10 * time.Second),
								Subject: pkix.Name{
									Country:      []string{"US"},
									Organization: []string{"SPIRE"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "entry DNS",
			createReq: func(tb testing.TB) []*svid.X509SVIDParams {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{spiffeIDDns.URL()},
				}
				return []*svid.X509SVIDParams{
					{
						EntryID: entryDns.Id,
						Csr:     createCsr(t, template, key),
					},
				}
			},
			resp: []*svid.X509SVIDResult{
				{
					Svid: &api.X509SVID{

						ID:        spiffeIDDns,
						ExpiresAt: expiredAt,
						CertChain: []*x509.Certificate{
							{
								URIs:     []*url.URL{spiffeIDDns.URL()},
								NotAfter: expiredAt,
								DNSNames: entryDns.DnsNames,
								Subject: pkix.Name{
									CommonName:   entryDns.DnsNames[0],
									Country:      []string{"US"},
									Organization: []string{"SPIRE"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "subject is not updated from CSR",
			createReq: func(tb testing.TB) []*svid.X509SVIDParams {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{spiffeID.URL()},
					Subject: pkix.Name{
						Country:      []string{"US", "EN"},
						Organization: []string{"ORG"},
					},
				}
				return []*svid.X509SVIDParams{
					{
						EntryID: entry1.Id,
						Csr:     createCsr(t, template, key),
					},
				}
			},
			resp: []*svid.X509SVIDResult{
				{
					Svid: &api.X509SVID{

						ID:        spiffeID,
						ExpiresAt: expiredAt,
						CertChain: []*x509.Certificate{
							{
								URIs:     []*url.URL{spiffeID.URL()},
								NotAfter: expiredAt,
								Subject: pkix.Name{
									Country:      []string{"US"},
									Organization: []string{"SPIRE"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "missing CallerID",
			createReq: func(tb testing.TB) []*svid.X509SVIDParams {
				return []*svid.X509SVIDParams{}
			},
			code: codes.Internal,
			err:  "callerID is required",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "CallerID is required",
					Data:	 logrus.Fields{},
				},
			},
			failCallerID: true,
		},
		{
			name: "fetcher fails",
			createReq: func(tb testing.TB) []*svid.X509SVIDParams {
				return []*svid.X509SVIDParams{
					{
						EntryID: entry1.Id,
						Csr:     csr,
					},
				}
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch registration entries",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = Internal desc = some error",
					},
				},
			},
			code:       codes.Internal,
			err:        "failed to fetch registration entries",
			fetcherErr: "some error",
		},
		{
			name: "entry not found",
			createReq: func(tb testing.TB) []*svid.X509SVIDParams {
				return []*svid.X509SVIDParams{
					{
						EntryID: "invalid ID",
						Csr:     csr,
					},
				}
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid registration entry: not found",
					Data: logrus.Fields{
						telemetry.RegistrationID: "invalid ID",
					},
				},
			},
			resp: []*svid.X509SVIDResult{
				{
					Err: status.Error(codes.InvalidArgument, `invalid entry id: "invalid ID" not found`),
				},
			},
		},
		{
			name: "invalid signature",
			createReq: func(tb testing.TB) []*svid.X509SVIDParams {
				return []*svid.X509SVIDParams{
					{
						EntryID: entry1.Id,
						Csr:     template},
				}
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid CSR: signature verify failed",
					Data: logrus.Fields{
						telemetry.RegistrationID: entry1.Id,
						logrus.ErrorKey:          "x509: cannot verify signature: algorithm unimplemented",
					},
				},
			},
			resp: []*svid.X509SVIDResult{
				{
					Err: status.Error(codes.InvalidArgument, "invalid CSR: signature verify failed"),
				},
			},
		},
		{
			name: "signing fails",
			createReq: func(tb testing.TB) []*svid.X509SVIDParams {
				return []*svid.X509SVIDParams{
					{
						EntryID: entry1.Id,
						Csr:     csr,
					},
				}
			},
			failMinting: true,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to sign X509-SVID",
					Data: logrus.Fields{
						telemetry.RegistrationID: entry1.Id,
						logrus.ErrorKey:          "X509 CA is not available for signing",
						telemetry.SPIFFEID:       spiffeID.String(),
					},
				},
			},
			resp: []*svid.X509SVIDResult{
				{
					Err: status.Error(codes.Internal, "failed to sign X509-SVID: X509 CA is not available for signing"),
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			logHook.Reset()

			// Set x509CA used when signing SVID
			fakeServerCA.CA.SetX509CA(x509CA)
			if testCase.failMinting {
				fakeServerCA.CA.SetX509CA(nil)
			}

			ctx := rpccontext.WithLogger(ctx, log)
			// Add caller to context
			if !testCase.failCallerID {
				ctx = rpccontext.WithCallerID(ctx, agentID)
			}

			service := svid.New(svid.Config{
				EntryFetcher: svid.AuthorizedEntryFetcherFunc(func(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
					if testCase.fetcherErr != "" {
						return nil, status.Error(codes.Internal, testCase.fetcherErr)
					}

					caller, ok := rpccontext.CallerID(ctx)
					require.True(t, ok)

					require.Equal(t, caller, agentID)

					return []*types.Entry{
						entry1,
						entryTtl,
						entryDns,
					}, nil
				}),
				ServerCA:    fakeServerCA,
				TrustDomain: trustDomain,
			})
			resp, err := service.BatchNewX509SVID(ctx, testCase.createReq(t))
			if testCase.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, testCase.code, testCase.err)
				require.Nil(t, resp)
				spiretest.AssertLogs(t, logHook.AllEntries(), testCase.expectLogs)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			for i, r := range resp {
				expected := testCase.resp[i]

				if expected.Err != nil {
					require.Nil(t, r.Svid)
					assert.Equal(t, expected.Err, r.Err)
					spiretest.AssertLogs(t, logHook.AllEntries(), testCase.expectLogs)

					return
				}
				require.NotNil(t, r.Svid)
				require.NoError(t, r.Err)
				assert.Equal(t, expected.Svid.ID, r.Svid.ID)
				assert.Equal(t, expected.Svid.ExpiresAt, r.Svid.ExpiresAt)

				// Validate certificate
				cert := r.Svid.CertChain[0]
				require.NotNil(t, cert)

				expectedCert := expected.Svid.CertChain[0]

				assert.Equal(t, expectedCert.URIs, cert.URIs)
				assert.Equal(t, expectedCert.DNSNames, cert.DNSNames)
				assert.Equal(t, expectedCert.NotAfter, cert.NotAfter)
				assert.Equal(t, expectedCert.Subject.CommonName, cert.Subject.CommonName)
				assert.Equal(t, expectedCert.Subject.String(), cert.Subject.String())
			}
		})
	}
}

func createCsr(t testing.TB, template *x509.CertificateRequest, key interface{}) *x509.CertificateRequest {
	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	// Parse raw certificate
	csr, err := x509.ParseCertificateRequest(csrRaw)
	require.NoError(t, err)

	return csr
}
