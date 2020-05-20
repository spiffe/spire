package svid_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/api/svid/v1"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"gopkg.in/square/go-jose.v2/jwt"
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
			require.NoError(t, err)

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

func TestServiceMintJWTSVID(t *testing.T) {
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

	jwtKey := fakeServerCA.JWTKey()
	now := fakeServerCA.Clock().Now().UTC()
	issuedAt := now
	expiresAt := now.Add(fakeServerCA.JWTSVIDTTL())

	testCases := []struct {
		name string

		code        codes.Code
		err         string
		logMsg      string
		issuedAt    time.Time
		expiresAt   time.Time
		spiffeID    spiffeid.ID
		ttl         time.Duration
		failMinting bool
		audience    []string
	}{
		{
			name:      "success",
			audience:  []string{"AUDIENCE"},
			issuedAt:  issuedAt,
			expiresAt: expiresAt,
			spiffeID:  spiffeID,
		},
		{
			name:      "success custom TTL",
			audience:  []string{"AUDIENCE"},
			ttl:       10 * time.Second,
			issuedAt:  issuedAt,
			expiresAt: now.Add(10 * time.Second),
			spiffeID:  spiffeID,
		},
		{
			name:     "invalid trust domain",
			code:     codes.InvalidArgument,
			audience: []string{"AUDIENCE"},
			spiffeID: spiffeid.Must("invalid.test", "workload1"),
			err:      `invalid SPIFFE ID: "spiffe://invalid.test/workload1" does not belong to trust domain "example.org"`,
			logMsg:   `Invalid SPIFFE ID: "spiffe://invalid.test/workload1" does not belong to trust domain "example.org"`,
		},
		{
			name:      "no audience",
			code:      codes.InvalidArgument,
			err:       "at least one audience is required",
			logMsg:    "At least one audience is required",
			issuedAt:  issuedAt,
			expiresAt: expiresAt,
			spiffeID:  spiffeID,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			fakeServerCA.CA.SetJWTKey(jwtKey)
			if testCase.failMinting {
				fakeServerCA.CA.SetJWTKey(nil)
			}

			resp, err := service.MintJWTSVID(ctx, testCase.spiffeID, testCase.audience, testCase.ttl)

			// Check for expected errors
			if testCase.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, testCase.code, testCase.err)
				require.Nil(t, resp)
				require.Equal(t, testCase.logMsg, logHook.LastEntry().Message)

				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)

			// Verify response
			require.NotEmpty(t, resp.Token)

			token, err := jwt.ParseSigned(resp.Token)
			require.NoError(t, err)

			var claims jwt.Claims
			err = token.UnsafeClaimsWithoutVerification(&claims)
			require.NoError(t, err)

			require.Equal(t, testCase.spiffeID.String(), claims.Subject)
			require.Equal(t, jwt.Audience(testCase.audience), claims.Audience)
			require.Equal(t, testCase.spiffeID, resp.ID)
			require.NotNil(t, claims.Expiry)

			expiry := time.Unix(int64(*claims.Expiry), 0).UTC()
			if testCase.ttl == 0 {
				require.Equal(t, now.Add(fakeServerCA.JWTSVIDTTL()), expiry)
			} else {
				require.Equal(t, testCase.expiresAt, expiry)
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
