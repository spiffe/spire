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
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/api/svid/v1"
	svidpb "github.com/spiffe/spire/proto/spire-next/api/server/svid/v1"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	testKey    = testkey.MustEC256()
	workloadID = spiffeid.Must("example.org", "workload1")
)

func TestServiceMintX509SVID(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	x509CA := test.ca.X509CA()
	now := test.ca.Clock().Now().UTC()
	expiredAt := now.Add(test.ca.X509SVIDTTL())

	for _, tt := range []struct {
		name        string
		code        codes.Code
		csrTemplate *x509.CertificateRequest
		dns         []string
		err         string
		expiredAt   time.Time
		msg         string
		subject     string
		ttl         time.Duration
		failMinting bool
		mutateCSR   func([]byte) []byte
	}{
		{
			name: "success",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{workloadID.URL()},
			},
			expiredAt: expiredAt,
			subject:   "O=SPIRE,C=US",
		},
		{
			name: "custom ttl",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{workloadID.URL()},
			},
			expiredAt: now.Add(10 * time.Second),
			subject:   "O=SPIRE,C=US",
			ttl:       10 * time.Second,
		},
		{
			name: "custom dns",
			csrTemplate: &x509.CertificateRequest{
				URIs:     []*url.URL{workloadID.URL()},
				DNSNames: []string{"dns1", "dns2"},
			},
			dns:       []string{"dns1", "dns2"},
			expiredAt: expiredAt,
			subject:   "CN=dns1,O=SPIRE,C=US",
		},
		{
			name: "custom subject",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{workloadID.URL()},
				Subject: pkix.Name{
					Country:      []string{"US", "EN"},
					Organization: []string{"ORG"},
				},
			},
			expiredAt: expiredAt,
			subject:   "O=ORG,C=US+C=EN",
		},
		{
			name: "custom subject and dns",
			csrTemplate: &x509.CertificateRequest{
				URIs:     []*url.URL{workloadID.URL()},
				DNSNames: []string{"dns1", "dns2"},
				Subject: pkix.Name{
					Country:      []string{"US", "EN"},
					Organization: []string{"ORG"},
				},
			},
			dns:       []string{"dns1", "dns2"},
			expiredAt: expiredAt,
			subject:   "CN=dns1,O=ORG,C=US+C=EN",
		},
		{
			name: "no CSR",
			code: codes.InvalidArgument,
			err:  "request missing CSR",
			msg:  "Request missing CSR",
		},
		{
			name: "malformed CSR",
			code: codes.InvalidArgument,
			mutateCSR: func(csr []byte) []byte {
				return []byte{1, 2, 3}
			},
			err: "malformed CSR: asn1:",
			msg: "Malformed CSR",
		},
		{
			name: "invalid signature",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{workloadID.URL()},
			},
			mutateCSR: func(csr []byte) []byte {
				// 4 bytes from the end should be back far enough to be in the
				// signature bytes.
				csr[len(csr)-4]++
				return csr
			},
			code: codes.InvalidArgument,
			err:  "invalid CSR: signature verify failed",
			msg:  "Invalid CSR: signature verify failed",
		},
		{
			name: "no URIs",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{},
			},
			code: codes.InvalidArgument,
			err:  "invalid CSR: URI SAN is required",
			msg:  "Invalid CSR: URI SAN is required",
		},
		{
			name: "multiple URIs",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{
					workloadID.URL(),
					spiffeid.Must("examples.org", "workload2").URL(),
				},
			},
			code: codes.InvalidArgument,
			err:  "invalid CSR: only one URI SAN is expected",
			msg:  "Invalid CSR: only one URI SAN is expected",
		},
		{
			name: "invalid SPIFFE ID",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{
					{Scheme: "http", Host: "localhost"},
				},
			},
			code: codes.InvalidArgument,
			err:  "invalid CSR: URI SAN is not a valid SPIFFE ID: spiffeid: invalid scheme",
			msg:  "Invalid CSR: URI SAN is not a valid SPIFFE ID",
		},
		{
			name: "different trust domain",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{
					spiffeid.Must("another.org", "workload1").URL(),
				},
			},
			code: codes.InvalidArgument,
			err:  `invalid SPIFFE ID in CSR: "spiffe://another.org/workload1" does not belong to trust domain "example.org"`,
			msg:  `Invalid SPIFFE ID in CSR: "spiffe://another.org/workload1" does not belong to trust domain "example.org"`,
		},
		{
			name: "SPIFFE ID is not for a workload in the trust domain",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{
					spiffeid.Must("example.org").URL(),
				},
			},
			code: codes.InvalidArgument,
			err:  `invalid SPIFFE ID in CSR: invalid workload SPIFFE ID "spiffe://example.org": path is empty`,
			msg:  `Invalid SPIFFE ID in CSR: invalid workload SPIFFE ID "spiffe://example.org": path is empty`,
		},
		{
			name: "invalid DNS",
			csrTemplate: &x509.CertificateRequest{
				URIs:     []*url.URL{workloadID.URL()},
				DNSNames: []string{"abc-"},
			},
			code: codes.InvalidArgument,
			err:  "invalid CSR: DNS name is not valid: label does not match regex: abc-",
			msg:  "Invalid CSR: DNS name is not valid",
		},
		{
			name: "signing fails",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{workloadID.URL()},
			},
			code:        codes.Internal,
			err:         "failed to sign X509-SVID: X509 CA is not available for signing",
			failMinting: true,
			msg:         "Failed to sign X509-SVID",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Set x509CA used when signing SVID
			test.ca.SetX509CA(x509CA)
			if tt.failMinting {
				test.ca.SetX509CA(nil)
			}

			// Create CSR
			var csr []byte
			if tt.csrTemplate != nil {
				csr = createCSR(t, tt.csrTemplate)
			}
			if tt.mutateCSR != nil {
				csr = tt.mutateCSR(csr)
			}

			// Mint CSR
			resp, err := test.client.MintX509SVID(context.Background(), &svidpb.MintX509SVIDRequest{
				Csr: csr,
				Ttl: int32(tt.ttl / time.Second),
			})
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)
				require.Equal(t, tt.msg, test.logHook.LastEntry().Message)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotNil(t, resp.Svid)

			certChain, err := x509util.RawCertsToCertificates(resp.Svid.CertChain)
			require.NoError(t, err)
			require.NotEmpty(t, certChain)
			svid := certChain[0]

			id, err := api.IDFromProto(resp.Svid.Id)
			require.NoError(t, err)

			require.Equal(t, workloadID, id)
			require.Equal(t, []*url.URL{workloadID.URL()}, svid.URIs)

			require.Equal(t, tt.expiredAt.Unix(), resp.Svid.ExpiresAt)
			require.Equal(t, tt.expiredAt, svid.NotAfter)

			if len(tt.dns) > 0 {
				require.Equal(t, tt.dns[0], svid.Subject.CommonName)
			}
			require.Equal(t, tt.dns, svid.DNSNames)
			require.Equal(t, tt.subject, svid.Subject.String())
		})
	}
}

func TestServiceMintJWTSVID(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	jwtKey := test.ca.JWTKey()
	now := test.ca.Clock().Now().UTC()
	issuedAt := now
	expiresAt := now.Add(test.ca.JWTSVIDTTL())

	for _, tt := range []struct {
		name string

		code        codes.Code
		err         string
		logMsg      string
		expiresAt   time.Time
		id          spiffeid.ID
		ttl         time.Duration
		failMinting bool
		audience    []string
	}{
		{
			name:      "success",
			audience:  []string{"AUDIENCE"},
			expiresAt: expiresAt,
			id:        workloadID,
		},
		{
			name:      "success custom TTL",
			audience:  []string{"AUDIENCE"},
			ttl:       10 * time.Second,
			expiresAt: now.Add(10 * time.Second),
			id:        workloadID,
		},
		{
			name:     "bad id",
			code:     codes.InvalidArgument,
			audience: []string{"AUDIENCE"},
			id:       spiffeid.ID{},
			err:      "spiffeid: trust domain is empty",
			logMsg:   "Failed to parse SPIFFE ID",
		},
		{
			name:     "invalid trust domain",
			code:     codes.InvalidArgument,
			audience: []string{"AUDIENCE"},
			id:       spiffeid.Must("invalid.test", "workload1"),
			err:      `invalid SPIFFE ID: "spiffe://invalid.test/workload1" does not belong to trust domain "example.org"`,
			logMsg:   `Invalid SPIFFE ID: "spiffe://invalid.test/workload1" does not belong to trust domain "example.org"`,
		},
		{
			name:     "SPIFFE ID is not for a workload in the trust domain",
			code:     codes.InvalidArgument,
			audience: []string{"AUDIENCE"},
			id:       spiffeid.Must("example.org"),
			err:      `invalid SPIFFE ID: invalid workload SPIFFE ID "spiffe://example.org": path is empty`,
			logMsg:   `Invalid SPIFFE ID: invalid workload SPIFFE ID "spiffe://example.org": path is empty`},
		{
			name:      "no audience",
			code:      codes.InvalidArgument,
			err:       "at least one audience is required",
			logMsg:    "At least one audience is required",
			expiresAt: expiresAt,
			id:        workloadID,
		},
		{
			name:        "fails minting",
			code:        codes.InvalidArgument,
			err:         "at least one audience is required",
			logMsg:      "At least one audience is required",
			failMinting: true,
			expiresAt:   expiresAt,
			id:          workloadID,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.ca.SetJWTKey(jwtKey)
			if tt.failMinting {
				test.ca.CA.SetJWTKey(nil)
			}

			resp, err := test.client.MintJWTSVID(context.Background(), &svidpb.MintJWTSVIDRequest{
				Id:       api.ProtoFromID(tt.id),
				Audience: tt.audience,
				Ttl:      int32(tt.ttl / time.Second),
			})

			// Check for expected errors
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)
				require.Equal(t, tt.logMsg, test.logHook.LastEntry().Message)

				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotNil(t, resp.Svid)

			// Verify response
			require.NotEmpty(t, resp.Svid.Token)

			token, err := jwt.ParseSigned(resp.Svid.Token)
			require.NoError(t, err)

			var claims jwt.Claims
			err = token.UnsafeClaimsWithoutVerification(&claims)
			require.NoError(t, err)

			id, err := api.IDFromProto(resp.Svid.Id)
			require.NoError(t, err)
			require.Equal(t, tt.id, id)
			require.Equal(t, tt.id.String(), claims.Subject)

			require.Equal(t, jwt.Audience(tt.audience), claims.Audience)

			require.NotNil(t, claims.IssuedAt)
			require.Equal(t, issuedAt.Unix(), resp.Svid.IssuedAt)
			require.Equal(t, issuedAt.Unix(), int64(*claims.IssuedAt))

			require.NotNil(t, claims.Expiry)
			if tt.ttl == 0 {
				require.Equal(t, expiresAt.Unix(), resp.Svid.ExpiresAt)
				require.Equal(t, expiresAt.Unix(), int64(*claims.Expiry))
			} else {
				require.Equal(t, tt.expiresAt.Unix(), resp.Svid.ExpiresAt)
				require.Equal(t, tt.expiresAt.Unix(), int64(*claims.Expiry))
			}
		})
	}
}

type serviceTest struct {
	client  svidpb.SVIDClient
	ca      *fakeserverca.CA
	logHook *test.Hook
	done    func()
}

func (c *serviceTest) Cleanup() {
	c.done()
}

func setupServiceTest(t *testing.T) *serviceTest {
	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	ca := fakeserverca.New(t, trustDomain.String(), &fakeserverca.Options{})
	service := svid.New(svid.Config{
		ServerCA:    ca,
		TrustDomain: trustDomain,
	})

	log, logHook := test.NewNullLogger()
	registerFn := func(s *grpc.Server) {
		svid.RegisterService(s, service)
	}

	contextFn := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		return ctx
	}

	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)

	return &serviceTest{
		client:  svidpb.NewSVIDClient(conn),
		ca:      ca,
		logHook: logHook,
		done:    done,
	}
}

func createCSR(tb testing.TB, template *x509.CertificateRequest) []byte {
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, testKey)
	require.NoError(tb, err)
	return csr
}
