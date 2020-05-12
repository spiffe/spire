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
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestServiceMintX509SVID(t *testing.T) {
	clock := clock.NewMock(t)
	// Add logger to context
	log, logHook := test.NewNullLogger()
	ctx := rpccontext.WithLogger(context.Background(), log)

	spiffeID := spiffeid.Must("example.org", "workload1")
	dns := []string{"dns1", "dns2"}

	// Create Service
	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	fakeServerCA := fakeserverca.New(t, trustDomain.String(), &fakeserverca.Options{Clock: clock})
	service := svid.New(svid.Config{
		ServerCA:    fakeServerCA,
		TrustDomain: trustDomain,
	})

	key := testkey.NewEC256(t)
	x509CA := fakeServerCA.X509CA()
	now := fakeServerCA.Clock().Now().UTC()

	testCases := []struct {
		name      string
		code      codes.Code
		createCsr func(tb testing.TB) *x509.CertificateRequest
		dns       []string
		err       string
		expiredAt time.Time
		msg       string
		spiffeID  spiffeid.ID
		subject   string
		ttl       time.Duration
		x509CA    *ca.X509CA
	}{
		{
			name: "success",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{spiffeID.URL()},
					DNSNames:           dns,
					Subject: pkix.Name{
						Country:      []string{"US", "EN"},
						Organization: []string{"ORG"},
					},
				}
				return createCsr(t, template, key)
			},
			dns:       []string{"dns1", "dns2"},
			expiredAt: now.Add(time.Minute),
			spiffeID:  spiffeID,
			subject:   "CN=dns1,O=ORG,C=US+C=EN",
			ttl:       time.Minute,
			x509CA:    x509CA,
		}, {
			name: "default values",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{spiffeID.URL()},
				}
				return createCsr(t, template, key)
			},
			expiredAt: now.Add(fakeServerCA.X509SVIDTTL()),
			spiffeID:  spiffeID,
			subject:   "O=SPIRE,C=US",
			x509CA:    x509CA,
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
			ttl:  time.Minute,
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
			err:  "invalid CSR: a valid URI is required",
			msg:  "Invalid CSR: a valid URI is required",
			ttl:  time.Minute,
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
			err:  "invalid CSR: a valid URI is required",
			msg:  "Invalid CSR: a valid URI is required",
			ttl:  time.Minute,
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
			err:  "invalid CSR: a valid SPIFFE ID is expected: spiffeid: invalid scheme",
			msg:  "Invalid CSR: a valid SPIFFE ID is expected",
			ttl:  time.Minute,
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
			err:  "invalid CSR: SPIFFE ID is not member of the server trust domain",
			msg:  "Invalid CSR: SPIFFE ID is not member of the server trust domain",
			ttl:  time.Minute,
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
			ttl:  time.Minute,
		}, {
			name: "serverCA fails",
			createCsr: func(tb testing.TB) *x509.CertificateRequest {
				template := &x509.CertificateRequest{
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					URIs:               []*url.URL{spiffeID.URL()},
				}

				return createCsr(tb, template, key)
			},
			code: codes.Internal,
			err:  "failed to sign X509-SVID: X509 CA is not available for signing",
			msg:  "Failed to sign X509-SVID",
			ttl:  time.Minute,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			// Set x509CA used when signing SVID
			fakeServerCA.CA.SetX509CA(testCase.x509CA)

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

func createCsr(t testing.TB, template *x509.CertificateRequest, key interface{}) *x509.CertificateRequest {
	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	// Parse raw certificate
	csr, err := x509.ParseCertificateRequest(csrRaw)
	require.NoError(t, err)

	return csr
}
