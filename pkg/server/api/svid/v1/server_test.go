package svid_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/api/svid/v1"
	svidpb "github.com/spiffe/spire/proto/spire-next/api/server/svid/v1"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const rawCert = `
-----BEGIN CERTIFICATE-----
MIICcDCCAdKgAwIBAgIBAjAKBggqhkjOPQQDBDAeMQswCQYDVQQGEwJVUzEPMA0G
A1UEChMGU1BJRkZFMB4XDTE4MDIxMDAwMzY1NVoXDTE4MDIxMDAxMzY1NlowHTEL
MAkGA1UEBhMCVVMxDjAMBgNVBAoTBVNQSVJFMIGbMBAGByqGSM49AgEGBSuBBAAj
A4GGAAQBfav2iunAwzozmwg5lq30ltm/X3XeBgxhbsWu4Rv+I5B22urvR0jxGQM7
TsquuQ/wpmJQgTgV9jnK/5fvl4GvhS8A+K2UXv6L3IlrHIcMG3VoQ+BeKo44Hwgu
keu5GMUKAiEF33acNWUHp7U+Swxdxw+CwR9bNnIf0ZTfxlqSBaJGVIujgb4wgbsw
DgYDVR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAM
BgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFPhG423HoTvTKNXTAi9TKsaQwpzPMFsG
A1UdEQRUMFKGUHNwaWZmZTovL2V4YW1wbGUub3JnL3NwaXJlL2FnZW50L2pvaW5f
dG9rZW4vMmNmMzUzOGMtNGY5Yy00NmMwLWE1MjYtMWNhNjc5YTkyNDkyMAoGCCqG
SM49BAMEA4GLADCBhwJBLM2CaOSw8kzSBJUyAvg32PM1PhzsVEsGIzWS7b+hgKkJ
NlnJx6MZ82eamOCsCdTVrXUV5cxO8kt2yTmYxF+ucu0CQgGVmL65pzg2E4YfCES/
4th19FFMRiOTtNpI5j2/qLTptnanJ/rpqE0qsgA2AiSsnbnnW6B7Oa+oi7QDMOLw
l6+bdA==
-----END CERTIFICATE-----
`

func TestMintX509SVID(t *testing.T) {
	ctx := context.Background()

	c := setupTest(t)
	defer c.Close()

	spiffeID := spiffeid.Must("example.org", "workload1")

	// Create certificate request
	key := testkey.NewEC256(t)
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		URIs:               []*url.URL{spiffeID.URL()},
	}
	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	testCases := []struct {
		name string

		certChain  [][]byte
		err        string
		expiresAt  time.Time
		code       codes.Code
		msg        string
		req        *svidpb.MintX509SVIDRequest
		serviceErr string
		spiffeID   spiffeid.ID
	}{
		{
			name: "success",
			certChain: [][]byte{
				[]byte(rawCert),
			},
			expiresAt: time.Now().Add(time.Minute),
			req: &svidpb.MintX509SVIDRequest{
				Csr: csrRaw,
				Ttl: 10,
			},
			spiffeID: spiffeID,
		}, {
			name: "empty CSR",
			err:  "request missing CSR",
			code: codes.InvalidArgument,
			msg:  "Request missing CSR",
			req: &svidpb.MintX509SVIDRequest{
				Csr: []byte{},
				Ttl: 10,
			},
		}, {
			name: "invalid CSR",
			err:  "invalid CSR: asn1: structure error: tags don't match",
			code: codes.InvalidArgument,
			msg:  "Invalid CSR",
			req: &svidpb.MintX509SVIDRequest{
				Csr: []byte("invalid CSR"),
				Ttl: 10,
			},
		}, {
			name: "service return error",
			err:  "some error",
			code: codes.Internal,
			msg:  "Invalid CSR",
			req: &svidpb.MintX509SVIDRequest{
				Csr: csrRaw,
				Ttl: 10,
			},
			serviceErr: "some error",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			// Setup service
			c.service.certChain = testCase.certChain
			c.service.id = testCase.spiffeID
			c.service.err = testCase.serviceErr
			c.service.expiresAt = testCase.expiresAt

			// Call mint
			resp, err := c.svidClient.MintX509SVID(ctx, testCase.req)

			// Verify expected error
			if testCase.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, testCase.code, testCase.err)
				require.Nil(t, resp)
				require.Equal(t, testCase.msg, c.logHook.LastEntry().Message)

				return
			}

			// Verify response
			require.NoError(t, err)

			require.Equal(t, testCase.spiffeID.TrustDomain().String(), resp.Svid.Id.TrustDomain)
			require.Equal(t, testCase.spiffeID.Path(), resp.Svid.Id.Path)
			require.Equal(t, testCase.expiresAt.UTC().Unix(), resp.Svid.ExpiresAt)
			require.Equal(t, testCase.certChain, resp.Svid.CertChain)

			c.logHook.Reset()
		})
	}
}

func TestBatchNewX509SVID(t *testing.T) {
	ctx := context.Background()

	// Setup Test
	c := setupTest(t)
	defer c.Close()

	spiffeID := spiffeid.Must("example.org", "workload1")

	// Create certificate request
	key := testkey.NewEC256(t)
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		URIs:               []*url.URL{spiffeID.URL()},
	}
	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrRaw)
	require.NoError(t, err)

	testCases := []struct {
		name string

		code           codes.Code
		err            string
		msg            string
		params         []*svidpb.NewX509SVIDParams
		rateLimiterErr error
		req            []*svid.BatchNewX509SVIDRequest
		resp           []*svid.BatchNewX509SVIDResponse
		serviceErr     string
	}{
		{
			name: "success",
			params: []*svidpb.NewX509SVIDParams{
				{
					EntryId: "entry1",
					Csr:     csrRaw,
				},
			},
			req: []*svid.BatchNewX509SVIDRequest{
				{
					EntryID: "entry1",
					Csr:     csr,
				},
			},
			resp: []*svid.BatchNewX509SVIDResponse{
				{
					Svid: &api.X509SVID{
						ID: spiffeID,
						CertChain: []*x509.Certificate{
							{Raw: []byte(rawCert)},
						},
						ExpiresAt: time.Now().Add(time.Minute),
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			// Configure service
			c.service.batchRequest = testCase.req
			c.service.batchResponse = testCase.resp
			c.service.err = testCase.serviceErr

			// Limiter expects count to be params length
			c.rateLimiter.count = len(testCase.params)
			c.rateLimiter.err = testCase.rateLimiterErr

			// Call BatchNewX509SVID
			resp, err := c.svidClient.BatchNewX509SVID(ctx, &svidpb.BatchNewX509SVIDRequest{
				Params: testCase.params,
			})
			if testCase.err != "" {
				require.Nil(t, resp)
				spiretest.RequireGRPCStatusContains(t, err, testCase.code, testCase.err)
				require.Equal(t, testCase.msg, c.logHook.LastEntry().Message)
				require.EqualError(t, err, testCase.err)
				return
			}

			// Validate response
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Len(t, resp.Results, len(testCase.resp))

			for i, result := range resp.Results {
				expected := testCase.resp[i]

				switch {
				case result.Status != nil:
					expectedStatus, ok := status.FromError(expected.Err)
					require.True(t, ok)

					assert.Equal(t, expectedStatus.Code(), result.Status.Code)
					assert.Equal(t, expectedStatus.Message(), result.Status.Message)
					assert.Nil(t, result.Bundle)
				default:
					id := expected.Svid.ID
					assert.Equal(t, id.TrustDomain().String(), result.Bundle.Id.TrustDomain)
					assert.Equal(t, id.Path(), result.Bundle.Id.Path)
					assert.Equal(t, expected.Svid.ExpiresAt.UTC().Unix(), result.Bundle.ExpiresAt)
					var bundleCertChain [][]byte
					for _, certChain := range expected.Svid.CertChain {
						bundleCertChain = append(bundleCertChain, certChain.Raw)
					}
					assert.Equal(t, bundleCertChain, result.Bundle.CertChain)
				}
			}

			c.logHook.Reset()
		})
	}
}

type FakeService struct {
	svid.Service

	tb            testing.TB
	id            spiffeid.ID
	certChain     [][]byte
	code          codes.Code
	batchRequest  []*svid.BatchNewX509SVIDRequest
	batchResponse []*svid.BatchNewX509SVIDResponse
	err           string
	expiresAt     time.Time
}

func (s *FakeService) MintX509SVID(context.Context, *x509.CertificateRequest, time.Duration) (*api.X509SVID, error) {
	if s.err != "" {
		return nil, status.Error(codes.Internal, s.err)
	}

	var certs []*x509.Certificate
	for _, cert := range s.certChain {
		certs = append(certs, &x509.Certificate{Raw: cert})
	}
	return &api.X509SVID{ID: s.id, CertChain: certs, ExpiresAt: s.expiresAt}, nil
}

func (s *FakeService) BatchNewX509SVID(ctx context.Context, req []*svid.BatchNewX509SVIDRequest) ([]*svid.BatchNewX509SVIDResponse, error) {
	if s.err != "" {
		return nil, status.Error(s.code, s.err)
	}

	require.Equal(s.tb, s.batchRequest, req)

	return s.batchResponse, nil
}

type serverTest struct {
	svidClient  svidpb.SVIDClient
	service     *FakeService
	logHook     *test.Hook
	rateLimiter *fakeRateLimiter
	done        func()
}

func (c *serverTest) Close() {
	c.done()
}

func setupTest(t *testing.T) *serverTest {
	fakeService := &FakeService{}
	log, logHook := test.NewNullLogger()
	rateLimiter := &fakeRateLimiter{}
	registerFn := func(s *grpc.Server) {
		svid.RegisterService(s, fakeService)
	}

	contextFn := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		ctx = rpccontext.WithRateLimiter(ctx, rateLimiter)
		return ctx
	}

	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)

	return &serverTest{
		svidClient:  svidpb.NewSVIDClient(conn),
		done:        done,
		logHook:     logHook,
		rateLimiter: rateLimiter,
		service:     fakeService,
	}
}

type fakeRateLimiter struct {
	count int
	err   error
}

func (f *fakeRateLimiter) RateLimit(ctx context.Context, count int) error {
	if f.count != count {
		return fmt.Errorf("rate limiter got %d but expected %d", count, f.count)
	}

	return f.err
}
