package svid_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
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

func TestMintJWTSVID(t *testing.T) {
	ctx := context.Background()

	c := setupTest(t)
	defer c.Close()

	spiffeID := spiffeid.Must("example.org", "workload1")

	testCases := []struct {
		name string

		req        *svidpb.MintJWTSVIDRequest
		err        string
		code       codes.Code
		issuedAt   time.Time
		expiresAt  time.Time
		logMsg     string
		serviceErr string
		token      string
		spiffeID   spiffeid.ID
	}{
		{
			name:      "success",
			spiffeID:  spiffeID,
			token:     "token",
			issuedAt:  time.Now(),
			expiresAt: time.Now().Add(time.Minute),
			req: &svidpb.MintJWTSVIDRequest{
				SpiffeId: spiffeID.String(),
				Audience: []string{"audience1", "audience2"},
				Ttl:      60,
			},
		},
		{
			name:   "request missing SPIFFE ID",
			err:    "spiffeid: ID is empty",
			logMsg: "Failed to parse SPIFFE ID",
			code:   codes.InvalidArgument,
			req: &svidpb.MintJWTSVIDRequest{
				Audience: []string{"audience1", "audience2"},
			},
		},
		{
			name:   "request missing audience",
			err:    "request must specify at least one audience",
			logMsg: "Request must specify at least one audience",
			code:   codes.InvalidArgument,
			req: &svidpb.MintJWTSVIDRequest{
				SpiffeId: spiffeID.String(),
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			// Setup service
			c.service.err = testCase.serviceErr
			c.service.id = testCase.spiffeID
			c.service.token = testCase.token
			c.service.issuedAt = testCase.issuedAt
			c.service.expiresAt = testCase.expiresAt

			// Call MintJWTSVID
			resp, err := c.svidClient.MintJWTSVID(ctx, testCase.req)

			// Verify expected error
			if testCase.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, testCase.code, testCase.err)
				require.Nil(t, resp)
				require.Equal(t, testCase.logMsg, c.logHook.LastEntry().Message)

				return
			}

			// Verify response
			require.NoError(t, err)
			require.Equal(t, testCase.spiffeID.TrustDomain().String(), resp.Svid.Id.TrustDomain)
			require.Equal(t, testCase.spiffeID.Path(), resp.Svid.Id.Path)
			require.Equal(t, testCase.token, resp.Svid.Token)
			require.Equal(t, testCase.issuedAt.UTC().Unix(), resp.Svid.IssuedAt)
			require.Equal(t, testCase.expiresAt.UTC().Unix(), resp.Svid.ExpiresAt)

			c.logHook.Reset()
		})
	}
}

type FakeService struct {
	svid.Service

	id        spiffeid.ID
	certChain [][]byte
	err       string
	expiresAt time.Time
	issuedAt  time.Time
	token     string
}

func (s *FakeService) MintX509SVID(context.Context, *x509.CertificateRequest, time.Duration) (*api.X509SVID, error) {
	if s.err != "" {
		return nil, status.Errorf(codes.Internal, s.err)
	}

	var certs []*x509.Certificate
	for _, cert := range s.certChain {
		certs = append(certs, &x509.Certificate{Raw: cert})
	}
	return &api.X509SVID{ID: s.id, CertChain: certs, ExpiresAt: s.expiresAt}, nil
}

func (s *FakeService) MintJWTSVID(ctx context.Context, id spiffeid.ID, audience []string, ttl time.Duration) (*api.JWTSVID, error) {
	if s.err != "" {
		return nil, status.Errorf(codes.Internal, s.err)
	}

	return &api.JWTSVID{ID: s.id, Token: s.token, ExpiresAt: s.expiresAt, IssuedAt: s.issuedAt}, nil
}

type serverTest struct {
	svidClient svidpb.SVIDClient
	service    *FakeService
	logHook    *test.Hook
	done       func()
}

func (c *serverTest) Close() {
	c.done()
}

func setupTest(t *testing.T) *serverTest {
	fakeService := &FakeService{}
	log, logHook := test.NewNullLogger()
	registerFn := func(s *grpc.Server) {
		svid.RegisterService(s, fakeService)
	}

	contextFn := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)

		return ctx
	}

	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)

	return &serverTest{
		svidClient: svidpb.NewSVIDClient(conn),
		done:       done,
		logHook:    logHook,
		service:    fakeService,
	}
}
