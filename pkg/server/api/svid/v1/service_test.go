package svid_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/api/svid/v1"
	svidpb "github.com/spiffe/spire/proto/spire-next/api/server/svid/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	testKey    = testkey.MustEC256()
	td         = spiffeid.RequireTrustDomainFromString("example.org")
	agentID    = td.NewID("agent")
	workloadID = td.NewID("workload1")
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
					spiffeid.Must("example.org", "workload2").URL(),
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
			code:        codes.Internal,
			audience:    []string{"AUDIENCE"},
			err:         "failed to sign JWT-SVID: JWT key is not available for signing",
			logMsg:      "Failed to sign JWT-SVID",
			failMinting: true,
			expiresAt:   expiresAt,
			id:          workloadID,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.ca.SetJWTKey(jwtKey)
			if tt.failMinting {
				test.ca.SetJWTKey(nil)
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

			// Verify response
			verifyJWTSVIDResponse(t, resp.Svid, tt.id, tt.audience, issuedAt, tt.expiresAt, expiresAt, tt.ttl)
		})
	}
}

func TestServiceNewJWTSVID(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	entry := &types.Entry{
		Id:       "agent-entry-id",
		ParentId: api.ProtoFromID(agentID),
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"},
	}
	entryWithTTL := &types.Entry{
		Id:       "agent-entry-ttl-id",
		ParentId: api.ProtoFromID(agentID),
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-ttl"},
		Ttl:      10,
	}
	invalidEntry := &types.Entry{
		Id:       "invalid-entry",
		ParentId: api.ProtoFromID(agentID),
		SpiffeId: &types.SPIFFEID{},
	}

	test.ef.entries = []*types.Entry{entry, entryWithTTL, invalidEntry}
	jwtKey := test.ca.JWTKey()
	now := test.ca.Clock().Now().UTC()

	issuedAt := now
	expiresAt := now.Add(test.ca.JWTSVIDTTL())

	for _, tt := range []struct {
		name string

		code           codes.Code
		err            string
		logMsg         string
		expiresAt      time.Time
		entry          *types.Entry
		failMinting    bool
		failCallerID   bool
		audience       []string
		rateLimiterErr error
	}{
		{
			name:      "success",
			audience:  []string{"AUDIENCE"},
			entry:     entry,
			expiresAt: expiresAt,
		},
		{
			name:      "success custom TTL",
			audience:  []string{"AUDIENCE"},
			entry:     entryWithTTL,
			expiresAt: now.Add(10 * time.Second),
		},
		{
			name:     "no SPIFFE ID",
			code:     codes.InvalidArgument,
			audience: []string{"AUDIENCE"},
			entry:    invalidEntry,
			err:      "spiffeid: trust domain is empty",
			logMsg:   "Failed to parse SPIFFE ID",
		},
		{
			name:   "no audience",
			code:   codes.InvalidArgument,
			err:    "at least one audience is required",
			logMsg: "At least one audience is required",
			entry:  entry,
		},
		{
			name:         "no caller id",
			code:         codes.Internal,
			audience:     []string{"AUDIENCE"},
			err:          "caller ID missing from request context",
			logMsg:       "Caller ID missing from request context",
			entry:        entry,
			failCallerID: true,
		},
		{
			name:           "rate limit fails",
			code:           codes.Internal,
			audience:       []string{"AUDIENCE"},
			entry:          entry,
			err:            "rate limit error",
			logMsg:         "Rejecting request due to JWT signing request rate limiting",
			rateLimiterErr: status.Error(codes.Internal, "rate limit error"),
		},
		{
			name:     "entry not found",
			code:     codes.NotFound,
			audience: []string{"AUDIENCE"},
			entry:    &types.Entry{Id: "non-existent-entry"},
			err:      "entry not found or not authorized",
			logMsg:   "Invalid request: entry not found",
		},
		{
			name:        "fails minting",
			code:        codes.Internal,
			audience:    []string{"AUDIENCE"},
			entry:       entry,
			err:         "failed to sign JWT-SVID: JWT key is not available for signing",
			logMsg:      "Failed to sign JWT-SVID",
			failMinting: true,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.ca.SetJWTKey(jwtKey)
			if tt.failMinting {
				test.ca.SetJWTKey(nil)
			}

			test.rateLimiter.count = 1
			test.rateLimiter.err = tt.rateLimiterErr
			test.withCallerID = !tt.failCallerID

			resp, err := test.client.NewJWTSVID(context.Background(), &svidpb.NewJWTSVIDRequest{
				EntryId:  tt.entry.Id,
				Audience: tt.audience,
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
			verifyJWTSVIDResponse(t, resp.Svid,
				spiffeid.Must(tt.entry.SpiffeId.TrustDomain, tt.entry.SpiffeId.Path),
				tt.audience,
				issuedAt,
				tt.expiresAt,
				expiresAt,
				time.Duration(tt.entry.Ttl)*time.Second)
		})
	}
}

func TestServiceBatchNewX509SVID(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	workloadEntry := &types.Entry{
		Id:       "workload",
		ParentId: api.ProtoFromID(agentID),
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "workload1"},
	}
	dnsEntry := &types.Entry{
		Id:       "dns",
		ParentId: api.ProtoFromID(agentID),
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "dns"},
		DnsNames: []string{"entryDNS1", "entryDNS2"},
	}
	ttlEntry := &types.Entry{
		Id:       "ttl",
		ParentId: api.ProtoFromID(agentID),
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "ttl"},
		Ttl:      10,
	}
	invalidEntry := &types.Entry{
		Id:       "invalid",
		ParentId: api.ProtoFromID(agentID),
	}
	test.ef.entries = []*types.Entry{workloadEntry, dnsEntry, ttlEntry, invalidEntry}

	x509CA := test.ca.X509CA()
	now := test.ca.Clock().Now().UTC()

	_, invalidCsrErr := x509.ParseCertificateRequest([]byte{1, 2, 3})
	require.Error(t, invalidCsrErr)

	type expectResult struct {
		entry  *types.Entry
		status *types.Status
	}

	for _, tt := range []struct {
		name           string
		code           codes.Code
		reqs           []string
		err            string
		expectLogs     []spiretest.LogEntry
		expectResults  []*expectResult
		failSigning    bool
		failCallerID   bool
		fetcherErr     string
		mutateCSR      func([]byte) []byte
		rateLimiterErr error
	}{
		{
			name: "success",
			reqs: []string{workloadEntry.Id},
			expectResults: []*expectResult{
				{
					entry: workloadEntry,
				},
			},
		}, {
			name: "custom ttl",
			reqs: []string{ttlEntry.Id},
			expectResults: []*expectResult{
				{
					entry: ttlEntry,
				},
			},
		}, {
			name: "custom dns",
			reqs: []string{dnsEntry.Id},
			expectResults: []*expectResult{
				{
					entry: dnsEntry,
				},
			},
		}, {
			name: "keep request order",
			reqs: []string{workloadEntry.Id, invalidEntry.Id, dnsEntry.Id},
			expectResults: []*expectResult{
				{
					entry: workloadEntry,
				},
				{
					status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "entry has malformed SPIFFE ID",
					},
				},
				{
					entry: dnsEntry,
				},
			},
		}, {
			name: "no caller id",
			reqs: []string{workloadEntry.Id},
			code: codes.Internal,
			err:  "caller ID missing from request context",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Caller ID missing from request context",
				},
			},
			failCallerID: true,
		}, {
			name: "no parameters",
			reqs: []string{},
			code: codes.InvalidArgument,
			err:  "request missing parameters",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Request missing parameters",
				},
			},
		}, {
			name: "rate limit fails",
			reqs: []string{workloadEntry.Id},
			code: codes.Internal,
			err:  "rate limit error",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Rejecting request due to certificate signing rate limiting",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = Internal desc = rate limit error",
					},
				},
			},
			rateLimiterErr: status.Error(codes.Internal, "rate limit error"),
		}, {
			name:       "fetch entries fails",
			reqs:       []string{workloadEntry.Id},
			code:       codes.Internal,
			err:        "failed to fetch registration entries",
			fetcherErr: "fetcher fails",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch registration entries",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = Internal desc = fetcher fails",
					},
				},
			},
		}, {
			name: "missing entry ID",
			reqs: []string{""},
			expectResults: []*expectResult{
				{
					status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "missing entry ID",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: missing entry ID",
				},
			},
		}, {
			name: "missing CSR",
			reqs: []string{workloadEntry.Id},
			expectResults: []*expectResult{
				{
					status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: `missing CSR`,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: missing CSR",
				},
			},
			mutateCSR: func([]byte) []byte {
				return []byte{}
			},
		}, {
			name: "entry not found",
			reqs: []string{"invalid entry"},
			expectResults: []*expectResult{
				{
					status: &types.Status{
						Code:    int32(codes.NotFound),
						Message: "entry not found or not authorized",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: entry not found or not authorized",
					Data: logrus.Fields{
						telemetry.RegistrationID: "invalid entry",
					},
				},
			},
		}, {
			name: "malformed CSR",
			reqs: []string{workloadEntry.Id},
			expectResults: []*expectResult{
				{
					status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "malformed CSR: asn1:",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: malformed CSR",
					Data: logrus.Fields{
						telemetry.RegistrationID: "workload",
						logrus.ErrorKey:          invalidCsrErr.Error(),
					},
				},
			},
			mutateCSR: func([]byte) []byte {
				return []byte{1, 2, 3}
			},
		}, {
			name: "invalid signature",
			reqs: []string{workloadEntry.Id},
			expectResults: []*expectResult{
				{
					status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "invalid CSR signature",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: invalid CSR signature",
					Data: logrus.Fields{
						telemetry.RegistrationID: "workload",
						logrus.ErrorKey:          "x509: ECDSA verification failure",
					},
				},
			},
			mutateCSR: func(csr []byte) []byte {
				// 4 bytes from the end should be back far enough to be in the
				// signature bytes.
				csr[len(csr)-4]++
				return csr
			},
		}, {
			name: "malformed SPIFFE ID",
			reqs: []string{invalidEntry.Id},
			expectResults: []*expectResult{
				{
					status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "entry has malformed SPIFFE ID",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Entry has malformed SPIFFE ID",
					Data: logrus.Fields{
						telemetry.RegistrationID: "invalid",
						logrus.ErrorKey:          "request must specify SPIFFE ID",
					},
				},
			},
		}, {
			name: "signing fails",
			reqs: []string{workloadEntry.Id},
			expectResults: []*expectResult{
				{
					status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "failed to sign X509-SVID: X509 CA is not available for signing",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to sign X509-SVID",
					Data: logrus.Fields{
						telemetry.RegistrationID: "workload",
						logrus.ErrorKey:          "X509 CA is not available for signing",
						telemetry.SPIFFEID:       workloadID.String(),
					},
				},
			},
			failSigning: true,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()

			// Set x509CA used when signing SVID
			test.ca.SetX509CA(x509CA)
			if tt.failSigning {
				test.ca.SetX509CA(nil)
			}
			ctx := context.Background()

			test.rateLimiter.count = len(tt.reqs)
			test.rateLimiter.err = tt.rateLimiterErr

			test.withCallerID = !tt.failCallerID
			test.ef.err = tt.fetcherErr

			var params []*svidpb.NewX509SVIDParams
			for _, entryID := range tt.reqs {
				// Create CSR
				csr := createCSR(t, &x509.CertificateRequest{})
				if tt.mutateCSR != nil {
					csr = tt.mutateCSR(csr)
				}
				params = append(params, &svidpb.NewX509SVIDParams{
					EntryId: entryID,
					Csr:     csr,
				})
			}

			// Batch svids
			resp, err := test.client.BatchNewX509SVID(ctx, &svidpb.BatchNewX509SVIDRequest{
				Params: params,
			})
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)
				spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)

				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotEmpty(t, resp.Results)

			for i, result := range resp.Results {
				expect := tt.expectResults[i]

				if expect.status != nil {
					require.Nil(t, result.Bundle)
					require.Equal(t, expect.status.Code, result.Status.Code)
					require.Contains(t, result.Status.Message, expect.status.Message)

					if tt.expectLogs != nil {
						spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
					}
					continue
				}

				require.NotNil(t, result.Bundle)

				entry := expect.entry

				require.Equal(t, entry.SpiffeId.TrustDomain, result.Bundle.Id.TrustDomain)
				require.Equal(t, entry.SpiffeId.Path, result.Bundle.Id.Path)

				certChain, err := x509util.RawCertsToCertificates(result.Bundle.CertChain)
				require.NoError(t, err)
				require.NotEmpty(t, certChain)
				svid := certChain[0]

				entryID := spiffeid.Must(entry.SpiffeId.TrustDomain, entry.SpiffeId.Path)
				require.Equal(t, []*url.URL{entryID.URL()}, svid.URIs)

				// Use entry ttl when defined
				ttl := test.ca.X509SVIDTTL()
				if entry.Ttl != 0 {
					ttl = time.Duration(entry.Ttl) * time.Second
				}
				expiresAt := now.Add(ttl)

				require.Equal(t, expiresAt, svid.NotAfter)
				require.Equal(t, expiresAt.UTC().Unix(), result.Bundle.ExpiresAt)

				require.Equal(t, entry.DnsNames, svid.DNSNames)

				expectedSubject := &pkix.Name{Country: []string{"US"}, Organization: []string{"SPIRE"}}
				if len(entry.DnsNames) > 0 {
					name := entry.DnsNames[0]

					expectedSubject.CommonName = name
					require.Equal(t, name, svid.Subject.CommonName)
				}

				require.Equal(t, expectedSubject.String(), svid.Subject.String())
			}
		})
	}
}

type serviceTest struct {
	client       svidpb.SVIDClient
	ef           *entryFetcher
	ca           *fakeserverca.CA
	logHook      *test.Hook
	rateLimiter  *fakeRateLimiter
	withCallerID bool
	done         func()
}

func (c *serviceTest) Cleanup() {
	c.done()
}

func setupServiceTest(t *testing.T) *serviceTest {
	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	ca := fakeserverca.New(t, trustDomain.String(), &fakeserverca.Options{})
	ef := &entryFetcher{}
	rateLimiter := &fakeRateLimiter{}
	service := svid.New(svid.Config{
		EntryFetcher: ef,
		ServerCA:     ca,
		TrustDomain:  trustDomain,
	})

	log, logHook := test.NewNullLogger()
	registerFn := func(s *grpc.Server) {
		svid.RegisterService(s, service)
	}

	test := &serviceTest{
		ca:          ca,
		ef:          ef,
		logHook:     logHook,
		rateLimiter: rateLimiter,
	}

	contextFn := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		ctx = rpccontext.WithRateLimiter(ctx, rateLimiter)
		if test.withCallerID {
			ctx = rpccontext.WithCallerID(ctx, agentID)
		}
		return ctx
	}

	// Set create client and add to test
	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)
	test.client = svidpb.NewSVIDClient(conn)
	test.done = done

	return test
}

func createCSR(tb testing.TB, template *x509.CertificateRequest) []byte {
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, testKey)
	require.NoError(tb, err)
	return csr
}

func verifyJWTSVIDResponse(t *testing.T, jwtsvid *types.JWTSVID, id spiffeid.ID, audience []string, issuedAt, expiresAt, defaultExpiresAt time.Time, ttl time.Duration) {
	require.NotNil(t, jwtsvid)
	require.NotEmpty(t, jwtsvid.Token)

	token, err := jwt.ParseSigned(jwtsvid.Token)
	require.NoError(t, err)

	var claims jwt.Claims
	err = token.UnsafeClaimsWithoutVerification(&claims)
	require.NoError(t, err)

	jwtsvidID, err := api.IDFromProto(jwtsvid.Id)
	require.NoError(t, err)
	require.Equal(t, id, jwtsvidID)
	require.Equal(t, id.String(), claims.Subject)

	require.Equal(t, jwt.Audience(audience), claims.Audience)

	require.NotNil(t, claims.IssuedAt)
	require.Equal(t, issuedAt.Unix(), jwtsvid.IssuedAt)
	require.Equal(t, issuedAt.Unix(), int64(*claims.IssuedAt))

	require.NotNil(t, claims.Expiry)
	if ttl == 0 {
		require.Equal(t, defaultExpiresAt.Unix(), jwtsvid.ExpiresAt)
		require.Equal(t, defaultExpiresAt.Unix(), int64(*claims.Expiry))
	} else {
		require.Equal(t, expiresAt.Unix(), jwtsvid.ExpiresAt)
		require.Equal(t, expiresAt.Unix(), int64(*claims.Expiry))
	}
}

type entryFetcher struct {
	err     string
	entries []*types.Entry
}

func (f *entryFetcher) FetchAuthorizedEntries(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
	if f.err != "" {
		return nil, status.Error(codes.Internal, f.err)
	}

	caller, ok := rpccontext.CallerID(ctx)
	if !ok {
		return nil, errors.New("no caller ID on context")
	}

	if caller != agentID {
		return nil, fmt.Errorf("provided caller id is different to expected")
	}

	return f.entries, nil
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
