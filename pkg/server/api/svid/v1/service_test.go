package svid_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	svid "github.com/spiffe/spire/pkg/server/api/svid/v1"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
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
	agentID    = spiffeid.RequireFromPath(td, "/agent")
	workloadID = spiffeid.RequireFromPath(td, "/workload1")
)

func TestServiceMintX509SVID(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	now := test.ca.Clock().Now().UTC()
	expiredAt := now.Add(test.ca.X509SVIDTTL())
	expiresAtStr := expiredAt.Format(time.RFC3339)
	customExpiresAt := now.Add(10 * time.Second)
	expiresAtCustomStr := customExpiresAt.Format(time.RFC3339)

	for _, tt := range []struct {
		name        string
		code        codes.Code
		csrTemplate *x509.CertificateRequest
		dns         []string
		err         string
		expiredAt   time.Time
		subject     string
		ttl         time.Duration
		failMinting bool
		mutateCSR   func([]byte) []byte
		expectLogs  func([]byte) []spiretest.LogEntry
	}{
		{
			name: "success",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{workloadID.URL()},
			},
			expiredAt: expiredAt,
			subject:   "O=SPIRE,C=US,2.5.4.45=#13203835323763353230323837636461376436323561613834373664386538336561",
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:    "success",
							telemetry.Type:      "audit",
							telemetry.SPIFFEID:  "spiffe://example.org/workload1",
							telemetry.Csr:       api.HashByte(csr),
							telemetry.TTL:       "0",
							telemetry.DNSName:   "",
							telemetry.Subject:   "",
							telemetry.ExpiresAt: expiresAtStr,
						},
					},
				}
			},
		},
		{
			name: "custom ttl",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{workloadID.URL()},
			},
			expiredAt: customExpiresAt,
			subject:   "O=SPIRE,C=US,2.5.4.45=#13203835323763353230323837636461376436323561613834373664386538336561",
			ttl:       10 * time.Second,
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:    "success",
							telemetry.Type:      "audit",
							telemetry.SPIFFEID:  "spiffe://example.org/workload1",
							telemetry.Csr:       api.HashByte(csr),
							telemetry.TTL:       "10",
							telemetry.DNSName:   "",
							telemetry.Subject:   "",
							telemetry.ExpiresAt: expiresAtCustomStr,
						},
					},
				}
			},
		},
		{
			name: "custom dns",
			csrTemplate: &x509.CertificateRequest{
				URIs:     []*url.URL{workloadID.URL()},
				DNSNames: []string{"dns1", "dns2"},
			},
			dns:       []string{"dns1", "dns2"},
			expiredAt: expiredAt,
			subject:   "CN=dns1,O=SPIRE,C=US,2.5.4.45=#13203835323763353230323837636461376436323561613834373664386538336561",
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:    "success",
							telemetry.Type:      "audit",
							telemetry.SPIFFEID:  "spiffe://example.org/workload1",
							telemetry.Csr:       api.HashByte(csr),
							telemetry.TTL:       "0",
							telemetry.DNSName:   "dns1,dns2",
							telemetry.Subject:   "",
							telemetry.ExpiresAt: expiresAtStr,
						},
					},
				}
			},
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
			subject:   "O=ORG,C=EN+C=US,2.5.4.45=#13203835323763353230323837636461376436323561613834373664386538336561",
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:    "success",
							telemetry.Type:      "audit",
							telemetry.SPIFFEID:  "spiffe://example.org/workload1",
							telemetry.Csr:       api.HashByte(csr),
							telemetry.TTL:       "0",
							telemetry.DNSName:   "",
							telemetry.Subject:   "O=ORG,C=EN+C=US",
							telemetry.ExpiresAt: expiresAtStr,
						},
					},
				}
			},
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
			subject:   "CN=dns1,O=ORG,C=EN+C=US,2.5.4.45=#13203835323763353230323837636461376436323561613834373664386538336561",
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:    "success",
							telemetry.Type:      "audit",
							telemetry.SPIFFEID:  "spiffe://example.org/workload1",
							telemetry.Csr:       api.HashByte(csr),
							telemetry.TTL:       "0",
							telemetry.DNSName:   "dns1,dns2",
							telemetry.Subject:   "O=ORG,C=EN+C=US",
							telemetry.ExpiresAt: expiresAtStr,
						},
					},
				}
			},
		},
		{
			name: "no CSR",
			code: codes.InvalidArgument,
			err:  "missing CSR",
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: missing CSR",
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "InvalidArgument",
							telemetry.StatusMessage: "missing CSR",
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TTL:           "0",
						},
					},
				}
			},
		},
		{
			name: "malformed CSR",
			code: codes.InvalidArgument,
			mutateCSR: func(csr []byte) []byte {
				return []byte{1, 2, 3}
			},
			err: "malformed CSR: asn1:",
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				_, err := x509.ParseCertificateRequest(csr)

				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: malformed CSR",
						Data: logrus.Fields{
							logrus.ErrorKey: err.Error(),
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "InvalidArgument",
							telemetry.StatusMessage: fmt.Sprintf("malformed CSR: %v", err),
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TTL:           "0",
						},
					},
				}
			},
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
			err:  "failed to verify CSR signature",
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: failed to verify CSR signature",
						Data: logrus.Fields{
							logrus.ErrorKey: "x509: ECDSA verification failure",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "InvalidArgument",
							telemetry.StatusMessage: "failed to verify CSR signature: x509: ECDSA verification failure",
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TTL:           "0",
						},
					},
				}
			},
		},
		{
			name: "no URIs",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{},
			},
			code: codes.InvalidArgument,
			err:  "CSR URI SAN is required",
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: CSR URI SAN is required",
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "InvalidArgument",
							telemetry.StatusMessage: "CSR URI SAN is required",
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TTL:           "0",
						},
					},
				}
			},
		},
		{
			name: "multiple URIs",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{
					workloadID.URL(),
					{Scheme: "spiffe", Host: "example.org", Path: "/workload2"},
				},
			},
			code: codes.InvalidArgument,
			err:  "only one URI SAN is expected",
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: only one URI SAN is expected",
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "InvalidArgument",
							telemetry.StatusMessage: "only one URI SAN is expected",
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TTL:           "0",
						},
					},
				}
			},
		},
		{
			name: "invalid SPIFFE ID",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{
					{Scheme: "http", Host: "localhost"},
				},
			},
			code: codes.InvalidArgument,
			err:  "CSR URI SAN is invalid: scheme is missing or invalid",
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: CSR URI SAN is invalid",
						Data: logrus.Fields{
							logrus.ErrorKey: "scheme is missing or invalid",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "InvalidArgument",
							telemetry.StatusMessage: "CSR URI SAN is invalid: scheme is missing or invalid",
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TTL:           "0",
						},
					},
				}
			},
		},
		{
			name: "different trust domain",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{{Scheme: "spiffe", Host: "another.org", Path: "/workload1"}},
			},
			code: codes.InvalidArgument,
			err:  `CSR URI SAN is invalid: "spiffe://another.org/workload1" is not a member of trust domain "example.org"`,
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: CSR URI SAN is invalid",
						Data: logrus.Fields{
							logrus.ErrorKey: `"spiffe://another.org/workload1" is not a member of trust domain "example.org"`,
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "InvalidArgument",
							telemetry.StatusMessage: `CSR URI SAN is invalid: "spiffe://another.org/workload1" is not a member of trust domain "example.org"`,
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TTL:           "0",
						},
					},
				}
			},
		},
		{
			name: "SPIFFE ID is not for a workload in the trust domain",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{{Scheme: "spiffe", Host: "example.org"}},
			},
			code: codes.InvalidArgument,
			err:  `CSR URI SAN is invalid: "spiffe://example.org" is not a workload in trust domain "example.org"; path is empty`,
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: CSR URI SAN is invalid",
						Data: logrus.Fields{
							logrus.ErrorKey: `"spiffe://example.org" is not a workload in trust domain "example.org"; path is empty`,
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "InvalidArgument",
							telemetry.StatusMessage: `CSR URI SAN is invalid: "spiffe://example.org" is not a workload in trust domain "example.org"; path is empty`,
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TTL:           "0",
						},
					},
				}
			},
		},
		{
			name: "invalid DNS",
			csrTemplate: &x509.CertificateRequest{
				URIs:     []*url.URL{workloadID.URL()},
				DNSNames: []string{"abc-"},
			},
			code: codes.InvalidArgument,
			err:  "CSR DNS name is invalid: label does not match regex: abc-",
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: CSR DNS name is invalid",
						Data: logrus.Fields{
							logrus.ErrorKey: "label does not match regex: abc-",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "InvalidArgument",
							telemetry.StatusMessage: "CSR DNS name is invalid: label does not match regex: abc-",
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TTL:           "0",
						},
					},
				}
			},
		},
		{
			name: "signing fails",
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{workloadID.URL()},
			},
			code:        codes.Internal,
			err:         "failed to sign X509-SVID: oh no",
			failMinting: true,
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Failed to sign X509-SVID",
						Data: logrus.Fields{
							logrus.ErrorKey: "oh no",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "Internal",
							telemetry.StatusMessage: "failed to sign X509-SVID: oh no",
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TTL:           "0",
						},
					},
				}
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()

			if tt.failMinting {
				test.ca.SetError(errors.New("oh no"))
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
			resp, err := test.client.MintX509SVID(context.Background(), &svidv1.MintX509SVIDRequest{
				Csr: csr,
				Ttl: int32(tt.ttl / time.Second),
			})
			expectLogs := tt.expectLogs(csr)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), expectLogs)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotNil(t, resp.Svid)

			certChain, err := x509util.RawCertsToCertificates(resp.Svid.CertChain)
			require.NoError(t, err)
			require.NotEmpty(t, certChain)
			svid := certChain[0]

			id, err := api.TrustDomainWorkloadIDFromProto(context.Background(), td, resp.Svid.Id)
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

	now := test.ca.Clock().Now().UTC()
	issuedAt := now
	expiresAt := now.Add(test.ca.JWTSVIDTTL())

	for _, tt := range []struct {
		name string

		code        codes.Code
		err         string
		expiresAt   time.Time
		id          spiffeid.ID
		ttl         time.Duration
		failMinting bool
		audience    []string
		expectLogs  []spiretest.LogEntry
	}{
		{
			name:      "success",
			audience:  []string{"AUDIENCE"},
			expiresAt: expiresAt,
			id:        workloadID,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:   "success",
						telemetry.Type:     "audit",
						telemetry.Audience: "AUDIENCE",
						telemetry.SPIFFEID: "spiffe://example.org/workload1",
						telemetry.TTL:      "0",
					},
				},
			},
		},
		{
			name:      "success custom TTL",
			audience:  []string{"AUDIENCE"},
			ttl:       10 * time.Second,
			expiresAt: now.Add(10 * time.Second),
			id:        workloadID,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:   "success",
						telemetry.Type:     "audit",
						telemetry.Audience: "AUDIENCE",
						telemetry.SPIFFEID: "spiffe://example.org/workload1",
						telemetry.TTL:      "10",
					},
				},
			},
		},
		{
			name:     "bad id",
			code:     codes.InvalidArgument,
			audience: []string{"AUDIENCE"},
			id:       spiffeid.ID{},
			err:      "invalid SPIFFE ID: trust domain is missing",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid SPIFFE ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "trust domain is missing",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid SPIFFE ID: trust domain is missing",
						telemetry.Audience:      "AUDIENCE",
						telemetry.TTL:           "0",
					},
				},
			},
		},
		{
			name:     "invalid trust domain",
			code:     codes.InvalidArgument,
			audience: []string{"AUDIENCE"},
			id:       spiffeid.RequireFromString("spiffe://invalid.test/workload1"),
			err:      `invalid SPIFFE ID: "spiffe://invalid.test/workload1" is not a member of trust domain "example.org"`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid SPIFFE ID",
					Data: logrus.Fields{
						logrus.ErrorKey: `"spiffe://invalid.test/workload1" is not a member of trust domain "example.org"`,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: `invalid SPIFFE ID: "spiffe://invalid.test/workload1" is not a member of trust domain "example.org"`,
						telemetry.Audience:      "AUDIENCE",
						telemetry.TTL:           "0",
					},
				},
			},
		},
		{
			name:     "SPIFFE ID is not for a workload in the trust domain",
			code:     codes.InvalidArgument,
			audience: []string{"AUDIENCE"},
			id:       spiffeid.RequireFromString("spiffe://invalid.test"),
			err:      `invalid SPIFFE ID: "spiffe://invalid.test" is not a member of trust domain "example.org"`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid SPIFFE ID",
					Data: logrus.Fields{
						logrus.ErrorKey: `"spiffe://invalid.test" is not a member of trust domain "example.org"`,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: `invalid SPIFFE ID: "spiffe://invalid.test" is not a member of trust domain "example.org"`,
						telemetry.Audience:      "AUDIENCE",
						telemetry.TTL:           "0",
					},
				},
			},
		},
		{
			name:      "no audience",
			code:      codes.InvalidArgument,
			err:       "at least one audience is required",
			expiresAt: expiresAt,
			id:        workloadID,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: at least one audience is required",
					Data: logrus.Fields{
						telemetry.SPIFFEID: "spiffe://example.org/workload1",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "at least one audience is required",
						telemetry.SPIFFEID:      "spiffe://example.org/workload1",
						telemetry.TTL:           "0",
					},
				},
			},
		},
		{
			name:        "fails minting",
			code:        codes.Internal,
			audience:    []string{"AUDIENCE"},
			err:         "failed to sign JWT-SVID: oh no",
			failMinting: true,
			expiresAt:   expiresAt,
			id:          workloadID,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to sign JWT-SVID",
					Data: logrus.Fields{
						logrus.ErrorKey:    "oh no",
						telemetry.SPIFFEID: "spiffe://example.org/workload1",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to sign JWT-SVID: oh no",
						telemetry.Audience:      "AUDIENCE",
						telemetry.SPIFFEID:      "spiffe://example.org/workload1",
						telemetry.TTL:           "0",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()

			if tt.failMinting {
				test.ca.SetError(errors.New("oh no"))
			}

			resp, err := test.client.MintJWTSVID(context.Background(), &svidv1.MintJWTSVIDRequest{
				Id:       api.ProtoFromID(tt.id),
				Audience: tt.audience,
				Ttl:      int32(tt.ttl / time.Second),
			})

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			// Check for expected errors
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)

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
		Id:          "agent-entry-ttl-id",
		ParentId:    api.ProtoFromID(agentID),
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-ttl"},
		X509SvidTtl: 10,
	}
	entryWithJWTTTL := &types.Entry{
		Id:          "agent-entry-ttl-id",
		ParentId:    api.ProtoFromID(agentID),
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-ttl"},
		X509SvidTtl: 30, // ensure this isn't used
		JwtSvidTtl:  10,
	}
	invalidEntry := &types.Entry{
		Id:       "invalid-entry",
		ParentId: api.ProtoFromID(agentID),
		SpiffeId: &types.SPIFFEID{},
	}

	test.ef.entries = []*types.Entry{entry, entryWithTTL, entryWithJWTTTL, invalidEntry}
	now := test.ca.Clock().Now().UTC()

	issuedAt := now
	expiresAt := now.Add(test.ca.JWTSVIDTTL())

	for _, tt := range []struct {
		name string

		code           codes.Code
		err            string
		expiresAt      time.Time
		entry          *types.Entry
		failMinting    bool
		failCallerID   bool
		audience       []string
		rateLimiterErr error
		expectLogs     []spiretest.LogEntry
	}{
		{
			name:      "success",
			audience:  []string{"AUDIENCE"},
			entry:     entry,
			expiresAt: expiresAt,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "success",
						telemetry.Type:           "audit",
						telemetry.Audience:       "AUDIENCE",
						telemetry.RegistrationID: "agent-entry-id",
						telemetry.TTL:            "0",
					},
				},
			},
		},
		{
			name:      "success custom TTL",
			audience:  []string{"AUDIENCE"},
			entry:     entryWithTTL,
			expiresAt: now.Add(10 * time.Second),
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "success",
						telemetry.Type:           "audit",
						telemetry.Audience:       "AUDIENCE",
						telemetry.RegistrationID: "agent-entry-ttl-id",
						telemetry.TTL:            "10",
					},
				},
			},
		},
		{
			name:      "success custom JWT TTL",
			audience:  []string{"AUDIENCE"},
			entry:     entryWithJWTTTL,
			expiresAt: now.Add(10 * time.Second),
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "success",
						telemetry.Type:           "audit",
						telemetry.Audience:       "AUDIENCE",
						telemetry.RegistrationID: "agent-entry-ttl-id",
						telemetry.TTL:            "10",
					},
				},
			},
		},
		{
			name:     "no SPIFFE ID",
			code:     codes.InvalidArgument,
			audience: []string{"AUDIENCE"},
			entry:    invalidEntry,
			err:      "invalid SPIFFE ID: trust domain is missing",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid SPIFFE ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "trust domain is missing",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.StatusCode:     "InvalidArgument",
						telemetry.StatusMessage:  "invalid SPIFFE ID: trust domain is missing",
						telemetry.Audience:       "AUDIENCE",
						telemetry.RegistrationID: "invalid-entry",
					},
				},
			},
		},
		{
			name:  "no audience",
			code:  codes.InvalidArgument,
			err:   "at least one audience is required",
			entry: entry,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: at least one audience is required",
					Data: logrus.Fields{
						telemetry.SPIFFEID: "spiffe://example.org/agent",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.StatusCode:     "InvalidArgument",
						telemetry.StatusMessage:  "at least one audience is required",
						telemetry.Audience:       "",
						telemetry.RegistrationID: "agent-entry-id",
					},
				},
			},
		},
		{
			name:         "no caller id",
			code:         codes.Internal,
			audience:     []string{"AUDIENCE"},
			err:          "caller ID missing from request context",
			entry:        entry,
			failCallerID: true,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Caller ID missing from request context",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.StatusCode:     "Internal",
						telemetry.StatusMessage:  "caller ID missing from request context",
						telemetry.Audience:       "AUDIENCE",
						telemetry.RegistrationID: "agent-entry-id",
					},
				},
			},
		},
		{
			name:           "rate limit fails",
			code:           codes.Internal,
			audience:       []string{"AUDIENCE"},
			entry:          entry,
			err:            "rate limit error",
			rateLimiterErr: status.Error(codes.Internal, "rate limit error"),
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Rejecting request due to JWT signing request rate limiting",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = Internal desc = rate limit error",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.StatusCode:     "Internal",
						telemetry.StatusMessage:  "rejecting request due to JWT signing request rate limiting: rate limit error",
						telemetry.Audience:       "AUDIENCE",
						telemetry.RegistrationID: "agent-entry-id",
					},
				},
			},
		},
		{
			name:     "entry not found",
			code:     codes.NotFound,
			audience: []string{"AUDIENCE"},
			entry:    &types.Entry{Id: "non-existent-entry"},
			err:      "entry not found or not authorized",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Entry not found or not authorized",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.StatusCode:     "NotFound",
						telemetry.StatusMessage:  "entry not found or not authorized",
						telemetry.Audience:       "AUDIENCE",
						telemetry.RegistrationID: "non-existent-entry",
					},
				},
			},
		},
		{
			name:        "fails minting",
			code:        codes.Internal,
			audience:    []string{"AUDIENCE"},
			entry:       entry,
			err:         "failed to sign JWT-SVID: oh no",
			failMinting: true,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to sign JWT-SVID",
					Data: logrus.Fields{
						logrus.ErrorKey:    "oh no",
						telemetry.SPIFFEID: "spiffe://example.org/agent",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.StatusCode:     "Internal",
						telemetry.StatusMessage:  "failed to sign JWT-SVID: oh no",
						telemetry.Audience:       "AUDIENCE",
						telemetry.RegistrationID: "agent-entry-id",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()

			if tt.failMinting {
				test.ca.SetError(errors.New("oh no"))
			}

			test.rateLimiter.count = 1
			test.rateLimiter.err = tt.rateLimiterErr
			test.withCallerID = !tt.failCallerID

			resp, err := test.client.NewJWTSVID(context.Background(), &svidv1.NewJWTSVIDRequest{
				EntryId:  tt.entry.Id,
				Audience: tt.audience,
			})

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			// Check for expected errors
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)

				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotNil(t, resp.Svid)

			// Verify response
			verifyJWTSVIDResponse(t, resp.Svid,
				idutil.RequireIDFromProto(tt.entry.SpiffeId),
				tt.audience,
				issuedAt,
				tt.expiresAt,
				expiresAt,
				time.Duration(tt.entry.X509SvidTtl)*time.Second)
		})
	}
}

func TestServiceBatchNewX509SVID(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	workloadEntry := &types.Entry{
		Id:       "workload",
		ParentId: api.ProtoFromID(agentID),
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload1"},
	}
	dnsEntry := &types.Entry{
		Id:       "dns",
		ParentId: api.ProtoFromID(agentID),
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/dns"},
		DnsNames: []string{"entryDNS1", "entryDNS2"},
	}
	ttlEntry := &types.Entry{
		Id:          "ttl",
		ParentId:    api.ProtoFromID(agentID),
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/ttl"},
		X509SvidTtl: 10,
		JwtSvidTtl:  30, // ensures this is ignored
	}
	x509TtlEntry := &types.Entry{
		Id:          "x509ttl",
		ParentId:    api.ProtoFromID(agentID),
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/ttl"},
		X509SvidTtl: 50,
		JwtSvidTtl:  30, // ensures this is ignored
	}
	invalidEntry := &types.Entry{
		Id:       "invalid",
		ParentId: api.ProtoFromID(agentID),
	}
	test.ef.entries = []*types.Entry{workloadEntry, dnsEntry, ttlEntry, x509TtlEntry, invalidEntry}

	now := test.ca.Clock().Now().UTC()

	expiresAtFromTTLEntry := now.Add(time.Duration(ttlEntry.X509SvidTtl) * time.Second).Unix()
	expiresAtFromTTLEntryStr := strconv.FormatInt(expiresAtFromTTLEntry, 10)
	expiresAtFromX509TTLEntry := now.Add(time.Duration(x509TtlEntry.X509SvidTtl) * time.Second).Unix()
	expiresAtFromX509TTLEntryStr := strconv.FormatInt(expiresAtFromX509TTLEntry, 10)
	expiresAtFromCA := now.Add(test.ca.X509SVIDTTL()).Unix()
	expiresAtFromCAStr := strconv.FormatInt(expiresAtFromCA, 10)

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
		expectLogs     func(map[string][]byte) []spiretest.LogEntry
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
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "workload",
							telemetry.Csr:            api.HashByte(m["workload"]),
							telemetry.ExpiresAt:      expiresAtFromCAStr,
						},
					},
				}
			},
		}, {
			name: "custom ttl",
			reqs: []string{ttlEntry.Id},
			expectResults: []*expectResult{
				{
					entry: ttlEntry,
				},
			},
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "ttl",
							telemetry.Csr:            api.HashByte(m["ttl"]),
							telemetry.ExpiresAt:      expiresAtFromTTLEntryStr,
						},
					},
				}
			},
		}, {
			name: "custom x509 ttl",
			reqs: []string{x509TtlEntry.Id},
			expectResults: []*expectResult{
				{
					entry: x509TtlEntry,
				},
			},
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "x509ttl",
							telemetry.Csr:            api.HashByte(m["x509ttl"]),
							telemetry.ExpiresAt:      expiresAtFromX509TTLEntryStr,
						},
					},
				}
			},
		}, {
			name: "custom dns",
			reqs: []string{dnsEntry.Id},
			expectResults: []*expectResult{
				{
					entry: dnsEntry,
				},
			},
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "dns",
							telemetry.Csr:            api.HashByte(m["dns"]),
							telemetry.ExpiresAt:      expiresAtFromCAStr,
						},
					},
				}
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
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "workload",
							telemetry.Csr:            api.HashByte(m["workload"]),
							telemetry.ExpiresAt:      expiresAtFromCAStr,
						},
					},
					{
						Level:   logrus.ErrorLevel,
						Message: "Entry has malformed SPIFFE ID",
						Data: logrus.Fields{
							telemetry.RegistrationID: "invalid",
							logrus.ErrorKey:          "request must specify SPIFFE ID",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "invalid",
							telemetry.Csr:            api.HashByte(m["invalid"]),
							telemetry.StatusCode:     "Internal",
							telemetry.StatusMessage:  "entry has malformed SPIFFE ID: request must specify SPIFFE ID",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "dns",
							telemetry.Csr:            api.HashByte(m["dns"]),
							telemetry.ExpiresAt:      expiresAtFromCAStr,
						},
					},
				}
			},
		}, {
			name:         "no caller id",
			reqs:         []string{workloadEntry.Id},
			code:         codes.Internal,
			err:          "caller ID missing from request context",
			failCallerID: true,
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Caller ID missing from request context",
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "Internal",
							telemetry.StatusMessage: "caller ID missing from request context",
						},
					},
				}
			},
		}, {
			name: "no parameters",
			reqs: []string{},
			code: codes.InvalidArgument,
			err:  "missing parameters",
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: missing parameters",
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "InvalidArgument",
							telemetry.StatusMessage: "missing parameters",
						},
					},
				}
			},
		}, {
			name:           "rate limit fails",
			reqs:           []string{workloadEntry.Id},
			code:           codes.Internal,
			err:            "rate limit error",
			rateLimiterErr: status.Error(codes.Internal, "rate limit error"),
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Rejecting request due to certificate signing rate limiting",
						Data: logrus.Fields{
							logrus.ErrorKey: "rpc error: code = Internal desc = rate limit error",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "Internal",
							telemetry.StatusMessage: "rejecting request due to certificate signing rate limiting: rate limit error",
						},
					},
				}
			},
		}, {
			name:       "fetch entries fails",
			reqs:       []string{workloadEntry.Id},
			code:       codes.Internal,
			err:        "failed to fetch registration entries",
			fetcherErr: "fetcher fails",
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Failed to fetch registration entries",
						Data: logrus.Fields{
							logrus.ErrorKey: "rpc error: code = Internal desc = fetcher fails",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "Internal",
							telemetry.StatusMessage: "failed to fetch registration entries: fetcher fails",
						},
					},
				}
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
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: missing entry ID",
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "",
							telemetry.Csr:            api.HashByte(m[""]),
							telemetry.StatusCode:     "InvalidArgument",
							telemetry.StatusMessage:  "missing entry ID",
						},
					},
				}
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
			mutateCSR: func([]byte) []byte {
				return []byte{}
			},
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: missing CSR",
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "workload",
							telemetry.Csr:            "",
							telemetry.StatusCode:     "InvalidArgument",
							telemetry.StatusMessage:  "missing CSR",
						},
					},
				}
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
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Entry not found or not authorized",
						Data: logrus.Fields{
							telemetry.RegistrationID: "invalid entry",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "invalid entry",
							telemetry.Csr:            api.HashByte(m["invalid entry"]),
							telemetry.StatusCode:     "NotFound",
							telemetry.StatusMessage:  "entry not found or not authorized",
						},
					},
				}
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
			mutateCSR: func([]byte) []byte {
				return []byte{1, 2, 3}
			},
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: malformed CSR",
						Data: logrus.Fields{
							telemetry.RegistrationID: "workload",
							logrus.ErrorKey:          invalidCsrErr.Error(),
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "workload",
							telemetry.Csr:            api.HashByte(m["workload"]),
							telemetry.StatusCode:     "InvalidArgument",
							telemetry.StatusMessage:  fmt.Sprintf("malformed CSR: %v", invalidCsrErr),
						},
					},
				}
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
			mutateCSR: func(csr []byte) []byte {
				// 4 bytes from the end should be back far enough to be in the
				// signature bytes.
				csr[len(csr)-4]++
				return csr
			},
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: invalid CSR signature",
						Data: logrus.Fields{
							telemetry.RegistrationID: "workload",
							logrus.ErrorKey:          "x509: ECDSA verification failure",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "workload",
							telemetry.Csr:            api.HashByte(m["workload"]),
							telemetry.StatusCode:     "InvalidArgument",
							telemetry.StatusMessage:  "invalid CSR signature: x509: ECDSA verification failure",
						},
					},
				}
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
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Entry has malformed SPIFFE ID",
						Data: logrus.Fields{
							telemetry.RegistrationID: "invalid",
							logrus.ErrorKey:          "request must specify SPIFFE ID",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "invalid",
							telemetry.Csr:            api.HashByte(m["invalid"]),
							telemetry.StatusCode:     "Internal",
							telemetry.StatusMessage:  "entry has malformed SPIFFE ID: request must specify SPIFFE ID",
						},
					},
				}
			},
		}, {
			name: "signing fails",
			reqs: []string{workloadEntry.Id},
			expectResults: []*expectResult{
				{
					status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "failed to sign X509-SVID: oh no",
					},
				},
			},
			failSigning: true,
			expectLogs: func(m map[string][]byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Failed to sign X509-SVID",
						Data: logrus.Fields{
							telemetry.RegistrationID: "workload",
							logrus.ErrorKey:          "oh no",
							telemetry.SPIFFEID:       workloadID.String(),
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "workload",
							telemetry.Csr:            api.HashByte(m["workload"]),
							telemetry.StatusCode:     "Internal",
							telemetry.StatusMessage:  "failed to sign X509-SVID: oh no",
						},
					},
				}
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()

			if tt.failSigning {
				test.ca.SetError(errors.New("oh no"))
			}

			ctx := context.Background()

			test.rateLimiter.count = len(tt.reqs)
			test.rateLimiter.err = tt.rateLimiterErr

			test.withCallerID = !tt.failCallerID
			test.ef.err = tt.fetcherErr

			csrMap := make(map[string][]byte, len(tt.reqs))
			var params []*svidv1.NewX509SVIDParams
			for _, entryID := range tt.reqs {
				// Create CSR
				csr := createCSR(t, &x509.CertificateRequest{})
				if tt.mutateCSR != nil {
					csr = tt.mutateCSR(csr)
				}
				params = append(params, &svidv1.NewX509SVIDParams{
					EntryId: entryID,
					Csr:     csr,
				})
				csrMap[entryID] = csr
			}

			// Batch svids
			resp, err := test.client.BatchNewX509SVID(ctx, &svidv1.BatchNewX509SVIDRequest{
				Params: params,
			})
			expectLogs := tt.expectLogs(csrMap)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), expectLogs)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)

				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotEmpty(t, resp.Results)

			for i, result := range resp.Results {
				expect := tt.expectResults[i]

				if expect.status != nil {
					require.Nil(t, result.Svid)
					require.Equal(t, expect.status.Code, result.Status.Code)
					require.Contains(t, result.Status.Message, expect.status.Message)

					continue
				}
				spiretest.AssertProtoEqual(t, &types.Status{Code: int32(codes.OK), Message: "OK"}, result.Status)

				require.NotNil(t, result.Svid)

				entry := expect.entry

				require.Equal(t, entry.SpiffeId.TrustDomain, result.Svid.Id.TrustDomain)
				require.Equal(t, entry.SpiffeId.Path, result.Svid.Id.Path)

				certChain, err := x509util.RawCertsToCertificates(result.Svid.CertChain)
				require.NoError(t, err)
				require.NotEmpty(t, certChain)
				svid := certChain[0]

				entrySPIFFEID := idutil.RequireIDFromProto(entry.SpiffeId)
				require.Equal(t, []*url.URL{entrySPIFFEID.URL()}, svid.URIs)

				// Use entry ttl when defined
				ttl := test.ca.X509SVIDTTL()
				if entry.X509SvidTtl != 0 {
					ttl = time.Duration(entry.X509SvidTtl) * time.Second
				}
				expiresAt := now.Add(ttl)

				require.Equal(t, expiresAt, svid.NotAfter)
				require.Equal(t, expiresAt.UTC().Unix(), result.Svid.ExpiresAt)

				require.Equal(t, entry.DnsNames, svid.DNSNames)

				expectedSubject := &pkix.Name{
					Organization: []string{"SPIRE"},
					Country:      []string{"US"},
					Names: []pkix.AttributeTypeAndValue{
						x509svid.UniqueIDAttribute(entrySPIFFEID),
					},
				}
				if len(entry.DnsNames) > 0 {
					expectedSubject.CommonName = entry.DnsNames[0]
				}
				require.Equal(t, expectedSubject.String(), svid.Subject.String())
			}
		})
	}
}

func TestNewDownstreamX509CA(t *testing.T) {
	type downstreamCaTest struct {
		name           string
		err            string
		failSigning    bool
		failDataStore  bool
		rateLimiterErr error
		entry          *types.Entry
		csr            []byte
		csrTemplate    *x509.CertificateRequest
		code           codes.Code
		fetcherErr     string
		expectLogs     func([]byte) []spiretest.LogEntry
	}

	downstreamEntry1 := &types.Entry{
		Id:         "downstreamCA1",
		ParentId:   api.ProtoFromID(agentID),
		SpiffeId:   &types.SPIFFEID{TrustDomain: "example.org", Path: ""},
		Downstream: true,
	}

	test := setupServiceTest(t)
	defer test.Cleanup()

	_, csrErr := x509.ParseCertificateRequest([]byte{1, 2, 3})

	now := test.ca.Clock().Now().UTC()
	expiresAtFromCA := now.Add(test.ca.X509SVIDTTL()).Unix()

	for _, tt := range []downstreamCaTest{
		{
			name:           "Malformed CSR",
			rateLimiterErr: nil,
			err:            "malformed CSR: asn1: structure error",
			failSigning:    false,
			csr:            []byte{1, 2, 3},
			code:           codes.InvalidArgument,
			fetcherErr:     "",
			entry:          downstreamEntry1,
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: malformed CSR",
						Data: logrus.Fields{
							logrus.ErrorKey: csrErr.Error(),
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "InvalidArgument",
							telemetry.StatusMessage: fmt.Sprintf("malformed CSR: %v", csrErr),
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TrustDomainID: "spiffe://example.org",
						},
					},
				}
			},
		},
		{
			name:           "Rate Limiter Err",
			rateLimiterErr: status.Error(codes.Internal, "rate limit error"),
			err:            "rate limit error",
			failSigning:    false,
			csr:            []byte{1, 2, 3},
			code:           codes.Internal,
			fetcherErr:     "",
			entry:          downstreamEntry1,
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Rejecting request due to downstream CA signing rate limit",
						Data: logrus.Fields{
							logrus.ErrorKey: "rpc error: code = Internal desc = rate limit error",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "Internal",
							telemetry.StatusMessage: "rejecting request due to downstream CA signing rate limit: rate limit error",
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TrustDomainID: "spiffe://example.org",
						},
					},
				}
			},
		},
		{
			name:           "Unauthorized",
			rateLimiterErr: nil,
			err:            "caller is not a downstream workload",
			failSigning:    false,
			csr:            []byte{1, 2, 3},
			code:           codes.Internal,
			fetcherErr:     "",
			entry:          nil,
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Caller is not a downstream workload",
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "Internal",
							telemetry.StatusMessage: "caller is not a downstream workload",
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TrustDomainID: "spiffe://example.org",
						},
					},
				}
			},
		},
		{
			name:           "Fail Data Store",
			rateLimiterErr: nil,
			err:            "bundle not found",
			failSigning:    false,
			csrTemplate:    &x509.CertificateRequest{},
			code:           codes.NotFound,
			fetcherErr:     "",
			entry:          downstreamEntry1,
			failDataStore:  true,
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Bundle not found",
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "NotFound",
							telemetry.StatusMessage: "bundle not found",
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TrustDomainID: "spiffe://example.org",
						},
					},
				}
			},
		},
		{
			name:           "Successful CA Request",
			rateLimiterErr: nil,
			err:            "",
			failSigning:    false,
			failDataStore:  false,
			csrTemplate: &x509.CertificateRequest{
				URIs: []*url.URL{workloadID.URL()},
			},
			fetcherErr: "",
			entry:      downstreamEntry1,
			expectLogs: func(csr []byte) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "success",
							telemetry.Type:          "audit",
							telemetry.Csr:           api.HashByte(csr),
							telemetry.TrustDomainID: "spiffe://example.org",
							telemetry.ExpiresAt:     strconv.FormatInt(expiresAtFromCA, 10),
						},
					},
				}
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()
			test.ef.err = tt.fetcherErr
			if !tt.failDataStore {
				_, err := test.ds.AppendBundle(context.Background(), &common.Bundle{
					// The SPIFFE ID of the bundle in the datastore needs to match the SPIFFE ID
					// provided by the client
					TrustDomainId: td.IDString(),
					RootCas: []*common.Certificate{
						{DerBytes: []byte("RootCa1")},
					},
				})
				require.NoError(t, err)
			} else {
				err := test.ds.DeleteBundle(context.Background(), td.IDString(), datastore.Restrict)
				require.NoError(t, err)
			}

			test.withCallerID = true
			test.rateLimiter.count = 1
			test.rateLimiter.err = tt.rateLimiterErr

			if tt.failSigning {
				test.ca.SetError(errors.New("oh no"))
			}

			csr := tt.csr
			if tt.csrTemplate != nil {
				csr = createCSR(t, tt.csrTemplate)
			}

			ctx := context.Background()

			test.downstream.entries = nil
			if tt.entry != nil {
				test.downstream.entries = []*types.Entry{tt.entry}
			}

			resp, err := test.client.NewDownstreamX509CA(ctx, &svidv1.NewDownstreamX509CARequest{
				Csr: csr,
			})
			expectLogs := tt.expectLogs(csr)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), expectLogs)

			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotEmpty(t, resp.CaCertChain)
			require.NotEmpty(t, resp.X509Authorities)

			certChain, err := x509util.RawCertsToCertificates(resp.CaCertChain)
			require.NoError(t, err)
			require.NotEmpty(t, certChain)
			require.NotEmpty(t, certChain[0].URIs)
			require.Equal(t, certChain[0].URIs[0].String(), td.IDString())

			require.Equal(t, string(resp.X509Authorities[0]), "RootCa1")
		})
	}
}

type serviceTest struct {
	client       svidv1.SVIDClient
	ef           *entryFetcher // Stores entries explicitly fetched using FetchAuthorizedEntries
	downstream   *entryFetcher // Stores Downstream entries which end up in the context
	ca           *fakeserverca.CA
	ds           *fakedatastore.DataStore
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
	ca := fakeserverca.New(t, trustDomain, &fakeserverca.Options{})
	ef := &entryFetcher{}
	downstream := &entryFetcher{}
	ds := fakedatastore.New(t)

	rateLimiter := &fakeRateLimiter{}
	service := svid.New(svid.Config{
		EntryFetcher: ef,
		ServerCA:     ca,
		TrustDomain:  trustDomain,
		DataStore:    ds,
	})

	log, logHook := test.NewNullLogger()
	registerFn := func(s *grpc.Server) {
		svid.RegisterService(s, service)
	}

	test := &serviceTest{
		ca:          ca,
		ef:          ef,
		downstream:  downstream,
		ds:          ds,
		logHook:     logHook,
		rateLimiter: rateLimiter,
	}

	ppMiddleware := middleware.Preprocess(func(ctx context.Context, fullMethod string, req interface{}) (context.Context, error) {
		ctx = rpccontext.WithLogger(ctx, log)
		ctx = rpccontext.WithRateLimiter(ctx, rateLimiter)
		if test.withCallerID {
			ctx = rpccontext.WithCallerID(ctx, agentID)
		}
		if test.downstream.entries != nil {
			ctx = rpccontext.WithCallerDownstreamEntries(ctx, downstream.entries)
		}
		return ctx, nil
	})

	unaryInterceptor, streamInterceptor := middleware.Interceptors(middleware.Chain(
		ppMiddleware,
		// Add audit log with local tracking disabled
		middleware.WithAuditLog(false),
	))
	server := grpc.NewServer(
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)

	// Set create client and add to test
	conn, done := spiretest.NewAPIServerWithMiddleware(t, registerFn, server)
	test.client = svidv1.NewSVIDClient(conn)
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

	jwtsvidID, err := api.TrustDomainWorkloadIDFromProto(context.Background(), td, jwtsvid.Id)
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

func (f *fakeRateLimiter) RateLimit(_ context.Context, count int) error {
	if f.count != count {
		return fmt.Errorf("rate limiter got %d but expected %d", count, f.count)
	}

	return f.err
}
