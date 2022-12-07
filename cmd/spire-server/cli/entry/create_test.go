package entry

import (
	"errors"
	"fmt"
	"testing"
	"time"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestCreateHelp(t *testing.T) {
	test := setupTest(t, newCreateCommand)
	test.client.Help()

	require.Equal(t, createUsage, test.stderr.String())
}

func TestCreateSynopsis(t *testing.T) {
	test := setupTest(t, newCreateCommand)
	require.Equal(t, "Creates registration entries", test.client.Synopsis())
}

func TestCreate(t *testing.T) {
	fakeRespOKFromCmd := &entryv1.BatchCreateEntryResponse{
		Results: []*entryv1.BatchCreateEntryResponse_Result{
			{
				Entry: &types.Entry{
					Id:       "entry-id",
					SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
					ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"},
					Selectors: []*types.Selector{
						{Type: "zebra", Value: "zebra:2000"},
						{Type: "alpha", Value: "alpha:2000"},
					},
					X509SvidTtl:   60,
					JwtSvidTtl:    30,
					FederatesWith: []string{"spiffe://domaina.test", "spiffe://domainb.test"},
					Admin:         true,
					ExpiresAt:     1552410266,
					DnsNames:      []string{"unu1000", "ung1000"},
					Downstream:    true,
					StoreSvid:     true,
				},
				Status: &types.Status{
					Code:    int32(codes.OK),
					Message: "OK",
				},
			},
		},
	}

	fakeRespOKFromCmd2 := &entryv1.BatchCreateEntryResponse{
		Results: []*entryv1.BatchCreateEntryResponse_Result{
			{
				Entry: &types.Entry{
					Id:       "entry-id",
					SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
					ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"},
					Selectors: []*types.Selector{
						{Type: "zebra", Value: "zebra:2000"},
						{Type: "alpha", Value: "alpha:2000"},
					},
					X509SvidTtl:   60,
					FederatesWith: []string{"spiffe://domaina.test", "spiffe://domainb.test"},
					Admin:         true,
					ExpiresAt:     1552410266,
					DnsNames:      []string{"unu1000", "ung1000"},
					Downstream:    true,
					StoreSvid:     true,
				},
				Status: &types.Status{
					Code:    int32(codes.OK),
					Message: "OK",
				},
			},
		},
	}

	fakeRespOKFromFile := &entryv1.BatchCreateEntryResponse{
		Results: []*entryv1.BatchCreateEntryResponse_Result{
			{
				Entry: &types.Entry{
					Id:          "entry-id-1",
					SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/Blog"},
					ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenBlog"},
					Selectors:   []*types.Selector{{Type: "unix", Value: "uid:1111"}},
					X509SvidTtl: 200,
					JwtSvidTtl:  30,
					Admin:       true,
				},
				Status: &types.Status{
					Code:    int32(codes.OK),
					Message: "OK",
				},
			},
			{
				Entry: &types.Entry{
					Id:          "entry-id-2",
					SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/Database"},
					ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
					Selectors:   []*types.Selector{{Type: "unix", Value: "uid:1111"}},
					X509SvidTtl: 200,
					JwtSvidTtl:  30,
				},
				Status: &types.Status{
					Code:    int32(codes.OK),
					Message: "OK",
				},
			},
			{
				Entry: &types.Entry{
					Id:       "entry-id-3",
					SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/storesvid"},
					ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
					Selectors: []*types.Selector{
						{Type: "type", Value: "key1:value"},
						{Type: "type", Value: "key2:value"},
					},
					StoreSvid:   true,
					X509SvidTtl: 200,
					JwtSvidTtl:  30,
				},
				Status: &types.Status{
					Code:    int32(codes.OK),
					Message: "OK",
				},
			},
		},
	}

	fakeRespErr := &entryv1.BatchCreateEntryResponse{
		Results: []*entryv1.BatchCreateEntryResponse_Result{
			{
				Status: &types.Status{
					Code:    int32(codes.AlreadyExists),
					Message: "similar entry already exists",
				},
			},
		},
	}

	for _, tt := range []struct {
		name string
		args []string

		expReq    *entryv1.BatchCreateEntryRequest
		fakeResp  *entryv1.BatchCreateEntryResponse
		serverErr error

		expOutPretty string
		expOutJSON   string
		expErrJSON   string
		expErrPretty string
	}{
		{
			name:         "Missing selectors",
			expErrPretty: "Error: at least one selector is required\n",
			expErrJSON:   "Error: at least one selector is required\n",
		},
		{
			name:         "Missing parent SPIFFE ID",
			args:         []string{"-selector", "unix:uid:1"},
			expErrPretty: "Error: a parent ID is required if the node flag is not set\n",
			expErrJSON:   "Error: a parent ID is required if the node flag is not set\n",
		},
		{
			name:         "Missing SPIFFE ID",
			args:         []string{"-selector", "unix:uid:1", "-parentID", "spiffe://example.org/parent"},
			expErrPretty: "Error: a SPIFFE ID is required\n",
			expErrJSON:   "Error: a SPIFFE ID is required\n",
		},
		{
			name:         "Wrong selectors",
			args:         []string{"-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload"},
			expErrPretty: "Error: selector \"unix\" must be formatted as type:value\n",
			expErrJSON:   "Error: selector \"unix\" must be formatted as type:value\n",
		},
		{
			name:         "Negative TTL",
			args:         []string{"-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload", "-ttl", "-10"},
			expErrPretty: "Error: a positive TTL is required\n",
			expErrJSON:   "Error: a positive TTL is required\n",
		},
		{
			name:         "Invalid TTL and X509SvidTtl",
			args:         []string{"-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload", "-ttl", "10", "-x509SVIDTTL", "20"},
			expErrPretty: "Error: use x509SVIDTTL and jwtSVIDTTL flags or the deprecated ttl flag\n",
			expErrJSON:   "Error: use x509SVIDTTL and jwtSVIDTTL flags or the deprecated ttl flag\n",
		},
		{
			name:         "Invalid TTL and JwtSvidTtl",
			args:         []string{"-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload", "-ttl", "10", "-jwtSVIDTTL", "20"},
			expErrPretty: "Error: use x509SVIDTTL and jwtSVIDTTL flags or the deprecated ttl flag\n",
			expErrJSON:   "Error: use x509SVIDTTL and jwtSVIDTTL flags or the deprecated ttl flag\n",
		},
		{
			name:         "Invalid TTL and both X509SvidTtl and JwtSvidTtl",
			args:         []string{"-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload", "-ttl", "10", "-x509SVIDTTL", "20", "-jwtSVIDTTL", "30"},
			expErrPretty: "Error: use x509SVIDTTL and jwtSVIDTTL flags or the deprecated ttl flag\n",
			expErrJSON:   "Error: use x509SVIDTTL and jwtSVIDTTL flags or the deprecated ttl flag\n",
		},
		{
			name:         "Federated node entries",
			args:         []string{"-selector", "unix", "-spiffeID", "spiffe://example.org/workload", "-node", "-federatesWith", "spiffe://another.org"},
			expErrPretty: "Error: node entries can not federate\n",
			expErrJSON:   "Error: node entries can not federate\n",
		},
		{
			name: "Server error",
			args: []string{"-spiffeID", "spiffe://example.org/node", "-node", "-selector", "unix:uid:1"},
			expReq: &entryv1.BatchCreateEntryRequest{Entries: []*types.Entry{
				{
					SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/node"},
					ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/server"},
					Selectors: []*types.Selector{{Type: "unix", Value: "uid:1"}},
				},
			}},
			serverErr:    errors.New("server-error"),
			expErrPretty: "Error: rpc error: code = Unknown desc = server-error\n",
			expErrJSON:   "Error: rpc error: code = Unknown desc = server-error\n",
		},
		{
			name: "Create succeeds using command line arguments",
			args: []string{
				"-spiffeID", "spiffe://example.org/workload",
				"-parentID", "spiffe://example.org/parent",
				"-selector", "zebra:zebra:2000",
				"-selector", "alpha:alpha:2000",
				"-x509SVIDTTL", "60",
				"-jwtSVIDTTL", "30",
				"-federatesWith", "spiffe://domaina.test",
				"-federatesWith", "spiffe://domainb.test",
				"-admin",
				"-entryExpiry", "1552410266",
				"-dns", "unu1000",
				"-dns", "ung1000",
				"-downstream",
				"-storeSVID",
			},
			expReq: &entryv1.BatchCreateEntryRequest{
				Entries: []*types.Entry{
					{
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
						ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"},
						Selectors: []*types.Selector{
							{Type: "zebra", Value: "zebra:2000"},
							{Type: "alpha", Value: "alpha:2000"},
						},
						X509SvidTtl:   60,
						JwtSvidTtl:    30,
						FederatesWith: []string{"spiffe://domaina.test", "spiffe://domainb.test"},
						Admin:         true,
						ExpiresAt:     1552410266,
						DnsNames:      []string{"unu1000", "ung1000"},
						Downstream:    true,
						StoreSvid:     true,
					},
				},
			},
			fakeResp: fakeRespOKFromCmd,
			expOutPretty: fmt.Sprintf(`Entry ID         : entry-id
SPIFFE ID        : spiffe://example.org/workload
Parent ID        : spiffe://example.org/parent
Revision         : 0
Downstream       : true
X509-SVID TTL    : 60
JWT-SVID TTL     : 30
Expiration time  : %s
Selector         : zebra:zebra:2000
Selector         : alpha:alpha:2000
FederatesWith    : spiffe://domaina.test
FederatesWith    : spiffe://domainb.test
DNS name         : unu1000
DNS name         : ung1000
Admin            : true
StoreSvid        : true

`, time.Unix(1552410266, 0).UTC()),
			expOutJSON: `{
  "results": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "entry": {
        "id": "entry-id",
        "spiffe_id": {
          "trust_domain": "example.org",
          "path": "/workload"
        },
        "parent_id": {
          "trust_domain": "example.org",
          "path": "/parent"
        },
        "selectors": [
          {
            "type": "zebra",
            "value": "zebra:2000"
          },
          {
            "type": "alpha",
            "value": "alpha:2000"
          }
        ],
        "x509_svid_ttl": 60,
        "federates_with": [
          "spiffe://domaina.test",
          "spiffe://domainb.test"
        ],
        "admin": true,
        "downstream": true,
        "expires_at": "1552410266",
        "dns_names": [
          "unu1000",
          "ung1000"
        ],
        "revision_number": "0",
        "store_svid": true,
        "jwt_svid_ttl": 30
      }
    }
  ]
}
`,
		},
		{
			name: "Create succeeds using deprecated command line arguments",
			args: []string{
				"-spiffeID", "spiffe://example.org/workload",
				"-parentID", "spiffe://example.org/parent",
				"-selector", "zebra:zebra:2000",
				"-selector", "alpha:alpha:2000",
				"-ttl", "60",
				"-federatesWith", "spiffe://domaina.test",
				"-federatesWith", "spiffe://domainb.test",
				"-admin",
				"-entryExpiry", "1552410266",
				"-dns", "unu1000",
				"-dns", "ung1000",
				"-downstream",
				"-storeSVID",
			},
			expReq: &entryv1.BatchCreateEntryRequest{
				Entries: []*types.Entry{
					{
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
						ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"},
						Selectors: []*types.Selector{
							{Type: "zebra", Value: "zebra:2000"},
							{Type: "alpha", Value: "alpha:2000"},
						},
						X509SvidTtl:   60,
						FederatesWith: []string{"spiffe://domaina.test", "spiffe://domainb.test"},
						Admin:         true,
						ExpiresAt:     1552410266,
						DnsNames:      []string{"unu1000", "ung1000"},
						Downstream:    true,
						StoreSvid:     true,
					},
				},
			},
			fakeResp: fakeRespOKFromCmd2,
			expOutPretty: fmt.Sprintf(`Entry ID         : entry-id
SPIFFE ID        : spiffe://example.org/workload
Parent ID        : spiffe://example.org/parent
Revision         : 0
Downstream       : true
X509-SVID TTL    : 60
JWT-SVID TTL     : default
Expiration time  : %s
Selector         : zebra:zebra:2000
Selector         : alpha:alpha:2000
FederatesWith    : spiffe://domaina.test
FederatesWith    : spiffe://domainb.test
DNS name         : unu1000
DNS name         : ung1000
Admin            : true
StoreSvid        : true

`, time.Unix(1552410266, 0).UTC()),
			expOutJSON: `{
  "results": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "entry": {
        "id": "entry-id",
        "spiffe_id": {
          "trust_domain": "example.org",
          "path": "/workload"
        },
        "parent_id": {
          "trust_domain": "example.org",
          "path": "/parent"
        },
        "selectors": [
          {
            "type": "zebra",
            "value": "zebra:2000"
          },
          {
            "type": "alpha",
            "value": "alpha:2000"
          }
        ],
        "x509_svid_ttl": 60,
        "federates_with": [
          "spiffe://domaina.test",
          "spiffe://domainb.test"
        ],
        "admin": true,
        "downstream": true,
        "expires_at": "1552410266",
        "dns_names": [
          "unu1000",
          "ung1000"
        ],
        "revision_number": "0",
        "store_svid": true,
        "jwt_svid_ttl": 0
      }
    }
  ]
}`,
		},
		{
			name: "Create succeeds using data file",
			args: []string{
				"-data", "../../../../test/fixture/registration/good.json",
			},
			expReq: &entryv1.BatchCreateEntryRequest{
				Entries: []*types.Entry{
					{
						SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/Blog"},
						ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenBlog"},
						Selectors:   []*types.Selector{{Type: "unix", Value: "uid:1111"}},
						X509SvidTtl: 200,
						JwtSvidTtl:  30,
						Admin:       true,
					},
					{
						SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/Database"},
						ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
						Selectors:   []*types.Selector{{Type: "unix", Value: "uid:1111"}},
						X509SvidTtl: 200,
						JwtSvidTtl:  30,
					},
					{
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/storesvid"},
						ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
						Selectors: []*types.Selector{
							{Type: "type", Value: "key1:value"},
							{Type: "type", Value: "key2:value"},
						},
						X509SvidTtl: 200,
						JwtSvidTtl:  30,
						StoreSvid:   true,
					},
				},
			},
			fakeResp: fakeRespOKFromFile,
			expOutPretty: `Entry ID         : entry-id-1
SPIFFE ID        : spiffe://example.org/Blog
Parent ID        : spiffe://example.org/spire/agent/join_token/TokenBlog
Revision         : 0
X509-SVID TTL    : 200
JWT-SVID TTL     : 30
Selector         : unix:uid:1111
Admin            : true

Entry ID         : entry-id-2
SPIFFE ID        : spiffe://example.org/Database
Parent ID        : spiffe://example.org/spire/agent/join_token/TokenDatabase
Revision         : 0
X509-SVID TTL    : 200
JWT-SVID TTL     : 30
Selector         : unix:uid:1111

Entry ID         : entry-id-3
SPIFFE ID        : spiffe://example.org/storesvid
Parent ID        : spiffe://example.org/spire/agent/join_token/TokenDatabase
Revision         : 0
X509-SVID TTL    : 200
JWT-SVID TTL     : 30
Selector         : type:key1:value
Selector         : type:key2:value
StoreSvid        : true

`,
			expOutJSON: `{
  "results": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "entry": {
        "id": "entry-id-1",
        "spiffe_id": {
          "trust_domain": "example.org",
          "path": "/Blog"
        },
        "parent_id": {
          "trust_domain": "example.org",
          "path": "/spire/agent/join_token/TokenBlog"
        },
        "selectors": [
          {
            "type": "unix",
            "value": "uid:1111"
          }
        ],
        "x509_svid_ttl": 200,
        "federates_with": [],
        "admin": true,
        "downstream": false,
        "expires_at": "0",
        "dns_names": [],
        "revision_number": "0",
        "store_svid": false,
        "jwt_svid_ttl": 30
      }
    },
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "entry": {
        "id": "entry-id-2",
        "spiffe_id": {
          "trust_domain": "example.org",
          "path": "/Database"
        },
        "parent_id": {
          "trust_domain": "example.org",
          "path": "/spire/agent/join_token/TokenDatabase"
        },
        "selectors": [
          {
            "type": "unix",
            "value": "uid:1111"
          }
        ],
        "x509_svid_ttl": 200,
        "federates_with": [],
        "admin": false,
        "downstream": false,
        "expires_at": "0",
        "dns_names": [],
        "revision_number": "0",
        "store_svid": false,
        "jwt_svid_ttl": 30
      }
    },
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "entry": {
        "id": "entry-id-3",
        "spiffe_id": {
          "trust_domain": "example.org",
          "path": "/storesvid"
        },
        "parent_id": {
          "trust_domain": "example.org",
          "path": "/spire/agent/join_token/TokenDatabase"
        },
        "selectors": [
          {
            "type": "type",
            "value": "key1:value"
          },
          {
            "type": "type",
            "value": "key2:value"
          }
        ],
        "x509_svid_ttl": 200,
        "federates_with": [],
        "admin": false,
        "downstream": false,
        "expires_at": "0",
        "dns_names": [],
        "revision_number": "0",
        "store_svid": true,
        "jwt_svid_ttl": 30
      }
    }
  ]
}`,
		},
		{
			name: "Entry already exist",
			args: []string{"-spiffeID", "spiffe://example.org/already-exist", "-node", "-selector", "unix:uid:1"},
			expReq: &entryv1.BatchCreateEntryRequest{Entries: []*types.Entry{
				{
					SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/already-exist"},
					ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/server"},
					Selectors: []*types.Selector{{Type: "unix", Value: "uid:1"}},
				},
			}},
			fakeResp: fakeRespErr,
			expErrPretty: `Failed to create the following entry (code: AlreadyExists, msg: "similar entry already exists"):
Entry ID         : (none)
SPIFFE ID        : spiffe://example.org/already-exist
Parent ID        : spiffe://example.org/spire/server
Revision         : 0
X509-SVID TTL    : default
JWT-SVID TTL     : default
Selector         : unix:uid:1

Error: failed to create one or more entries
`,
			expOutJSON: `{
  "results": [
    {
      "status": {
        "code": 6,
        "message": "similar entry already exists"
      },
      "entry": {
        "id": "",
        "spiffe_id": {
          "trust_domain": "example.org",
          "path": "/already-exist"
        },
        "parent_id": {
          "trust_domain": "example.org",
          "path": "/spire/server"
        },
        "selectors": [
          {
            "type": "unix",
            "value": "uid:1"
          }
        ],
        "x509_svid_ttl": 0,
        "federates_with": [],
        "admin": false,
        "downstream": false,
        "expires_at": "0",
        "dns_names": [],
        "revision_number": "0",
        "store_svid": false,
        "jwt_svid_ttl": 0
      }
    }
  ]
}`,
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, newCreateCommand)
				test.server.err = tt.serverErr
				test.server.expBatchCreateEntryReq = tt.expReq
				test.server.batchCreateEntryResp = tt.fakeResp
				args := tt.args
				args = append(args, "-output", format)

				rc := test.client.Run(test.args(args...))

				if tt.expErrJSON != "" && format == "json" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expErrJSON, test.stderr.String())
					return
				}
				if tt.expErrPretty != "" && format == "pretty" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expErrPretty, test.stderr.String())
					return
				}
				require.Equal(t, 0, rc)
				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expOutPretty, tt.expOutJSON)
			})
		}
	}
}
