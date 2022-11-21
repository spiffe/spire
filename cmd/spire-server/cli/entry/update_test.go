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

func TestUpdateHelp(t *testing.T) {
	test := setupTest(t, newUpdateCommand)
	test.client.Help()
	require.Equal(t, updateUsage, test.stderr.String())
}

func TestUpdateSynopsis(t *testing.T) {
	test := setupTest(t, newUpdateCommand)
	require.Equal(t, "Updates registration entries", test.client.Synopsis())
}

func TestUpdate(t *testing.T) {
	entry0JSON := `{
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
            "type": "type",
            "value": "key1:value"
          },
          {
            "type": "type",
            "value": "key2:value"
          }
        ],
		"x509_svid_ttl": 60,
        "federates_with": [
          "spiffe://domaina.test",
          "spiffe://domainb.test"
        ],
        "admin": false,
        "downstream": false,
        "expires_at": "1552410266",
        "dns_names": [
          "unu1000",
          "ung1000"
        ],
        "revision_number": "0",
        "store_svid": true,
		"jwt_svid_ttl":30
      }`
	entry0AdminJSON := `{
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
        "store_svid": false,
		"jwt_svid_ttl":30
      }`
	entry1JSON := `{
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
		"jwt_svid_ttl": 300
      }
    }`
	entry2JSON := `{
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
		"jwt_svid_ttl":300
      }
    }`
	entry3JSON := `{
        "id": "entry-id-3",
        "spiffe_id": {
          "trust_domain": "example.org",
          "path": "/Storesvid"
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
		"jwt_svid_ttl":300
      }`
	nonExistentEntryJSON := `{
        "id": "non-existent-id",
        "spiffe_id": {
          "trust_domain": "example.org",
          "path": "/workload"
        },
		"jwt_svid_ttl": 0,
        "parent_id": {
          "trust_domain": "example.org",
          "path": "/parent"
        },
        "selectors": [
          {
            "type": "unix",
            "value": "uid:1"
          }
        ],
        "federates_with": [],
        "admin": false,
        "downstream": false,
        "expires_at": "0",
        "dns_names": [],
        "revision_number": "0",
        "store_svid": false,
		"x509_svid_ttl": 0
      }`

	entry1 := &types.Entry{
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
	}

	entryStoreSvid := &types.Entry{
		Id:       "entry-id",
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
		ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"},
		Selectors: []*types.Selector{
			{Type: "type", Value: "key1:value"},
			{Type: "type", Value: "key2:value"},
		},
		X509SvidTtl:   60,
		JwtSvidTtl:    30,
		FederatesWith: []string{"spiffe://domaina.test", "spiffe://domainb.test"},
		ExpiresAt:     1552410266,
		DnsNames:      []string{"unu1000", "ung1000"},
		StoreSvid:     true,
	}
	fakeRespOKFromCmd := &entryv1.BatchUpdateEntryResponse{
		Results: []*entryv1.BatchUpdateEntryResponse_Result{
			{
				Entry: entry1,
				Status: &types.Status{
					Code:    int32(codes.OK),
					Message: "OK",
				},
			},
		},
	}

	entry2 := &types.Entry{
		Id:          "entry-id-1",
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/Blog"},
		ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenBlog"},
		Selectors:   []*types.Selector{{Type: "unix", Value: "uid:1111"}},
		X509SvidTtl: 200,
		JwtSvidTtl:  300,
		Admin:       true,
	}

	entry3 := &types.Entry{
		Id:          "entry-id-2",
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/Database"},
		ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
		Selectors:   []*types.Selector{{Type: "unix", Value: "uid:1111"}},
		X509SvidTtl: 200,
		JwtSvidTtl:  300,
	}

	entry4 := &types.Entry{
		Id:       "entry-id-3",
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/Storesvid"},
		ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/join_token/TokenDatabase"},
		Selectors: []*types.Selector{
			{Type: "type", Value: "key1:value"},
			{Type: "type", Value: "key2:value"},
		},
		StoreSvid:   true,
		X509SvidTtl: 200,
		JwtSvidTtl:  300,
	}

	entry5 := &types.Entry{
		Id:       "entry-id",
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
		ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"},
		Selectors: []*types.Selector{
			{Type: "zebra", Value: "zebra:2000"},
			{Type: "alpha", Value: "alpha:2000"},
		},
		X509SvidTtl:   60,
		JwtSvidTtl:    0,
		FederatesWith: []string{"spiffe://domaina.test", "spiffe://domainb.test"},
		Admin:         true,
		ExpiresAt:     1552410266,
		DnsNames:      []string{"unu1000", "ung1000"},
		Downstream:    true,
	}

	fakeRespOKFromFile := &entryv1.BatchUpdateEntryResponse{
		Results: []*entryv1.BatchUpdateEntryResponse_Result{
			{
				Entry:  entry2,
				Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
			},
			{
				Entry:  entry3,
				Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
			},
			{
				Entry:  entry4,
				Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
			},
		},
	}

	fakeRespErr := &entryv1.BatchUpdateEntryResponse{
		Results: []*entryv1.BatchUpdateEntryResponse_Result{
			{
				Status: &types.Status{
					Code:    int32(codes.NotFound),
					Message: "failed to update entry: datastore-sql: record not found",
				},
			},
		},
	}

	for _, tt := range []struct {
		name string
		args []string

		expReq    *entryv1.BatchUpdateEntryRequest
		fakeResp  *entryv1.BatchUpdateEntryResponse
		serverErr error

		expOutPretty string
		expOutJSON   string
		expErrPretty string
		expErrJSON   string
	}{
		{
			name:         "Missing Entry ID",
			expErrPretty: "Error: entry ID is required\n",
			expErrJSON:   "Error: entry ID is required\n",
		},
		{
			name:         "Missing selectors",
			args:         []string{"-entryID", "entry-id"},
			expErrPretty: "Error: at least one selector is required\n",
			expErrJSON:   "Error: at least one selector is required\n",
		},
		{
			name:         "Missing parent SPIFFE ID",
			args:         []string{"-entryID", "entry-id", "-selector", "unix:uid:1"},
			expErrPretty: "Error: a parent ID is required\n",
			expErrJSON:   "Error: a parent ID is required\n",
		},
		{
			name:         "Missing SPIFFE ID",
			args:         []string{"-entryID", "entry-id", "-selector", "unix:uid:1", "-parentID", "spiffe://example.org/parent"},
			expErrPretty: "Error: a SPIFFE ID is required\n",
			expErrJSON:   "Error: a SPIFFE ID is required\n",
		},
		{
			name:         "Wrong selectors",
			args:         []string{"-entryID", "entry-id", "-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload"},
			expErrPretty: "Error: selector \"unix\" must be formatted as type:value\n",
			expErrJSON:   "Error: selector \"unix\" must be formatted as type:value\n",
		},
		{
			name:         "Negative TTL",
			args:         []string{"-entryID", "entry-id", "-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload", "-ttl", "-10"},
			expErrPretty: "Error: a positive TTL is required\n",
			expErrJSON:   "Error: a positive TTL is required\n",
		},
		{
			name:         "Invalid TTL and X509SvidTtl",
			args:         []string{"-entryID", "entry-id", "-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload", "-ttl", "10", "-x509SVIDTTL", "20"},
			expErrPretty: "Error: use x509SVIDTTL and jwtSVIDTTL flags or the deprecated ttl flag\n",
			expErrJSON:   "Error: use x509SVIDTTL and jwtSVIDTTL flags or the deprecated ttl flag\n",
		},
		{
			name:         "Invalid TTL and JwtSvidTtl",
			args:         []string{"-entryID", "entry-id", "-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload", "-ttl", "10", "-jwtSVIDTTL", "20"},
			expErrPretty: "Error: use x509SVIDTTL and jwtSVIDTTL flags or the deprecated ttl flag\n",
			expErrJSON:   "Error: use x509SVIDTTL and jwtSVIDTTL flags or the deprecated ttl flag\n",
		},
		{
			name:         "Invalid TTL and both X509SvidTtl and JwtSvidTtl",
			args:         []string{"-entryID", "entry-id", "-selector", "unix", "-parentID", "spiffe://example.org/parent", "-spiffeID", "spiffe://example.org/workload", "-ttl", "10", "-x509SVIDTTL", "20", "-jwtSVIDTTL", "30"},
			expErrPretty: "Error: use x509SVIDTTL and jwtSVIDTTL flags or the deprecated ttl flag\n",
			expErrJSON:   "Error: use x509SVIDTTL and jwtSVIDTTL flags or the deprecated ttl flag\n",
		},
		{
			name: "Server error",
			args: []string{"-entryID", "entry-id", "-spiffeID", "spiffe://example.org/workload", "-parentID", "spiffe://example.org/parent", "-selector", "unix:uid:1"},
			expReq: &entryv1.BatchUpdateEntryRequest{Entries: []*types.Entry{
				{
					Id:        "entry-id",
					SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
					ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"},
					Selectors: []*types.Selector{{Type: "unix", Value: "uid:1"}},
				},
			}},
			serverErr:    errors.New("server-error"),
			expErrPretty: "Error: rpc error: code = Unknown desc = server-error\n",
			expErrJSON:   "Error: rpc error: code = Unknown desc = server-error\n",
		},
		{
			name: "Update succeeds using command line arguments",
			args: []string{
				"-entryID", "entry-id",
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
			},
			expReq: &entryv1.BatchUpdateEntryRequest{
				Entries: []*types.Entry{entry1},
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

`, time.Unix(1552410266, 0).UTC()),
			expOutJSON: fmt.Sprintf(`{
  "results": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "entry": %s
    }
  ]
}`, entry0AdminJSON),
		},
		{
			name: "Update succeeds using deprecated command line arguments",
			args: []string{
				"-entryID", "entry-id",
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
			},
			expReq: &entryv1.BatchUpdateEntryRequest{
				Entries: []*types.Entry{entry5},
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

`, time.Unix(1552410266, 0).UTC()),
			expOutJSON: fmt.Sprintf(`{
  "results": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "entry": %s
    }
  ]
}`, entry0AdminJSON),
		},
		{
			name: "Update succeeds using command line arguments Store Svid",
			args: []string{
				"-entryID", "entry-id",
				"-spiffeID", "spiffe://example.org/workload",
				"-parentID", "spiffe://example.org/parent",
				"-selector", "type:key1:value",
				"-selector", "type:key2:value",
				"-x509SVIDTTL", "60",
				"-jwtSVIDTTL", "30",
				"-federatesWith", "spiffe://domaina.test",
				"-federatesWith", "spiffe://domainb.test",
				"-entryExpiry", "1552410266",
				"-dns", "unu1000",
				"-dns", "ung1000",
				"-storeSVID",
			},
			expReq: &entryv1.BatchUpdateEntryRequest{
				Entries: []*types.Entry{entryStoreSvid},
			},
			fakeResp: &entryv1.BatchUpdateEntryResponse{
				Results: []*entryv1.BatchUpdateEntryResponse_Result{
					{
						Entry: entryStoreSvid,
						Status: &types.Status{
							Code:    int32(codes.OK),
							Message: "OK",
						},
					},
				},
			},
			expOutPretty: fmt.Sprintf(`Entry ID         : entry-id
SPIFFE ID        : spiffe://example.org/workload
Parent ID        : spiffe://example.org/parent
Revision         : 0
X509-SVID TTL    : 60
JWT-SVID TTL     : 30
Expiration time  : %s
Selector         : type:key1:value
Selector         : type:key2:value
FederatesWith    : spiffe://domaina.test
FederatesWith    : spiffe://domainb.test
DNS name         : unu1000
DNS name         : ung1000
StoreSvid        : true

`, time.Unix(1552410266, 0).UTC()),
			expOutJSON: fmt.Sprintf(`{
  "results": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "entry": %s
    }
  ]
}`, entry0JSON),
		},
		{
			name: "Update succeeds using data file",
			args: []string{
				"-data", "../../../../test/fixture/registration/good-for-update.json",
			},
			expReq: &entryv1.BatchUpdateEntryRequest{
				Entries: []*types.Entry{entry2, entry3, entry4},
			},
			fakeResp: fakeRespOKFromFile,
			expOutPretty: `Entry ID         : entry-id-1
SPIFFE ID        : spiffe://example.org/Blog
Parent ID        : spiffe://example.org/spire/agent/join_token/TokenBlog
Revision         : 0
X509-SVID TTL    : 200
JWT-SVID TTL     : 300
Selector         : unix:uid:1111
Admin            : true

Entry ID         : entry-id-2
SPIFFE ID        : spiffe://example.org/Database
Parent ID        : spiffe://example.org/spire/agent/join_token/TokenDatabase
Revision         : 0
X509-SVID TTL    : 200
JWT-SVID TTL     : 300
Selector         : unix:uid:1111

Entry ID         : entry-id-3
SPIFFE ID        : spiffe://example.org/Storesvid
Parent ID        : spiffe://example.org/spire/agent/join_token/TokenDatabase
Revision         : 0
X509-SVID TTL    : 200
JWT-SVID TTL     : 300
Selector         : type:key1:value
Selector         : type:key2:value
StoreSvid        : true

`,
			expOutJSON: fmt.Sprintf(`
{
  "results": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "entry": %s,
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "entry": %s,
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "entry": %s
    }
  ]
}`, entry1JSON, entry2JSON, entry3JSON),
		},
		{
			name: "Entry not found",
			args: []string{"-entryID", "non-existent-id", "-spiffeID", "spiffe://example.org/workload", "-parentID", "spiffe://example.org/parent", "-selector", "unix:uid:1"},
			expReq: &entryv1.BatchUpdateEntryRequest{Entries: []*types.Entry{
				{
					Id:        "non-existent-id",
					SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
					ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"},
					Selectors: []*types.Selector{{Type: "unix", Value: "uid:1"}},
				},
			}},
			fakeResp: fakeRespErr,
			expErrPretty: `Failed to update the following entry (code: NotFound, msg: "failed to update entry: datastore-sql: record not found"):
Entry ID         : non-existent-id
SPIFFE ID        : spiffe://example.org/workload
Parent ID        : spiffe://example.org/parent
Revision         : 0
X509-SVID TTL    : default
JWT-SVID TTL     : default
Selector         : unix:uid:1

Error: failed to update one or more entries
`,
			expOutJSON: fmt.Sprintf(`{
  "results": [
    {
      "status": {
        "code": 5,
        "message": "failed to update entry: datastore-sql: record not found"
      },
      "entry": %s
    }
  ]
}`, nonExistentEntryJSON),
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, newUpdateCommand)
				test.server.err = tt.serverErr
				test.server.expBatchUpdateEntryReq = tt.expReq
				test.server.batchUpdateEntryResp = tt.fakeResp
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

				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expOutPretty, tt.expOutJSON)
				require.Equal(t, 0, rc)
			})
		}
	}
}
