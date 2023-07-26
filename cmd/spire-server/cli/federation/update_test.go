package federation

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/test/spiretest"
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
	require.Equal(t, "Updates a dynamic federation relationship with a foreign trust domain", test.client.Synopsis())
}

func TestUpdate(t *testing.T) {
	frWeb := &types.FederationRelationship{
		TrustDomain:           "td-1.org",
		BundleEndpointUrl:     "https://td-1.org/bundle",
		BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
	}

	frSPIFFE := &types.FederationRelationship{
		TrustDomain:       "td-2.org",
		BundleEndpointUrl: "https://td-2.org/bundle",
		BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
			HttpsSpiffe: &types.HTTPSSPIFFEProfile{
				EndpointSpiffeId: "spiffe://other.org/bundle",
			},
		},
	}

	bundle, bundlePath := createBundle(t, "td-3.org")
	frSPIFFEAndBundle := &types.FederationRelationship{
		TrustDomain:       "td-3.org",
		BundleEndpointUrl: "https://td-3.org/bundle",
		BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
			HttpsSpiffe: &types.HTTPSSPIFFEProfile{
				EndpointSpiffeId: "spiffe://td-3.org/bundle",
			},
		},
		TrustDomainBundle: bundle,
	}

	corruptedBundlePath := createCorruptedBundle(t)

	jsonDataFilePath := createJSONDataFile(t, testFile)

	jsonDataInvalidRelationship := createJSONDataFile(t, `
{
    "federationRelationships": [
        {
        	"trustDomain": "",
        	"bundleEndpointURL": "https://td-1.org/bundle",
        	"bundleEndpointProfile": "https_web"
        }
    ]
}
`)

	x509Authority, err := pemutil.ParseCertificate([]byte(pemCert))
	require.NoError(t, err)
	frPemAuthority := &types.FederationRelationship{
		TrustDomain:       "td-3.org",
		BundleEndpointUrl: "https://td-3.org/bundle",
		BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
			HttpsSpiffe: &types.HTTPSSPIFFEProfile{
				EndpointSpiffeId: "spiffe://td-3.org/bundle",
			},
		},
		TrustDomainBundle: &types.Bundle{
			TrustDomain: "td-3.org",
			X509Authorities: []*types.X509Certificate{
				{Asn1: x509Authority.Raw},
			},
		},
	}

	spiffeBundle, err := spiffebundle.Parse(spiffeid.RequireTrustDomainFromString("td-4.org"), []byte(jwks))
	require.NoError(t, err)

	var x509Authorities []*types.X509Certificate
	for _, cert := range spiffeBundle.X509Authorities() {
		x509Authorities = append(x509Authorities, &types.X509Certificate{
			Asn1: cert.Raw,
		})
	}
	require.Len(t, x509Authorities, 1)

	var jwtAuthorities []*types.JWTKey
	for id, key := range spiffeBundle.JWTAuthorities() {
		keyBytes, err := x509.MarshalPKIXPublicKey(key)
		require.NoError(t, err)

		jwtAuthorities = append(jwtAuthorities, &types.JWTKey{
			KeyId:     id,
			PublicKey: keyBytes,
		})
	}
	require.Len(t, jwtAuthorities, 1)

	frSPIFFEAuthority := &types.FederationRelationship{
		TrustDomain:       "td-4.org",
		BundleEndpointUrl: "https://td-4.org/bundle",
		BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
			HttpsSpiffe: &types.HTTPSSPIFFEProfile{
				EndpointSpiffeId: "spiffe://td-4.org/bundle",
			},
		},
		TrustDomainBundle: &types.Bundle{
			TrustDomain:     "td-4.org",
			X509Authorities: x509Authorities,
			JwtAuthorities:  jwtAuthorities,
		},
	}

	for _, tt := range []struct {
		name string
		args []string

		expReq    *trustdomainv1.BatchUpdateFederationRelationshipRequest
		fakeResp  *trustdomainv1.BatchUpdateFederationRelationshipResponse
		serverErr error

		expOutPretty string
		expErrPretty string
		expOutJSON   string
		expErrJSON   string
	}{
		{
			name:         "Missing trust domain",
			expErrPretty: "Error: trust domain is required\n",
			expErrJSON:   "Error: trust domain is required\n",
		},
		{
			name:         "Missing bundle endpoint URL",
			args:         []string{"-trustDomain", "td.org"},
			expErrPretty: "Error: bundle endpoint URL is required\n",
			expErrJSON:   "Error: bundle endpoint URL is required\n",
		},
		{
			name:         "Unknown endpoint profile",
			args:         []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-bundleEndpointProfile", "bad-type"},
			expErrPretty: "Error: unknown bundle endpoint profile type: \"bad-type\"\n",
			expErrJSON:   "Error: unknown bundle endpoint profile type: \"bad-type\"\n",
		},
		{
			name:         "Missing endpoint SPIFFE ID",
			args:         []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-bundleEndpointProfile", profileHTTPSSPIFFE},
			expErrPretty: "Error: endpoint SPIFFE ID is required if 'https_spiffe' endpoint profile is set\n",
			expErrJSON:   "Error: endpoint SPIFFE ID is required if 'https_spiffe' endpoint profile is set\n",
		},
		{
			name:         "Invalid bundle endpoint SPIFFE ID",
			args:         []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-endpointSpiffeID", "invalid-id", "-trustDomainBundlePath", bundlePath, "-bundleEndpointProfile", profileHTTPSSPIFFE},
			expErrPretty: "Error: cannot parse bundle endpoint SPIFFE ID: scheme is missing or invalid\n",
			expErrJSON:   "Error: cannot parse bundle endpoint SPIFFE ID: scheme is missing or invalid\n",
		},
		{
			name:         "Non-existent bundle file",
			args:         []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-endpointSpiffeID", "spiffe://td.org/bundle", "-trustDomainBundlePath", "non-existent-path", "-bundleEndpointProfile", profileHTTPSWeb},
			expErrPretty: fmt.Sprintf("Error: cannot read bundle file: open non-existent-path: %s\n", spiretest.FileNotFound()),
			expErrJSON:   fmt.Sprintf("Error: cannot read bundle file: open non-existent-path: %s\n", spiretest.FileNotFound()),
		},
		{
			name:         "Corrupted bundle file",
			args:         []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-endpointSpiffeID", "spiffe://td.org/bundle", "-trustDomainBundlePath", corruptedBundlePath, "-bundleEndpointProfile", profileHTTPSWeb},
			expErrPretty: "Error: cannot parse bundle file: unable to parse bundle data: no PEM blocks\n",
			expErrJSON:   "Error: cannot parse bundle file: unable to parse bundle data: no PEM blocks\n",
		},
		{
			name:         "Server error",
			args:         []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-bundleEndpointProfile", "https_web"},
			serverErr:    errors.New("server error"),
			expErrPretty: "Error: request failed: rpc error: code = Unknown desc = server error\n",
			expErrJSON:   "Error: request failed: rpc error: code = Unknown desc = server error\n",
		},
		{
			name: "Succeeds for SPIFFE profile",
			args: []string{"-trustDomain", "td-2.org", "-bundleEndpointURL", "https://td-2.org/bundle", "-endpointSpiffeID", "spiffe://other.org/bundle", "-bundleEndpointProfile", profileHTTPSSPIFFE},
			expReq: &trustdomainv1.BatchUpdateFederationRelationshipRequest{
				FederationRelationships: []*types.FederationRelationship{frSPIFFE},
			},
			fakeResp: &trustdomainv1.BatchUpdateFederationRelationshipResponse{
				Results: []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
					{
						Status:                 api.OK(),
						FederationRelationship: frSPIFFE,
					},
				},
			},
			expOutPretty: `
Trust domain              : td-2.org
Bundle endpoint URL       : https://td-2.org/bundle
Bundle endpoint profile   : https_spiffe
Endpoint SPIFFE ID        : spiffe://other.org/bundle
`,
			expOutJSON: `{
  "results": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "federation_relationship": {
        "trust_domain": "td-2.org",
        "bundle_endpoint_url": "https://td-2.org/bundle",
        "https_spiffe": {
          "endpoint_spiffe_id": "spiffe://other.org/bundle"
        }
      }
    }
  ]
}`,
		},
		{
			name: "Succeeds for SPIFFE profile and bundle",
			args: []string{"-trustDomain", "td-3.org", "-bundleEndpointURL", "https://td-3.org/bundle", "-endpointSpiffeID", "spiffe://td-3.org/bundle", "-trustDomainBundlePath", bundlePath, "-bundleEndpointProfile", profileHTTPSSPIFFE},
			expReq: &trustdomainv1.BatchUpdateFederationRelationshipRequest{
				FederationRelationships: []*types.FederationRelationship{frSPIFFEAndBundle},
			},
			fakeResp: &trustdomainv1.BatchUpdateFederationRelationshipResponse{
				Results: []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
					{
						Status:                 api.OK(),
						FederationRelationship: frSPIFFEAndBundle,
					},
				},
			},
			expOutPretty: `
Trust domain              : td-3.org
Bundle endpoint URL       : https://td-3.org/bundle
Bundle endpoint profile   : https_spiffe
Endpoint SPIFFE ID        : spiffe://td-3.org/bundle
`,
			expOutJSON: fmt.Sprintf(`{
  "results": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "federation_relationship": {
        "trust_domain": "td-3.org",
        "bundle_endpoint_url": "https://td-3.org/bundle",
        "https_spiffe": {
          "endpoint_spiffe_id": "spiffe://td-3.org/bundle"
        },
        "trust_domain_bundle": {
          "trust_domain": "td-3.org",
          "x509_authorities": [
            {
              "asn1": "%s",
	      "tainted": false
            }
          ],
          "jwt_authorities": [],
          "refresh_hint": "0",
          "sequence_number": "0"
        }
      }
    }
  ]
}`, base64.StdEncoding.EncodeToString(bundle.X509Authorities[0].Asn1)),
		},
		{
			name: "Succeeds for web profile",
			args: []string{"-trustDomain", "td-1.org", "-bundleEndpointURL", "https://td-1.org/bundle", "-bundleEndpointProfile", "https_web"},
			expReq: &trustdomainv1.BatchUpdateFederationRelationshipRequest{
				FederationRelationships: []*types.FederationRelationship{frWeb},
			},
			fakeResp: &trustdomainv1.BatchUpdateFederationRelationshipResponse{
				Results: []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
					{
						Status:                 api.OK(),
						FederationRelationship: frWeb,
					},
				},
			},
			expOutPretty: `
Trust domain              : td-1.org
Bundle endpoint URL       : https://td-1.org/bundle
Bundle endpoint profile   : https_web
`,
			expOutJSON: `{
  "results": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "federation_relationship": {
        "trust_domain": "td-1.org",
        "bundle_endpoint_url": "https://td-1.org/bundle",
        "https_web": {}
      }
    }
  ]
}`,
		},
		{
			name: "Federation relationships that failed to be updated are printed",
			args: []string{"-trustDomain", "td-1.org", "-bundleEndpointURL", "https://td-1.org/bundle", "-bundleEndpointProfile", "https_web"},
			expReq: &trustdomainv1.BatchUpdateFederationRelationshipRequest{
				FederationRelationships: []*types.FederationRelationship{frWeb},
			},
			fakeResp: &trustdomainv1.BatchUpdateFederationRelationshipResponse{
				Results: []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
					{
						Status: &types.Status{
							Code:    int32(codes.AlreadyExists),
							Message: "the message",
						},
						FederationRelationship: frWeb,
					},
				},
			},
			expErrPretty: `Failed to update the following federation relationship (code: AlreadyExists, msg: "the message"):
Trust domain              : td-1.org
Bundle endpoint URL       : https://td-1.org/bundle
Bundle endpoint profile   : https_web
Error: failed to update one or more federation relationships
`,
			expOutJSON: `{
  "results": [
    {
      "status": {
        "code": 6,
        "message": "the message"
      },
      "federation_relationship": {
        "trust_domain": "td-1.org",
        "bundle_endpoint_url": "https://td-1.org/bundle",
        "https_web": {}
      }
    }
  ]
}`,
		},
		{
			name: "Succeeds loading federation relationships from JSON file",
			args: []string{"-data", jsonDataFilePath},
			expReq: &trustdomainv1.BatchUpdateFederationRelationshipRequest{
				FederationRelationships: []*types.FederationRelationship{
					frWeb,
					frSPIFFE,
					frPemAuthority,
					frSPIFFEAuthority,
				},
			},
			fakeResp: &trustdomainv1.BatchUpdateFederationRelationshipResponse{
				Results: []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
					{FederationRelationship: frWeb, Status: api.OK()},
					{FederationRelationship: frSPIFFE, Status: api.OK()},
					{FederationRelationship: frPemAuthority, Status: api.OK()},
				},
			},
			expOutPretty: `
Trust domain              : td-1.org
Bundle endpoint URL       : https://td-1.org/bundle
Bundle endpoint profile   : https_web

Trust domain              : td-2.org
Bundle endpoint URL       : https://td-2.org/bundle
Bundle endpoint profile   : https_spiffe
Endpoint SPIFFE ID        : spiffe://other.org/bundle

Trust domain              : td-3.org
Bundle endpoint URL       : https://td-3.org/bundle
Bundle endpoint profile   : https_spiffe
Endpoint SPIFFE ID        : spiffe://td-3.org/bundle
`,
			expOutJSON: `{
  "results": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "federation_relationship": {
        "trust_domain": "td-1.org",
        "bundle_endpoint_url": "https://td-1.org/bundle",
        "https_web": {}
      }
    },
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "federation_relationship": {
        "trust_domain": "td-2.org",
        "bundle_endpoint_url": "https://td-2.org/bundle",
        "https_spiffe": {
          "endpoint_spiffe_id": "spiffe://other.org/bundle"
        }
      }
    },
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "federation_relationship": {
        "trust_domain": "td-3.org",
        "bundle_endpoint_url": "https://td-3.org/bundle",
        "https_spiffe": {
          "endpoint_spiffe_id": "spiffe://td-3.org/bundle"
        },
        "trust_domain_bundle": {
          "trust_domain": "td-3.org",
          "x509_authorities": [
            {
              "asn1": "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyvsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09Xmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylAdZglS5kKnYigmwDh+/U=",
	      "tainted": false
            }
          ],
          "jwt_authorities": [],
          "refresh_hint": "0",
          "sequence_number": "0"
        }
      }
    }
  ]
}`,
		},
		{
			name:         "Loading federation relationships from JSON file: invalid path",
			args:         []string{"-data", "somePath"},
			expErrPretty: fmt.Sprintf("Error: open somePath: %s\n", spiretest.FileNotFound()),
			expErrJSON:   fmt.Sprintf("Error: open somePath: %s\n", spiretest.FileNotFound()),
		},
		{
			name:         "Loading federation relationships from JSON file: no a json",
			args:         []string{"-data", bundlePath},
			expErrPretty: "Error: failed to parse JSON: invalid character '-' in numeric literal\n",
			expErrJSON:   "Error: failed to parse JSON: invalid character '-' in numeric literal\n",
		},
		{
			name:         "Loading federation relationships from JSON file: invalid relationship",
			args:         []string{"-data", jsonDataInvalidRelationship},
			expErrPretty: "Error: could not parse item 0: trust domain is required\n",
			expErrJSON:   "Error: could not parse item 0: trust domain is required\n",
		},
		{
			name:         "Loading federation relationships from JSON file: multiple flags",
			args:         []string{"-data", jsonDataInvalidRelationship, "-bundleEndpointURL", "https://td-1.org/bundle"},
			expErrPretty: "Error: cannot use other flags to specify relationship fields when 'data' flag is set\n",
			expErrJSON:   "Error: cannot use other flags to specify relationship fields when 'data' flag is set\n",
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, newUpdateCommand)
				test.server.err = tt.serverErr
				test.server.expectUpdateReq = tt.expReq
				test.server.updateResp = tt.fakeResp
				args := tt.args
				args = append(args, "-output", format)

				rc := test.client.Run(test.args(args...))

				if tt.expErrPretty != "" && format == "pretty" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expErrPretty, test.stderr.String())
					return
				}
				if tt.expErrJSON != "" && format == "json" {
					require.Equal(t, 1, rc)
					require.Equal(t, tt.expErrJSON, test.stderr.String())
					return
				}
				require.Equal(t, 0, rc)
				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expOutPretty, tt.expOutJSON)
			})
		}
	}
}
