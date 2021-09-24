package federation

import (
	"errors"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestCreatetHelp(t *testing.T) {
	test := setupTest(t, newCreateCommand)
	test.client.Help()

	require.Equal(t, `Usage of federation create:
  -bundleEndpointProfile string
    	Endpoint profile type (either "https_web" or "https_spiffe") (default "https_spiffe")
  -bundleEndpointURL string
    	URL of the SPIFFE bundle endpoint that provides the trust bundle (must use the HTTPS protocol)
  -bundleFormat string
    	The format of the bundle data (optional). Either "pem" or "spiffe". Only used for 'spiffe' profile. (default "pem")
  -bundlePath string
    	Path to the bundle data (optional). Only used for 'spiffe' profile.
  -data string
    	Path to a file containing federation relationships in JSON format (optional). If set to '-', read the JSON from stdin.
  -endpointSpiffeID string
    	SPIFFE ID of the SPIFFE bundle endpoint server. Only used for 'spiffe' profile.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -trustDomain string
    	Name of the trust domain to federate with (e.g., example.org)
`, test.stderr.String())
}

func TestCreateSynopsis(t *testing.T) {
	test := setupTest(t, newCreateCommand)
	require.Equal(t, "Creates a federation relationship to a foreign trust domain", test.client.Synopsis())
}

func TestCreate(t *testing.T) {
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
				Bundle:           bundle,
			},
		},
	}

	corruptedBundlePath := createCorruptedBundle(t)

	jsonDataFilePath := createJSONDataFile(t, bundlePath)

	for _, tt := range []struct {
		name string
		args []string

		expReq    *trustdomainv1.BatchCreateFederationRelationshipRequest
		fakeResp  *trustdomainv1.BatchCreateFederationRelationshipResponse
		serverErr error

		expOut string
		expErr string
	}{
		{
			name:   "Missing trust domain",
			expErr: "Error: trust domain is required\n",
		},
		{
			name:   "Invalid trust domain",
			args:   []string{"-trustDomain", "invalid trustdomain"},
			expErr: "Error: cannot parse trust domain: spiffeid: unable to parse: parse \"spiffe://invalid trustdomain\": invalid character \" \" in host name\n",
		},
		{
			name:   "Missing bundle endpoint URL",
			args:   []string{"-trustDomain", "td.org"},
			expErr: "Error: bundle endpoint URL is required\n",
		},
		{
			name:   "Unknown endpoint profile",
			args:   []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-bundleEndpointProfile", "bad-type"},
			expErr: "Error: unknown bundle endpoint profile type: \"bad-type\"\n",
		},
		{
			name:   "Missing endpoint SPIFFE ID",
			args:   []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle"},
			expErr: "Error: endpoint SPIFFE ID is required if 'https_spiffe' endpoint profile is set\n",
		},
		{
			name:   "Invalid bundle endpoint SPIFFE ID",
			args:   []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-endpointSpiffeID", "invalid-id", "-bundlePath", bundlePath},
			expErr: "Error: cannot parse bundle endpoint SPIFFE ID: spiffeid: invalid scheme\n",
		},
		{
			name:   "Non-existent bundle file",
			args:   []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-endpointSpiffeID", "spiffe://td.org/bundle", "-bundlePath", "non-existent-path"},
			expErr: "Error: cannot read bundle file: open non-existent-path: no such file or directory\n",
		},
		{
			name:   "Corrupted bundle file",
			args:   []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-endpointSpiffeID", "spiffe://td.org/bundle", "-bundlePath", corruptedBundlePath},
			expErr: "Error: cannot parse bundle file: unable to parse bundle data: no PEM blocks\n",
		},
		{
			name:      "Server error",
			args:      []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-bundleEndpointProfile", "https_web"},
			serverErr: errors.New("server error"),
			expErr:    "Error: request failed: rpc error: code = Unknown desc = server error\n",
		},
		{
			name:   "EndpointSpiffeID is used with https_web profile",
			args:   []string{"-trustDomain", "td-1.org", "-bundleEndpointURL", "https://td-1.org/bundle", "-bundleEndpointProfile", "https_web", "-endpointSpiffeID", "A"},
			expErr: "Error: the 'https_web' endpoint profile does not expect an endpoint SPIFFE ID\n",
		},
		{
			name:   "BundlePath is used with https_web profile",
			args:   []string{"-trustDomain", "td-1.org", "-bundleEndpointURL", "https://td-1.org/bundle", "-bundleEndpointProfile", "https_web", "-bundlePath", "A"},
			expErr: "Error: the 'https_web' endpoint profile does not expect a bundle\n",
		},
		{
			name:   "Self serving endpoint missing bundle",
			args:   []string{"-trustDomain", "td-2.org", "-bundleEndpointURL", "https://td-2.org/bundle", "-endpointSpiffeID", "spiffe://td-2.org/bundle"},
			expErr: "Error: bundle is required for self-serving endpoint\n",
		},
		{
			name:   "Non self-serving endpoint includes bundle",
			args:   []string{"-trustDomain", "td-2.org", "-bundleEndpointURL", "https://td-2.org/bundle", "-endpointSpiffeID", "spiffe://other.org/bundle", "-bundlePath", "path"},
			expErr: "Error: bundle should only be present for a self-serving endpoint\n",
		},
		{
			name: "Succeeds for SPIFFE profile",
			args: []string{"-trustDomain", "td-2.org", "-bundleEndpointURL", "https://td-2.org/bundle", "-endpointSpiffeID", "spiffe://other.org/bundle"},
			expReq: &trustdomainv1.BatchCreateFederationRelationshipRequest{
				FederationRelationships: []*types.FederationRelationship{frSPIFFE},
			},
			fakeResp: &trustdomainv1.BatchCreateFederationRelationshipResponse{
				Results: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
					{
						Status:                 &types.Status{},
						FederationRelationship: frSPIFFE,
					},
				},
			},
			expOut: `
Trust domain              : td-2.org
Bundle endpoint URL       : https://td-2.org/bundle
Bundle endpoint profile   : https_spiffe
Endpoint SPIFFE ID        : spiffe://other.org/bundle
`,
		},
		{
			name: "Succeeds for SPIFFE profile and bundle",
			args: []string{"-trustDomain", "td-3.org", "-bundleEndpointURL", "https://td-3.org/bundle", "-endpointSpiffeID", "spiffe://td-3.org/bundle", "-bundlePath", bundlePath},
			expReq: &trustdomainv1.BatchCreateFederationRelationshipRequest{
				FederationRelationships: []*types.FederationRelationship{frSPIFFEAndBundle},
			},
			fakeResp: &trustdomainv1.BatchCreateFederationRelationshipResponse{
				Results: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
					{
						Status:                 &types.Status{},
						FederationRelationship: frSPIFFEAndBundle,
					},
				},
			},
			expOut: `
Trust domain              : td-3.org
Bundle endpoint URL       : https://td-3.org/bundle
Bundle endpoint profile   : https_spiffe
Endpoint SPIFFE ID        : spiffe://td-3.org/bundle
`,
		},
		{
			name: "Succeeds for web profile",
			args: []string{"-trustDomain", "td-1.org", "-bundleEndpointURL", "https://td-1.org/bundle", "-bundleEndpointProfile", "https_web"},
			expReq: &trustdomainv1.BatchCreateFederationRelationshipRequest{
				FederationRelationships: []*types.FederationRelationship{frWeb},
			},
			fakeResp: &trustdomainv1.BatchCreateFederationRelationshipResponse{
				Results: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
					{
						Status:                 &types.Status{},
						FederationRelationship: frWeb,
					},
				},
			},
			expOut: `
Trust domain              : td-1.org
Bundle endpoint URL       : https://td-1.org/bundle
Bundle endpoint profile   : https_web
`,
		},
		{
			name: "Federation relationships that failed to be created are printed",
			args: []string{"-trustDomain", "td-1.org", "-bundleEndpointURL", "https://td-1.org/bundle", "-bundleEndpointProfile", "https_web"},
			expReq: &trustdomainv1.BatchCreateFederationRelationshipRequest{
				FederationRelationships: []*types.FederationRelationship{frWeb},
			},
			fakeResp: &trustdomainv1.BatchCreateFederationRelationshipResponse{
				Results: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
					{
						Status: &types.Status{
							Code:    int32(codes.AlreadyExists),
							Message: "the message",
						},
						FederationRelationship: frWeb,
					},
				},
			},
			expErr: `Failed to create the following federation relationship (code: AlreadyExists, msg: "the message"):
Trust domain              : td-1.org
Bundle endpoint URL       : https://td-1.org/bundle
Bundle endpoint profile   : https_web
Error: failed to create one or more federation relationships
`,
		},
		{
			name: "Succeeds loading federation relationships from JSON file",
			args: []string{"-data", jsonDataFilePath},
			expReq: &trustdomainv1.BatchCreateFederationRelationshipRequest{
				FederationRelationships: []*types.FederationRelationship{
					frWeb,
					frSPIFFE,
					frSPIFFEAndBundle,
				},
			},
			fakeResp: &trustdomainv1.BatchCreateFederationRelationshipResponse{
				Results: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
					{FederationRelationship: frWeb, Status: &types.Status{}},
					{FederationRelationship: frSPIFFE, Status: &types.Status{}},
					{FederationRelationship: frSPIFFEAndBundle, Status: &types.Status{}},
				},
			},
			expOut: `
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
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, newCreateCommand)
			test.server.err = tt.serverErr
			test.server.expectCreateReq = tt.expReq
			test.server.createResp = tt.fakeResp

			args := append(test.args, tt.args...)
			rc := test.client.Run(args)
			if tt.expErr != "" {
				require.Equal(t, 1, rc)
				require.Equal(t, tt.expErr, test.stderr.String())
				return
			}

			require.Equal(t, 0, rc)
			require.Equal(t, tt.expOut, test.stdout.String())
		})
	}
}

func createBundle(t *testing.T, trustDomain string) (*types.Bundle, string) {
	td := spiffeid.RequireTrustDomainFromString(trustDomain)
	bundlePath := path.Join(t.TempDir(), "bundle.pem")
	ca := fakeserverca.New(t, td, &fakeserverca.Options{})
	require.NoError(t, pemutil.SaveCertificates(bundlePath, ca.Bundle(), 0600))

	return &types.Bundle{
		TrustDomain: td.String(),
		X509Authorities: []*types.X509Certificate{
			{Asn1: ca.X509CA().Certificate.Raw},
		},
	}, bundlePath
}

func createCorruptedBundle(t *testing.T) string {
	bundlePath := path.Join(t.TempDir(), "bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("corrupted-bundle"), 0600))
	return bundlePath
}

func createJSONDataFile(t *testing.T, bundlePath string) string {
	data := []byte(fmt.Sprintf(`
    {
	"federation_relationships": [
	    {
		"trust_domain": "td-1.org",
		"bundle_endpoint_url": "https://td-1.org/bundle",
		"bundle_endpoint_profile": "https_web"
	    },
	    {
		"trust_domain": "td-2.org",
		"bundle_endpoint_url": "https://td-2.org/bundle",
		"bundle_endpoint_profile": "https_spiffe",
		"endpoint_spiffe_id": "spiffe://other.org/bundle"
	    },
	    {
		"trust_domain": "td-3.org",
		"bundle_endpoint_url": "https://td-3.org/bundle",
		"bundle_endpoint_profile": "https_spiffe",
		"endpoint_spiffe_id": "spiffe://td-3.org/bundle",
		"bundle_path": %q,
		"bundle_format": "pem"
	    }
	]
    }  
`, bundlePath))

	jsonDataFilePath := path.Join(t.TempDir(), "bundle.pem")
	require.NoError(t, os.WriteFile(jsonDataFilePath, data, 0600))
	return jsonDataFilePath
}
