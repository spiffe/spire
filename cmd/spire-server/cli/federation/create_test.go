package federation

import (
	"crypto/x509"
	"errors"
	"os"
	"path"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testFile = `
{
    "federationRelationships": [
        {
    	   "trustDomain": "td-1.org",
    	   "bundleEndpointURL": "https://td-1.org/bundle",
    	   "bundleEndpointProfile": "https_web"
        },
        {
    	   "trustDomain": "td-2.org",
    	   "bundleEndpointURL": "https://td-2.org/bundle",
    	   "bundleEndpointProfile": "https_spiffe",
    	   "endpointSpiffeID": "spiffe://other.org/bundle"
        },
        {
    	"trustDomain": "td-3.org",
    	"bundleEndpointURL": "https://td-3.org/bundle",
    	"bundleEndpointProfile": "https_spiffe",
    	"endpointSPIFFEID": "spiffe://td-3.org/bundle",
    	"trustDomainBundle": "-----BEGIN CERTIFICATE-----\nMIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa\nGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyv\nsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXs\nRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkw\nF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09X\nmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylA\ndZglS5kKnYigmwDh+/U=\n-----END CERTIFICATE-----",
    	"trustDomainBundleFormat": "pem"
        },
        {
    	     "trustDomain": "td-4.org",
    	     "bundleEndpointURL": "https://td-4.org/bundle",
    	     "bundleEndpointProfile": "https_spiffe",
    	     "endpointSPIFFEID": "spiffe://td-4.org/bundle",
    	     "trustDomainBundleFormat": "spiffe",
    	     "trustDomainBundle": {
                 "keys": [
                     {
                         "use": "x509-svid",
                         "kty": "EC",
                         "crv": "P-256",
                         "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
                         "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI",
                         "x5c": [
                             "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyvsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09Xmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylAdZglS5kKnYigmwDh+/U="
                         ]
                     },
                     {
                         "use": "jwt-svid",
                         "kty": "EC",
                         "kid": "KID",
                         "crv": "P-256",
                         "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
                         "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI"
                     }
                 ]
             }
        }
    ]
}  
`
	pemCert = "-----BEGIN CERTIFICATE-----\nMIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa\nGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyv\nsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXs\nRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkw\nF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09X\nmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylA\ndZglS5kKnYigmwDh+/U=\n-----END CERTIFICATE-----"
	jwks    = `{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI",
            "x5c": [
                "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyvsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09Xmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylAdZglS5kKnYigmwDh+/U="
            ]
        },
        {
            "use": "jwt-svid",
            "kty": "EC",
            "kid": "KID",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI"
        }
    ]
}`
)

func TestCreatetHelp(t *testing.T) {
	test := setupTest(t, newCreateCommand)
	test.client.Help()

	require.Equal(t, `Usage of federation create:
  -bundleEndpointProfile string
    	Endpoint profile type (either "https_web" or "https_spiffe")
  -bundleEndpointURL string
    	URL of the SPIFFE bundle endpoint that provides the trust bundle (must use the HTTPS protocol)
  -data string
    	Path to a file containing federation relationships in JSON format (optional). If set to '-', read the JSON from stdin.
  -endpointSpiffeID string
    	SPIFFE ID of the SPIFFE bundle endpoint server. Only used for 'spiffe' profile.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -trustDomain string
    	Name of the trust domain to federate with (e.g., example.org)
  -trustDomainBundleFormat string
    	The format of the bundle data (optional). Either "pem" or "spiffe". (default "pem")
  -trustDomainBundlePath string
    	Path to the trust domain bundle data (optional).
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
			args:   []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-bundleEndpointProfile", profileHTTPSSPIFFE},
			expErr: "Error: endpoint SPIFFE ID is required if 'https_spiffe' endpoint profile is set\n",
		},
		{
			name:   "Invalid bundle endpoint SPIFFE ID",
			args:   []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-endpointSpiffeID", "invalid-id", "-trustDomainBundlePath", bundlePath, "-bundleEndpointProfile", profileHTTPSSPIFFE},
			expErr: "Error: cannot parse bundle endpoint SPIFFE ID: spiffeid: invalid scheme\n",
		},
		{
			name:   "Non-existent bundle file",
			args:   []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-endpointSpiffeID", "spiffe://td.org/bundle", "-trustDomainBundlePath", "non-existent-path", "-bundleEndpointProfile", profileHTTPSWeb},
			expErr: "Error: cannot read bundle file: open non-existent-path: no such file or directory\n",
		},
		{
			name:   "Corrupted bundle file",
			args:   []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-endpointSpiffeID", "spiffe://td.org/bundle", "-trustDomainBundlePath", corruptedBundlePath, "-bundleEndpointProfile", profileHTTPSWeb},
			expErr: "Error: cannot parse bundle file: unable to parse bundle data: no PEM blocks\n",
		},
		{
			name:      "Server error",
			args:      []string{"-trustDomain", "td.org", "-bundleEndpointURL", "https://td.org/bundle", "-bundleEndpointProfile", "https_web"},
			serverErr: errors.New("server error"),
			expErr:    "Error: request failed: rpc error: code = Unknown desc = server error\n",
		},
		{
			name: "Succeeds for SPIFFE profile",
			args: []string{"-trustDomain", "td-2.org", "-bundleEndpointURL", "https://td-2.org/bundle", "-endpointSpiffeID", "spiffe://other.org/bundle", "-bundleEndpointProfile", profileHTTPSSPIFFE},
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
			args: []string{"-trustDomain", "td-3.org", "-bundleEndpointURL", "https://td-3.org/bundle", "-endpointSpiffeID", "spiffe://td-3.org/bundle", "-trustDomainBundlePath", bundlePath, "-bundleEndpointProfile", profileHTTPSSPIFFE},
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
					frPemAuthority,
					frSPIFFEAuthority,
				},
			},
			fakeResp: &trustdomainv1.BatchCreateFederationRelationshipResponse{
				Results: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
					{FederationRelationship: frWeb, Status: &types.Status{}},
					{FederationRelationship: frSPIFFE, Status: &types.Status{}},
					{FederationRelationship: frPemAuthority, Status: &types.Status{}},
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
		{
			name:   "Loading federation relationships from JSON file: invalid path",
			args:   []string{"-data", "somePath"},
			expErr: "Error: open somePath: no such file or directory\n",
		},
		{
			name:   "Loading federation relationships from JSON file: no a json",
			args:   []string{"-data", bundlePath},
			expErr: "Error: failed to parse JSON: invalid character '-' in numeric literal\n",
		},
		{
			name:   "Loading federation relationships from JSON file: invalid relationship",
			args:   []string{"-data", jsonDataInvalidRelationship},
			expErr: "Error: could not parse item 0: trust domain is required\n",
		},
		{
			name:   "Loading federation relationships from JSON file: multiple flags",
			args:   []string{"-data", jsonDataInvalidRelationship, "-bundleEndpointURL", "https://td-1.org/bundle"},
			expErr: "Error: could not use aditional flags when 'data' is set\n",
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

func createJSONDataFile(t *testing.T, data string) string {
	jsonDataFilePath := path.Join(t.TempDir(), "bundle.pem")
	require.NoError(t, os.WriteFile(jsonDataFilePath, []byte(data), 0600))
	return jsonDataFilePath
}
