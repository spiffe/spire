package federation

import (
	"bytes"
	"context"
	"os"
	"path"
	"testing"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/clitest"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
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

var availableFormats = []string{"pretty", "json"}

type cmdTest struct {
	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer

	addr   string
	server *fakeServer

	client cli.Command
}

func (c *cmdTest) afterTest(t *testing.T) {
	t.Logf("TEST:%s", t.Name())
	t.Logf("STDOUT:\n%s", c.stdout.String())
	t.Logf("STDIN:\n%s", c.stdin.String())
	t.Logf("STDERR:\n%s", c.stderr.String())
}

func (c *cmdTest) args(extra ...string) []string {
	return append([]string{clitest.AddrArg, c.addr}, extra...)
}

type fakeServer struct {
	trustdomainv1.UnimplementedTrustDomainServer

	t   *testing.T
	err error

	expectCreateReq  *trustdomainv1.BatchCreateFederationRelationshipRequest
	expectDeleteReq  *trustdomainv1.BatchDeleteFederationRelationshipRequest
	expectListReq    *trustdomainv1.ListFederationRelationshipsRequest
	expectShowReq    *trustdomainv1.GetFederationRelationshipRequest
	expectRefreshReq *trustdomainv1.RefreshBundleRequest
	expectUpdateReq  *trustdomainv1.BatchUpdateFederationRelationshipRequest

	createResp  *trustdomainv1.BatchCreateFederationRelationshipResponse
	deleteResp  *trustdomainv1.BatchDeleteFederationRelationshipResponse
	listResp    *trustdomainv1.ListFederationRelationshipsResponse
	showResp    *types.FederationRelationship
	refreshResp *emptypb.Empty
	updateResp  *trustdomainv1.BatchUpdateFederationRelationshipResponse
}

func (f *fakeServer) BatchCreateFederationRelationship(_ context.Context, req *trustdomainv1.BatchCreateFederationRelationshipRequest) (*trustdomainv1.BatchCreateFederationRelationshipResponse, error) {
	if f.err != nil {
		return nil, f.err
	}

	spiretest.AssertProtoEqual(f.t, f.expectCreateReq, req)
	return f.createResp, nil
}

func (f *fakeServer) BatchDeleteFederationRelationship(_ context.Context, req *trustdomainv1.BatchDeleteFederationRelationshipRequest) (*trustdomainv1.BatchDeleteFederationRelationshipResponse, error) {
	if f.err != nil {
		return nil, f.err
	}

	spiretest.AssertProtoEqual(f.t, f.expectDeleteReq, req)
	return f.deleteResp, nil
}

func (f *fakeServer) ListFederationRelationships(_ context.Context, req *trustdomainv1.ListFederationRelationshipsRequest) (*trustdomainv1.ListFederationRelationshipsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}

	spiretest.AssertProtoEqual(f.t, f.expectListReq, req)
	return f.listResp, nil
}

func (f *fakeServer) GetFederationRelationship(_ context.Context, req *trustdomainv1.GetFederationRelationshipRequest) (*types.FederationRelationship, error) {
	if f.err != nil {
		return nil, f.err
	}

	if f.showResp != nil {
		require.Equal(f.t, f.showResp.TrustDomain, req.TrustDomain)
		return f.showResp, nil
	}
	return &types.FederationRelationship{}, status.Error(codes.NotFound, "federation relationship does not exist")
}

func (f *fakeServer) RefreshBundle(_ context.Context, req *trustdomainv1.RefreshBundleRequest) (*emptypb.Empty, error) {
	if f.err != nil {
		return nil, f.err
	}

	spiretest.AssertProtoEqual(f.t, f.expectRefreshReq, req)
	return f.refreshResp, nil
}

func (f *fakeServer) BatchUpdateFederationRelationship(_ context.Context, req *trustdomainv1.BatchUpdateFederationRelationshipRequest) (*trustdomainv1.BatchUpdateFederationRelationshipResponse, error) {
	if f.err != nil {
		return nil, f.err
	}

	spiretest.AssertProtoEqual(f.t, f.expectUpdateReq, req)
	return f.updateResp, nil
}

func setupTest(t *testing.T, newClient func(*common_cli.Env) cli.Command) *cmdTest {
	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	client := newClient(&common_cli.Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	})

	server := &fakeServer{t: t}
	addr := spiretest.StartGRPCServer(t, func(s *grpc.Server) {
		trustdomainv1.RegisterTrustDomainServer(s, server)
	})

	test := &cmdTest{
		addr:   clitest.GetAddr(addr),
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		server: server,
		client: client,
	}

	t.Cleanup(func() {
		test.afterTest(t)
	})

	return test
}

func createBundle(t *testing.T, trustDomain string) (*types.Bundle, string) {
	td := spiffeid.RequireTrustDomainFromString(trustDomain)
	bundlePath := path.Join(t.TempDir(), "bundle.pem")
	ca := fakeserverca.New(t, td, &fakeserverca.Options{})
	require.NoError(t, os.WriteFile(bundlePath, pemutil.EncodeCertificates(ca.Bundle()), 0o600))

	return &types.Bundle{
		TrustDomain: td.Name(),
		X509Authorities: []*types.X509Certificate{
			{Asn1: ca.Bundle()[0].Raw},
		},
	}, bundlePath
}

func createCorruptedBundle(t *testing.T) string {
	bundlePath := path.Join(t.TempDir(), "bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("corrupted-bundle"), 0o600))
	return bundlePath
}

func createJSONDataFile(t *testing.T, data string) string {
	jsonDataFilePath := path.Join(t.TempDir(), "bundle.pem")
	require.NoError(t, os.WriteFile(jsonDataFilePath, []byte(data), 0o600))
	return jsonDataFilePath
}

func requireOutputBasedOnFormat(t *testing.T, format, stdoutString string, expectedStdoutPretty, expectedStdoutJSON string) {
	switch format {
	case "pretty":
		require.Contains(t, stdoutString, expectedStdoutPretty)
	case "json":
		if expectedStdoutJSON != "" {
			require.JSONEq(t, expectedStdoutJSON, stdoutString)
		} else {
			require.Empty(t, stdoutString)
		}
	}
}
