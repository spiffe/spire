package bundle

import (
	"bytes"
	"context"
	"crypto/x509"
	"testing"

	"github.com/mitchellh/cli"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	cert1PEM = `-----BEGIN CERTIFICATE-----
MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyv
sCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXs
RxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkw
F4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09X
makw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylA
dZglS5kKnYigmwDh+/U=
-----END CERTIFICATE-----
`

	cert2PEM = `-----BEGIN CERTIFICATE-----
MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB8V
bmlJ8YIuN9RuQ94PYanmkIRG7MkGV5mmrO6rFAv3SFd/uVlwYNkXrh0219eHUSD4
o+4RGXoiMFJKysw5GK6jODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkw
F4YVc3BpZmZlOi8vZG9tYWluMi50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIQDMKwYt
q+2ZoNyl4udPj7IMYIGX8yuCNRmh7m3d9tvoDgIgbS26wSwDjngGqdiHHL8fTcgg
diIqWtxAqBLFrx8zNS4=
-----END CERTIFICATE-----
`

	otherDomainJWKS = `{
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
`

	cert1JWKS = `{
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
        }
    ],
    "spiffe_refresh_hint": 60
}
`

	cert2JWKS = `{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "HxVuaUnxgi431G5D3g9hqeaQhEbsyQZXmaas7qsUC_c",
            "y": "SFd_uVlwYNkXrh0219eHUSD4o-4RGXoiMFJKysw5GK4",
            "x5c": [
                "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB8VbmlJ8YIuN9RuQ94PYanmkIRG7MkGV5mmrO6rFAv3SFd/uVlwYNkXrh0219eHUSD4o+4RGXoiMFJKysw5GK6jODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMi50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIQDMKwYtq+2ZoNyl4udPj7IMYIGX8yuCNRmh7m3d9tvoDgIgbS26wSwDjngGqdiHHL8fTcggdiIqWtxAqBLFrx8zNS4="
            ]
        }
    ]
}
`

	allBundlesPEM = `****************************************
* spiffe://domain1.test
****************************************
-----BEGIN CERTIFICATE-----
MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyv
sCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXs
RxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkw
F4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09X
makw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylA
dZglS5kKnYigmwDh+/U=
-----END CERTIFICATE-----

****************************************
* spiffe://domain2.test
****************************************
-----BEGIN CERTIFICATE-----
MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB8V
bmlJ8YIuN9RuQ94PYanmkIRG7MkGV5mmrO6rFAv3SFd/uVlwYNkXrh0219eHUSD4
o+4RGXoiMFJKysw5GK6jODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkw
F4YVc3BpZmZlOi8vZG9tYWluMi50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIQDMKwYt
q+2ZoNyl4udPj7IMYIGX8yuCNRmh7m3d9tvoDgIgbS26wSwDjngGqdiHHL8fTcgg
diIqWtxAqBLFrx8zNS4=
-----END CERTIFICATE-----
`

	allBundlesJWKS = `****************************************
* spiffe://domain1.test
****************************************
{
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

****************************************
* spiffe://domain2.test
****************************************
{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "HxVuaUnxgi431G5D3g9hqeaQhEbsyQZXmaas7qsUC_c",
            "y": "SFd_uVlwYNkXrh0219eHUSD4o-4RGXoiMFJKysw5GK4",
            "x5c": [
                "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB8VbmlJ8YIuN9RuQ94PYanmkIRG7MkGV5mmrO6rFAv3SFd/uVlwYNkXrh0219eHUSD4o+4RGXoiMFJKysw5GK6jODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMi50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIQDMKwYtq+2ZoNyl4udPj7IMYIGX8yuCNRmh7m3d9tvoDgIgbS26wSwDjngGqdiHHL8fTcggdiIqWtxAqBLFrx8zNS4="
            ]
        }
    ]
}
`
)

func setupTest(t *testing.T, newClient func(*common_cli.Env) cli.Command) *bundleTest {
	cert1, err := pemutil.ParseCertificate([]byte(cert1PEM))
	require.NoError(t, err)

	key1Pkix, err := x509.MarshalPKIXPublicKey(cert1.PublicKey)
	require.NoError(t, err)

	cert2, err := pemutil.ParseCertificate([]byte(cert2PEM))
	require.NoError(t, err)

	server := &fakeBundleServer{t: t}

	socketPath := spiretest.StartGRPCSocketServerOnTempSocket(t, func(s *grpc.Server) {
		bundle.RegisterBundleServer(s, server)
	})

	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	client := newClient(&common_cli.Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	})

	test := &bundleTest{
		cert1:    cert1,
		cert2:    cert2,
		key1Pkix: key1Pkix,
		stdin:    stdin,
		stdout:   stdout,
		stderr:   stderr,
		args:     []string{"-socketPath", socketPath},
		server:   server,
		client:   client,
	}

	t.Cleanup(func() {
		test.afterTest(t)
	})

	return test
}

type bundleTest struct {
	cert1    *x509.Certificate
	cert2    *x509.Certificate
	key1Pkix []byte

	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer

	args   []string
	server *fakeBundleServer

	client cli.Command
}

func (s *bundleTest) afterTest(t *testing.T) {
	t.Logf("TEST:%s", t.Name())
	t.Logf("STDOUT:\n%s", s.stdout.String())
	t.Logf("STDIN:\n%s", s.stdin.String())
	t.Logf("STDERR:\n%s", s.stderr.String())
}

type fakeBundleServer struct {
	bundle.BundleServer

	t                 testing.TB
	bundles           []*types.Bundle
	deleteResults     []*bundle.BatchDeleteFederatedBundleResponse_Result
	err               error
	expectedSetBundle *types.Bundle
	mode              bundle.BatchDeleteFederatedBundleRequest_Mode
	setResponse       *bundle.BatchSetFederatedBundleResponse
	toDelete          []string
}

func (f *fakeBundleServer) GetBundle(ctx context.Context, in *bundle.GetBundleRequest) (*types.Bundle, error) {
	if f.err != nil {
		return nil, f.err
	}
	require.NotEmpty(f.t, f.bundles)

	return f.bundles[0], nil
}

func (f *fakeBundleServer) BatchSetFederatedBundle(ctx context.Context, req *bundle.BatchSetFederatedBundleRequest) (*bundle.BatchSetFederatedBundleResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	spiretest.AssertProtoEqual(f.t, f.expectedSetBundle, req.Bundle[0])

	return f.setResponse, nil
}

func (f *fakeBundleServer) CountBundles(context.Context, *bundle.CountBundlesRequest) (*bundle.CountBundlesResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &bundle.CountBundlesResponse{
		Count: int32(len(f.bundles)),
	}, nil
}

func (f *fakeBundleServer) ListFederatedBundles(context.Context, *bundle.ListFederatedBundlesRequest) (*bundle.ListFederatedBundlesResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &bundle.ListFederatedBundlesResponse{
		Bundles: f.bundles,
	}, nil
}

func (f *fakeBundleServer) GetFederatedBundle(ctx context.Context, req *bundle.GetFederatedBundleRequest) (*types.Bundle, error) {
	if f.err != nil {
		return nil, f.err
	}

	for _, b := range f.bundles {
		if b.TrustDomain == req.TrustDomain {
			return b, nil
		}
	}

	return nil, status.New(codes.NotFound, "not found").Err()
}

func (f *fakeBundleServer) BatchDeleteFederatedBundle(ctx context.Context, req *bundle.BatchDeleteFederatedBundleRequest) (*bundle.BatchDeleteFederatedBundleResponse, error) {
	if f.err != nil {
		return nil, f.err
	}

	require.Equal(f.t, f.toDelete, req.TrustDomains)
	require.Equal(f.t, f.mode, req.Mode)

	return &bundle.BatchDeleteFederatedBundleResponse{
		Results: f.deleteResults,
	}, nil
}
