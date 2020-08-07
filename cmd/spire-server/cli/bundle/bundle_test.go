package bundle

import (
	"bytes"
	"context"
	"crypto/x509"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeregistrationclient"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
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

type bundleTest struct {
	cert1    *x509.Certificate
	cert2    *x509.Certificate
	key1Pkix []byte

	ds                 *fakedatastore.DataStore
	registrationClient *fakeregistrationclient.Client
	testEnv            *env

	showCmd   cli.Command
	setCmd    cli.Command
	listCmd   cli.Command
	deleteCmd cli.Command
}

func setupTest(t *testing.T) *bundleTest {
	cert1, err := pemutil.ParseCertificate([]byte(cert1PEM))
	require.NoError(t, err)

	key1Pkix, err := x509.MarshalPKIXPublicKey(cert1.PublicKey)
	require.NoError(t, err)

	cert2, err := pemutil.ParseCertificate([]byte(cert2PEM))
	require.NoError(t, err)

	ds := fakedatastore.New(t)
	registrationClient := fakeregistrationclient.New(t, "spiffe://example.test", ds, nil)

	testEnv := &env{
		stdin:  new(bytes.Buffer),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}
	clientMaker := func(string) (*clients, error) {
		return &clients{
			r: registrationClient,
		}, nil
	}

	t.Cleanup(func() {
		registrationClient.Close()
	})

	return &bundleTest{
		cert1:              cert1,
		cert2:              cert2,
		key1Pkix:           key1Pkix,
		ds:                 ds,
		registrationClient: fakeregistrationclient.New(t, "spiffe://example.test", ds, nil),
		testEnv:            testEnv,
		showCmd:            newShowCommand(testEnv, clientMaker),
		setCmd:             newSetCommand(testEnv, clientMaker),
		listCmd:            newListCommand(testEnv, clientMaker),
		deleteCmd:          newDeleteCommand(testEnv, clientMaker),
	}
}

func (s *bundleTest) AfterTest(t *testing.T, suiteName, testName string) {
	t.Logf("SUITE: %s TEST:%s", suiteName, testName)
	t.Logf("STDOUT:\n%s", s.testEnv.stdout.(*bytes.Buffer).String())
	t.Logf("STDIN:\n%s", s.testEnv.stdin.(*bytes.Buffer).String())
	t.Logf("STDERR:\n%s", s.testEnv.stderr.(*bytes.Buffer).String())
}

func TestShowHelp(t *testing.T) {
	test := setupTest(t)

	test.showCmd.Help()
	require.Equal(t, `Usage of bundle show:
  -format string
    	The format to show the bundle. Either "pem" or "spiffe". (default "pem")
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
`, test.testEnv.stderr.(*bytes.Buffer).String())
}

func TestShow(t *testing.T) {
	for _, tt := range []struct {
		name        string
		args        []string
		expectedOut string
	}{
		{
			name:        "default",
			expectedOut: cert1PEM,
		},
		{
			name:        "pem",
			args:        []string{"-format", formatPEM},
			expectedOut: cert1PEM,
		},
		{
			name:        "spiffe",
			args:        []string{"-format", formatSPIFFE},
			expectedOut: cert1JWKS,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t)
			test.createBundle(t, &common.Bundle{
				TrustDomainId: "spiffe://example.test",
				RootCas: []*common.Certificate{
					{DerBytes: test.cert1.Raw},
				},
				RefreshHint: 60,
			})

			require.Equal(t, 0, test.showCmd.Run(tt.args))
			require.Equal(t, test.testEnv.stdout.(*bytes.Buffer).String(), tt.expectedOut)
		})
	}
}

func TestSetHelp(t *testing.T) {
	test := setupTest(t)

	test.setCmd.Help()
	require.Equal(t, `Usage of bundle set:
  -format string
    	The format of the bundle data. Either "pem" or "spiffe". (default "pem")
  -id string
    	SPIFFE ID of the trust domain
  -path string
    	Path to the bundle data
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
`, test.testEnv.stderr.(*bytes.Buffer).String())
}

func TestSet(t *testing.T) {
	for _, tt := range []struct {
		name           string
		args           []string
		expectedStderr string
		stdin          string
		createBundle   bool
		fileData       string
	}{
		{
			name:           "no id",
			expectedStderr: "id flag is required\n",
		},
		{
			name:           "invalid trust domain ID",
			expectedStderr: "\"spiffe://otherdomain.test/spire/server\" is not a valid trust domain SPIFFE ID: path is not empty\n",
			args:           []string{"-id", "spiffe://otherdomain.test/spire/server"},
		},
		{
			name:           "invalid trust domain ID",
			expectedStderr: "unable to parse bundle data: no PEM blocks\n",
			args:           []string{"-id", "spiffe://otherdomain.test"},
		},
		{
			name:  "create bundle (default)",
			stdin: cert1PEM,
			args:  []string{"-id", "spiffe://otherdomain.test"},
		},
		{
			name:  "create bundle (pem)",
			stdin: cert1PEM,
			args:  []string{"-id", "spiffe://otherdomain.test", "-format", formatPEM},
		},
		{
			name:  "create bundle (jwks)",
			stdin: otherDomainJWKS,
			args:  []string{"-id", "spiffe://otherdomain.test", "-format", formatSPIFFE},
		},
		{
			name:  "update bundle (default)",
			stdin: cert1PEM,
			args:  []string{"-id", "spiffe://otherdomain.test"},
		},
		{
			name:  "update bundle (pem)",
			stdin: cert1PEM,
			args:  []string{"-id", "spiffe://otherdomain.test", "-format", formatPEM},
		},
		{
			name:  "update bundle (jwks)",
			stdin: otherDomainJWKS,
			args:  []string{"-id", "spiffe://otherdomain.test", "-format", formatSPIFFE},
		},
		{
			name:           "invalid file name",
			expectedStderr: "unable to load bundle data: open /not/a/real/path/to/a/bundle: no such file or directory\n",
			args:           []string{"-id", "spiffe://otherdomain.test", "-path", "/not/a/real/path/to/a/bundle"},
		},
		{
			name:     "create from file (default)",
			args:     []string{"-id", "spiffe://otherdomain.test"},
			fileData: cert1PEM,
		},
		{
			name:     "create from file (pem)",
			args:     []string{"-id", "spiffe://otherdomain.test", "-format", formatPEM},
			fileData: cert1PEM,
		},
		{
			name:     "create from file (jwks)",
			args:     []string{"-id", "spiffe://otherdomain.test", "-format", formatSPIFFE},
			fileData: otherDomainJWKS,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t)
			rc := test.setCmd.Run(tt.args)

			if tt.expectedStderr != "" {
				require.Equal(t, 1, rc)
				require.Equal(t, tt.expectedStderr, test.testEnv.stderr.(*bytes.Buffer).String())
				return
			}

			if tt.createBundle {
				test.createBundle(t, &common.Bundle{
					TrustDomainId: "spiffe://otherdomain.test",
					RootCas: []*common.Certificate{
						{DerBytes: []byte("BOGUSCERTS")},
					},
				})
			}

			test.testEnv.stdin.(*bytes.Buffer).WriteString(tt.stdin)
			if tt.fileData != "" {
				tmpDir := spiretest.TempDir(t)
				bundlePath := filepath.Join(tmpDir, "bundle_data")
				require.NoError(t, ioutil.WriteFile(bundlePath, []byte(tt.fileData), 0600))
				tt.args = append(tt.args, "-path", bundlePath)
			}
			test.assertBundleSet(t, tt.args)
		})
	}
}

func TestListHelp(t *testing.T) {
	test := setupTest(t)

	test.listCmd.Help()
	require.Equal(t, `Usage of bundle list:
  -format string
    	The format to list federated bundles. Either "pem" or "spiffe". (default "pem")
  -id string
    	SPIFFE ID of the trust domain
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
`, test.testEnv.stderr.(*bytes.Buffer).String())
}

func TestList(t *testing.T) {
	for _, tt := range []struct {
		name           string
		args           []string
		expectedStdout string
	}{
		{
			name:           "all bundles (default)",
			expectedStdout: allBundlesPEM,
		},
		{
			name:           "all bundles (pem)",
			args:           []string{"-format", formatPEM},
			expectedStdout: allBundlesPEM,
		},
		{
			name:           "all bundles (jwks)",
			args:           []string{"-format", formatSPIFFE},
			expectedStdout: allBundlesJWKS,
		},
		{
			name:           "one bundle (default)",
			args:           []string{"-id", "spiffe://domain2.test"},
			expectedStdout: cert2PEM,
		},
		{
			name:           "one bundle (pem)",
			args:           []string{"-id", "spiffe://domain2.test", "-format", formatPEM},
			expectedStdout: cert2PEM,
		},
		{
			name:           "one bundle (jwks)",
			args:           []string{"-id", "spiffe://domain2.test", "-format", formatSPIFFE},
			expectedStdout: cert2JWKS,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t)
			test.createBundle(t, &common.Bundle{
				TrustDomainId: "spiffe://domain1.test",
				RootCas: []*common.Certificate{
					{DerBytes: test.cert1.Raw},
				},
				JwtSigningKeys: []*common.PublicKey{
					{Kid: "KID", PkixBytes: test.key1Pkix},
				},
			})
			test.createBundle(t, &common.Bundle{
				TrustDomainId: "spiffe://domain2.test",
				RootCas: []*common.Certificate{
					{DerBytes: test.cert2.Raw},
				},
			})

			require.Equal(t, 0, test.listCmd.Run(tt.args))
			require.Equal(t, tt.expectedStdout, test.testEnv.stdout.(*bytes.Buffer).String())
		})
	}
}

func TestDeleteHelp(t *testing.T) {
	test := setupTest(t)

	test.deleteCmd.Help()
	require.Equal(t, `Usage of bundle delete:
  -id string
    	SPIFFE ID of the trust domain
  -mode string
    	Deletion mode: one of restrict, delete, or dissociate (default "restrict")
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
`, test.testEnv.stderr.(*bytes.Buffer).String())
}

func TestDelete(t *testing.T) {
	for _, tt := range []struct {
		name                string
		args                []string
		expectedStderr      string
		expectedStdout      string
		withAssociatedEntry bool
	}{
		{
			name:           "no id",
			expectedStderr: "id is required\n",
		},
		{
			name:           "unsupported mode",
			args:           []string{"-id", "spiffe://domain1.test", "-mode", "whatever"},
			expectedStderr: "unsupported mode \"whatever\"\n",
		},
		{
			name:           "success",
			args:           []string{"-id", "spiffe://domain1.test"},
			expectedStdout: "bundle deleted.\n",
		},
		{
			name:                "with associated entry (default mode)",
			withAssociatedEntry: true,
			args:                []string{"-id", "spiffe://domain1.test"},
			expectedStderr:      "rpc error: code = Internal desc = rpc error: code = Unknown desc = datastore-sql: cannot delete bundle; federated with 1 registration entries\n",
		},
		{
			name:                "with associated entry (restrict mode)",
			withAssociatedEntry: true,
			args:                []string{"-id", "spiffe://domain1.test", "-mode", deleteBundleRestrict},
			expectedStderr:      "rpc error: code = Internal desc = rpc error: code = Unknown desc = datastore-sql: cannot delete bundle; federated with 1 registration entries\n",
		},
		{
			name:                "with associated entry (delete mode)",
			withAssociatedEntry: true,
			args:                []string{"-id", "spiffe://domain1.test", "-mode", deleteBundleDelete},
			expectedStdout:      "bundle deleted.\n",
		},
		{
			name:                "with associated entry (dissociate mode)",
			withAssociatedEntry: true,
			args:                []string{"-id", "spiffe://domain1.test", "-mode", deleteBundleDissociate},
			expectedStdout:      "bundle deleted.\n",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t)
			test.createBundle(t, &common.Bundle{
				TrustDomainId: "spiffe://domain1.test",
				RootCas: []*common.Certificate{
					{DerBytes: test.cert1.Raw},
				},
			})

			if tt.withAssociatedEntry {
				test.createRegistrationEntry(t, &common.RegistrationEntry{
					ParentId:      "spiffe://example.test/spire/agent/foo",
					SpiffeId:      "spiffe://example.test/blog",
					Selectors:     []*common.Selector{{Type: "foo", Value: "bar"}},
					FederatesWith: []string{"spiffe://domain1.test"},
				})
			}

			if tt.expectedStderr != "" {
				require.Equal(t, 1, test.deleteCmd.Run(tt.args))
				require.Equal(t, tt.expectedStderr, test.testEnv.stderr.(*bytes.Buffer).String())

				_, err := test.ds.FetchBundle(context.Background(), &datastore.FetchBundleRequest{
					TrustDomainId: "spiffe://domain1.test",
				})
				require.Nil(t, err)
				return
			}

			require.Equal(t, 0, test.deleteCmd.Run(tt.args))
			require.Equal(t, tt.expectedStdout, test.testEnv.stdout.(*bytes.Buffer).String())

			resp, err := test.ds.FetchBundle(context.Background(), &datastore.FetchBundleRequest{
				TrustDomainId: "spiffe://domain1.test",
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Nil(t, resp.Bundle)
		})
	}
}

func (s *bundleTest) assertBundleSet(t *testing.T, args []string) {
	rc := s.setCmd.Run(args)
	require.Equal(t, 0, rc)
	require.Equal(t, "bundle set.\n", s.testEnv.stdout.(*bytes.Buffer).String())

	// make sure it made it into the datastore
	resp, err := s.ds.FetchBundle(context.Background(), &datastore.FetchBundleRequest{
		TrustDomainId: "spiffe://otherdomain.test",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Bundle)
	require.Len(t, resp.Bundle.RootCas, 1)
	require.Equal(t, s.cert1.Raw, resp.Bundle.RootCas[0].DerBytes)
}

func (s *bundleTest) createBundle(t *testing.T, bundle *common.Bundle) {
	_, err := s.ds.CreateBundle(context.Background(), &datastore.CreateBundleRequest{
		Bundle: bundle,
	})
	require.NoError(t, err)
}

func (s *bundleTest) createRegistrationEntry(t *testing.T, entry *common.RegistrationEntry) *common.RegistrationEntry {
	resp, err := s.ds.CreateRegistrationEntry(context.Background(), &datastore.CreateRegistrationEntryRequest{
		Entry: entry,
	})
	require.NoError(t, err)
	return resp.Entry
}
