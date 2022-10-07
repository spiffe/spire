package gcpkms

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	keymanagertest "github.com/spiffe/spire/pkg/server/plugin/keymanager/test"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/grpc/codes"
)

const (
	customPolicy = `
	{
		"bindings": [
			{
				"role": "projects/test-project/roles/role-name",
				"members": [
					"serviceAccount:sa@test-project.iam.gserviceaccount.com"
				]
			}
		],
		"version": 3
	}	
	`
	pemCert = `-----BEGIN CERTIFICATE-----
MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyv
sCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXs
RxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkw
F4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09X
makw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylA
dZglS5kKnYigmwDh+/U=
-----END CERTIFICATE-----
`
	validPolicyFile   = "custom_policy_file.json"
	validServerID     = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	validServerIDFile = "test-server-id"
	validKeyRing      = "projects/project-name/locations/location-name/keyRings/key-ring-name"
)

var (
	ctx       = context.Background()
	isWindows = runtime.GOOS == "windows"
)

type pluginTest struct {
	plugin        *Plugin
	fakeKMSClient *fakeKMSClient
	logHook       *test.Hook
	clockHook     *clock.Mock
}

func setupTest(t *testing.T) *pluginTest {
	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	c := clock.NewMock(t)
	fakeKMSClient := newKMSClientFake(t, c)
	p := newPlugin(
		func(context.Context, ...option.ClientOption) (cloudKeyManagementService, error) {
			return fakeKMSClient, nil
		},
	)
	km := new(keymanager.V1)
	plugintest.Load(t, builtin(p), km, plugintest.Log(log))

	p.hooks.clk = c

	return &pluginTest{
		plugin:        p,
		fakeKMSClient: fakeKMSClient,
		logHook:       logHook,
		clockHook:     c,
	}
}

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name                   string
		expectMsg              string
		expectCode             codes.Code
		configureRequest       *configv1.ConfigureRequest
		fakeCryptoKeys         []fakeCryptoKey
		getCryptoKeyVersionErr error
		listCryptoKeysErr      error
		describeKeyErr         error
		getPublicKeyErr        error
	}{
		{
			name:             "pass with keys",
			configureRequest: configureRequestWithDefaults(t),
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-31c2defd-15e2-4df9-abd4-6da9ee900b71-k1",
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-31c2defd-15e2-4df9-abd4-6da9ee900b71-k1/cryptoKeyVersions/1"},
						},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-31c2defd-15e2-4df9-abd4-6da9ee900b71-k1",
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"2": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-31c2defd-15e2-4df9-abd4-6da9ee900b71-k1/cryptoKeyVersions/2"},
						},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-31c2defd-15e2-4df9-abd4-6da9ee900b71-k2",
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-31c2defd-15e2-4df9-abd4-6da9ee900b71-k2/cryptoKeyVersions/1"},
						},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-31c2defd-15e2-4df9-abd4-6da9ee900b71-k2",
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"2": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-31c2defd-15e2-4df9-abd4-6da9ee900b71-k2/cryptoKeyVersions/2"},
						},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-eb0feec5-8526-482e-a42d-094c19b7ef5d-k1",
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-eb0feec5-8526-482e-a42d-094c19b7ef5d-k1/cryptoKeyVersions/1"},
						},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-eb0feec5-8526-482e-a42d-094c19b7ef5d-k1",
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"2": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-eb0feec5-8526-482e-a42d-094c19b7ef5d-k1/cryptoKeyVersions/2"},
						},
					},
				},
			},
		},
		{
			name:             "pass without keys",
			configureRequest: configureRequestWithDefaults(t),
		},
		{
			name:             "no service account file",
			configureRequest: configureRequestWithVars(getKeyMetadataFile(t), "", validKeyRing),
		},
		{
			name:             "missing key ring",
			configureRequest: configureRequestWithVars(getKeyMetadataFile(t), "", ""),
			expectMsg:        "configuration is missing the key ring",
			expectCode:       codes.InvalidArgument,
		},
		{
			name:             "missing server id file path",
			configureRequest: configureRequestWithVars("", "", validKeyRing),
			expectMsg:        "configuration is missing server ID file path",
			expectCode:       codes.InvalidArgument,
		},
		{
			name:             "custom policy file does not exist",
			configureRequest: configureRequestWithVars(getKeyMetadataFile(t), "non-existent-file.json", validKeyRing),
			expectMsg:        fmt.Sprintf("failed to read file configured in 'key_policy_file': open non-existent-file.json: %s", spiretest.FileNotFound()),
			expectCode:       codes.Internal,
		},
		{
			name:             "use custom policy file",
			configureRequest: configureRequestWithVars(getKeyMetadataFile(t), getCustomPolicyFile(t), validKeyRing),
		},
		{
			name:             "new server id file path",
			configureRequest: configureRequestWithVars(getEmptyKeyMetadataFile(t), getCustomPolicyFile(t), validKeyRing),
		},
		{
			name:             "decode error",
			configureRequest: configureRequestWithString("{ malformed json }"),
			expectMsg:        "unable to decode configuration: 1:11: illegal char",
			expectCode:       codes.InvalidArgument,
		},
		{
			name:              "ListCryptoKeys error",
			expectMsg:         "failed to list SPIRE Server keys in Cloud KMS: error listing CryptoKeys",
			expectCode:        codes.Internal,
			configureRequest:  configureRequestWithDefaults(t),
			listCryptoKeysErr: errors.New("error listing CryptoKeys"),
		},
		{
			name:             "unsupported CryptoKeyVersionAlgorithm",
			expectMsg:        "failed to fetch entries: unsupported CryptoKeyVersionAlgorithm: GOOGLE_SYMMETRIC_ENCRYPTION",
			expectCode:       codes.Internal,
			configureRequest: configureRequestWithDefaults(t),
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-eb0feec5-8526-482e-a42d-094c19b7ef5d-k1",
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
								Name:      "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-eb0feec5-8526-482e-a42d-094c19b7ef5d-k1/cryptoKeyVersions/1"},
						},
					},
				},
			},
		},
		{
			name:             "get public key error",
			expectMsg:        "failed to fetch entries: failed to get public key: get public key error",
			expectCode:       codes.Internal,
			configureRequest: configureRequestWithDefaults(t),
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-eb0feec5-8526-482e-a42d-094c19b7ef5d-k1",
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-eb0feec5-8526-482e-a42d-094c19b7ef5d-k1/cryptoKeyVersions/1"},
						},
					},
				},
			},
			getPublicKeyErr: errors.New("get public key error"),
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)
			ts.fakeKMSClient.listCryptoKeysErr = tt.listCryptoKeysErr
			ts.fakeKMSClient.getCryptoKeyVersionErr = tt.getCryptoKeyVersionErr
			ts.fakeKMSClient.getPublicKeyErr = tt.getPublicKeyErr

			_, err := ts.plugin.Configure(ctx, tt.configureRequest)

			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			if tt.expectCode != codes.OK {
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestKeyManagerContract(t *testing.T) {
	create := func(t *testing.T) keymanager.KeyManager {
		dir := spiretest.TempDir(t)
		c := clock.NewMock(t)
		fakeKMSClient := newKMSClientFake(t, c)
		p := newPlugin(
			func(ctx context.Context, opts ...option.ClientOption) (cloudKeyManagementService, error) {
				return fakeKMSClient, nil
			},
		)
		km := new(keymanager.V1)
		keyMetadataFile := filepath.Join(dir, "metadata.json")
		if isWindows {
			keyMetadataFile = filepath.ToSlash(keyMetadataFile)
		}
		plugintest.Load(t, builtin(p), km, plugintest.Configuref(`
        key_metadata_file = %q
        key_ring = "projects/project-id/locations/location/keyRings/keyring"
		`, keyMetadataFile))
		return km
	}

	unsupportedSignatureAlgorithms := map[keymanager.KeyType][]x509.SignatureAlgorithm{
		keymanager.ECP256:  {x509.ECDSAWithSHA384, x509.ECDSAWithSHA512},
		keymanager.ECP384:  {x509.ECDSAWithSHA256, x509.ECDSAWithSHA512},
		keymanager.RSA2048: {x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS, x509.SHA384WithRSA, x509.SHA512WithRSA},
		keymanager.RSA4096: {x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS, x509.SHA384WithRSA, x509.SHA512WithRSA},
	}
	keymanagertest.Test(t, keymanagertest.Config{
		Create:                         create,
		UnsupportedSignatureAlgorithms: unsupportedSignatureAlgorithms,
	})
}

func configureRequestWithDefaults(t *testing.T) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration:  serializedConfiguration(getKeyMetadataFile(t), validKeyRing),
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "test.example.org"},
	}
}

func configureRequestWithString(config string) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration: config,
	}
}

func configureRequestWithVars(keyMetadataFile, keyPolicyFile, keyRing string) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration: fmt.Sprintf(`{
			"key_metadata_file":"%s",
			"key_policy_file":"%s",
			"key_ring":"%s"
			}`,
			keyMetadataFile,
			keyPolicyFile,
			keyRing),
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "test.example.org"},
	}
}

func getKeyMetadataFile(t *testing.T) string {
	tempDir := t.TempDir()
	tempFilePath := path.Join(tempDir, validServerIDFile)
	err := os.WriteFile(tempFilePath, []byte(validServerID), 0600)
	if err != nil {
		t.Error(err)
	}
	if isWindows {
		tempFilePath = filepath.ToSlash(tempFilePath)
	}
	return tempFilePath
}

func getEmptyKeyMetadataFile(t *testing.T) string {
	tempDir := t.TempDir()
	keyMetadataFile := path.Join(tempDir, validServerIDFile)
	if isWindows {
		keyMetadataFile = filepath.ToSlash(keyMetadataFile)
	}
	return keyMetadataFile
}

func getCustomPolicyFile(t *testing.T) string {
	tempDir := t.TempDir()
	tempFilePath := path.Join(tempDir, validPolicyFile)
	err := os.WriteFile(tempFilePath, []byte(customPolicy), 0600)
	if err != nil {
		t.Error(err)
	}
	if isWindows {
		tempFilePath = filepath.ToSlash(tempFilePath)
	}
	return tempFilePath
}

func serializedConfiguration(keyMetadataFile, keyRing string) string {
	return fmt.Sprintf(`{
		"key_metadata_file":"%s",
		"key_ring":"%s"
		}`,
		keyMetadataFile,
		keyRing)
}
