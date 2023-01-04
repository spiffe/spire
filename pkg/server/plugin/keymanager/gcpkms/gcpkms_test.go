package gcpkms

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	keymanagertest "github.com/spiffe/spire/pkg/server/plugin/keymanager/test"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	customPolicy = `
{
	"bindings": [
		{
			"role": "projects/test-project/roles/role-name",
			"members": [
				"serviceAccount:test-sa@example.com"
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
	spireKeyID1       = "spireKeyID-1"
	spireKeyID2       = "spireKeyID-2"
	testTimeout       = 60 * time.Second
	validPolicyFile   = "custom_policy_file.json"
	validServerID     = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	validServerIDFile = "test-server-id"
	validKeyRing      = "projects/project-name/locations/location-name/keyRings/key-ring-name"
)

var (
	ctx            = context.Background()
	cryptoKeyName1 = path.Join(validKeyRing, "cryptoKeys", fmt.Sprintf("test-crypto-key/spire-key-%s-spireKeyID-1", validServerID))
	cryptoKeyName2 = path.Join(validKeyRing, "cryptoKeys", fmt.Sprintf("test-crypto-key/spire-key-%s-spireKeyID-2", validServerID))
	fakeTime       = timestamppb.Now()
	unixEpoch      = time.Unix(0, 0)

	pubKey = &kmspb.PublicKey{
		Pem:       pemCert,
		PemCrc32C: &wrapperspb.Int64Value{Value: int64(crc32Checksum([]byte(pemCert)))},
	}
)

type pluginTest struct {
	plugin        *Plugin
	fakeKMSClient *fakeKMSClient
	log           logrus.FieldLogger
	logHook       *test.Hook
	clockHook     *clock.Mock
}

func setupTest(t *testing.T) *pluginTest {
	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	c := clock.NewMock(t)
	c.Set(unixEpoch)
	fakeKMSClient := newKMSClientFake(t, c)
	p := newPlugin(
		func(ctx context.Context, opts ...option.ClientOption) (cloudKeyManagementService, error) {
			fakeKMSClient.opts = opts
			return fakeKMSClient, nil
		},
	)
	km := new(keymanager.V1)
	plugintest.Load(t, builtin(p), km, plugintest.Log(log))

	p.hooks.clk = c

	return &pluginTest{
		plugin:        p,
		fakeKMSClient: fakeKMSClient,
		log:           log,
		logHook:       logHook,
		clockHook:     c,
	}
}

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name                   string
		expectMsg              string
		expectCode             codes.Code
		expectOpts             []option.ClientOption
		config                 *Config
		configureRequest       *configv1.ConfigureRequest
		fakeCryptoKeys         []*fakeCryptoKey
		getCryptoKeyVersionErr error
		listCryptoKeysErr      error
		describeKeyErr         error
		getPublicKeyErr        error
		getPublicKeyErrCount   int
	}{
		{
			name: "pass with keys",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				KeyRing:         validKeyRing,
			},
			fakeCryptoKeys: []*fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							},
						},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"2": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/2", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							},
						},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName2,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName2),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							},
						},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName2,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"2": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/2", cryptoKeyName2),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							},
						},
					},
				},
			},
		},
		{
			name: "pass without keys",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				KeyRing:         validKeyRing,
			},
		},
		{
			name: "pass without keys - using a service account file",
			config: &Config{
				KeyMetadataFile:    createKeyMetadataFile(t, validServerID),
				KeyRing:            validKeyRing,
				ServiceAccountFile: "service-account-file",
			},
			expectOpts: []option.ClientOption{option.WithCredentialsFile("service-account-file")},
		},
		{
			name: "missing key ring",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
			},
			expectMsg:  "configuration is missing the key ring",
			expectCode: codes.InvalidArgument,
		},
		{
			name: "missing key metadata file",
			config: &Config{
				KeyRing: validKeyRing,
			},
			expectMsg:  "configuration is missing server ID file path",
			expectCode: codes.InvalidArgument,
		},
		{
			name: "custom policy file does not exist",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				KeyPolicyFile:   "non-existent-file.json",
				KeyRing:         validKeyRing,
			},
			expectMsg:  fmt.Sprintf("could not parse policy file: failed to read file: open non-existent-file.json: %s", spiretest.FileNotFound()),
			expectCode: codes.Internal,
		},
		{
			name: "use custom policy file",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				KeyPolicyFile:   getCustomPolicyFile(t),
				KeyRing:         validKeyRing,
			},
		},
		{
			name: "empty key metadata file",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, ""),
				KeyRing:         validKeyRing,
			},
		},
		{
			name: "invalid server ID in metadata file",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, "invalid-id"),
				KeyRing:         validKeyRing,
			},
			expectMsg:  "failed to parse server ID from path: uuid: incorrect UUID length 10 in string \"invalid-id\"",
			expectCode: codes.Internal,
		},
		{
			name: "invalid metadata file path",
			config: &Config{
				KeyMetadataFile: "/",
				KeyRing:         validKeyRing,
			},
			expectMsg:  "failed to read server ID from path: read /:",
			expectCode: codes.Internal,
		},
		{
			name:             "decode error",
			configureRequest: configureRequestWithString("{ malformed json }"),
			expectMsg:        "unable to decode configuration: 1:11: illegal char",
			expectCode:       codes.InvalidArgument,
		},
		{
			name: "ListCryptoKeys error",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				KeyRing:         validKeyRing,
			},
			expectMsg:         "failed to list SPIRE Server keys in Cloud KMS: error listing CryptoKeys",
			expectCode:        codes.Internal,
			listCryptoKeysErr: errors.New("error listing CryptoKeys"),
		},
		{
			name:       "unsupported CryptoKeyVersionAlgorithm",
			expectMsg:  "failed to fetch entries: unsupported CryptoKeyVersionAlgorithm: GOOGLE_SYMMETRIC_ENCRYPTION",
			expectCode: codes.Internal,
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				KeyRing:         validKeyRing,
			},
			fakeCryptoKeys: []*fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							},
						},
					},
				},
			},
		},
		{
			name:       "get public key error max attempts",
			expectMsg:  "failed to fetch entries: error getting public key: get public key error",
			expectCode: codes.Internal,
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				KeyRing:         validKeyRing,
			},
			fakeCryptoKeys: []*fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							},
						},
					},
				},
			},
			getPublicKeyErr:      errors.New("get public key error"),
			getPublicKeyErrCount: getPublicKeyMaxAttempts + 1,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)
			ts.fakeKMSClient.setListCryptoKeysErr(tt.listCryptoKeysErr)
			ts.fakeKMSClient.setGetCryptoKeyVersionErr(tt.getCryptoKeyVersionErr)
			ts.fakeKMSClient.setGetPublicKeySequentialErrs(tt.getPublicKeyErr, tt.getPublicKeyErrCount)

			var configureRequest *configv1.ConfigureRequest
			if tt.config != nil {
				require.Nil(t, tt.configureRequest, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = configureRequestFromConfig(tt.config)
			} else {
				require.Nil(t, tt.config, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = tt.configureRequest
			}
			_, err := ts.plugin.Configure(ctx, configureRequest)

			spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
			if tt.expectCode != codes.OK {
				return
			}
			require.NoError(t, err)

			// Assert the config settings
			require.Equal(t, tt.config, ts.plugin.config)

			// Assert that the keys have been loaded
			storedFakeCryptoKeys := ts.fakeKMSClient.store.fetchFakeCryptoKeys()
			for _, expectedFakeCryptoKey := range storedFakeCryptoKeys {
				spireKeyID, ok := getSPIREKeyIDFromCryptoKeyName(expectedFakeCryptoKey.Name)
				require.True(t, ok)

				entry, ok := ts.plugin.entries[spireKeyID]
				require.True(t, ok)
				require.Equal(t, expectedFakeCryptoKey.CryptoKey, entry.cryptoKey)
			}

			require.Equal(t, tt.expectOpts, ts.plugin.kmsClient.(*fakeKMSClient).opts)
		})
	}
}

func TestDisposeStaleCryptoKeys(t *testing.T) {
	configureRequest := configureRequestWithDefaults(t)
	fakeCryptoKeys := []*fakeCryptoKey{
		{
			CryptoKey: &kmspb.CryptoKey{
				Name:            cryptoKeyName1,
				Labels:          map[string]string{labelNameActive: "true"},
				VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
			},
			fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
				"1": {
					publicKey: pubKey,
					CryptoKeyVersion: &kmspb.CryptoKeyVersion{
						Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
						Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
						State:     kmspb.CryptoKeyVersion_ENABLED,
					}},
			},
		},
		{
			CryptoKey: &kmspb.CryptoKey{
				Name:            cryptoKeyName2,
				Labels:          map[string]string{labelNameActive: "true"},
				VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
			},
			fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
				"1": {
					publicKey: pubKey,
					CryptoKeyVersion: &kmspb.CryptoKeyVersion{
						Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
						Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName2),
						State:     kmspb.CryptoKeyVersion_ENABLED,
					}},
			},
		},
	}

	ts := setupTest(t)
	ts.fakeKMSClient.putFakeCryptoKeys(fakeCryptoKeys)

	ts.plugin.hooks.disposeCryptoKeysSignal = make(chan error)
	ts.plugin.hooks.scheduleDestroySignal = make(chan error)
	ts.plugin.hooks.setInactiveSignal = make(chan error)

	_, err := ts.plugin.Configure(ctx, configureRequest)
	require.NoError(t, err)

	// Move the clock to start disposeCryptoKeysTask.
	ts.clockHook.Add(disposeCryptoKeysFrequency)

	// Wait for dispose disposeCryptoKeysTask to be initialized.
	_ = waitForSignal(t, ts.plugin.hooks.disposeCryptoKeysSignal)

	// Move the clock to make sure that we have stale CryptoKeys.
	ts.clockHook.Add(maxStaleDuration)

	// Wait for destroy notification of all the CryptoKeyVersions.
	storedFakeCryptoKeys := ts.fakeKMSClient.store.fetchFakeCryptoKeys()
	for _, fakeKey := range storedFakeCryptoKeys {
		storedFakeCryptoKeyVersions := fakeKey.fetchFakeCryptoKeyVersions()
		for range storedFakeCryptoKeyVersions {
			_ = waitForSignal(t, ts.plugin.hooks.scheduleDestroySignal)
		}
	}

	for _, fakeKey := range storedFakeCryptoKeys {
		// The CryptoKeys should be active until the next run of disposeCryptoKeys.
		require.Equal(t, "true", fakeKey.getLabelValue(labelNameActive))

		storedFakeCryptoKeyVersions := fakeKey.fetchFakeCryptoKeyVersions()
		for _, fakeKeyVersion := range storedFakeCryptoKeyVersions {
			// The status should be changed to CryptoKeyVersion_DESTROY_SCHEDULED.
			require.Equal(t, kmspb.CryptoKeyVersion_DESTROY_SCHEDULED, fakeKeyVersion.State, fmt.Sprintf("state mismatch in CryptokeyVersion %q", fakeKeyVersion.Name))
		}
	}

	// Move the clock to start disposeCryptoKeysTask again.
	ts.clockHook.Add(disposeCryptoKeysFrequency)

	// Wait for dispose disposeCryptoKeysTask to be initialized.
	_ = waitForSignal(t, ts.plugin.hooks.disposeCryptoKeysSignal)

	// Since the CryptoKey doesn't have any enabled CryptoKeyVersions at
	// this point, it should be set as inactive.
	// Wait for the set inactive signal.
	// The order is not respected, so verify no error is returned
	// and that all signals received
	for _, fakeKey := range storedFakeCryptoKeys {
		err = waitForSignal(t, ts.plugin.hooks.setInactiveSignal)
		require.NoErrorf(t, err, "unexpected error on %v", fakeKey.getName())
	}

	for _, fakeKey := range storedFakeCryptoKeys {
		// The CryptoKey should be inactive now.
		fakeKey, ok := ts.fakeKMSClient.store.fetchFakeCryptoKey(fakeKey.getName())
		require.True(t, ok)
		require.Equal(t, "false", fakeKey.getLabelValue(labelNameActive))
	}
}

func TestDisposeActiveCryptoKeys(t *testing.T) {
	configureRequest := configureRequestWithDefaults(t)
	fakeCryptoKeys := []*fakeCryptoKey{
		{
			CryptoKey: &kmspb.CryptoKey{
				Name:            cryptoKeyName1,
				Labels:          map[string]string{labelNameActive: "true"},
				VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
			},
			fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
				"1": {
					publicKey: pubKey,
					CryptoKeyVersion: &kmspb.CryptoKeyVersion{
						Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
						Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
						State:     kmspb.CryptoKeyVersion_ENABLED,
					}},
			},
		},
		{
			CryptoKey: &kmspb.CryptoKey{
				Name:            cryptoKeyName2,
				Labels:          map[string]string{labelNameActive: "true"},
				VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
			},
			fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
				"1": {
					publicKey: pubKey,
					CryptoKeyVersion: &kmspb.CryptoKeyVersion{
						Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
						Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName2),
						State:     kmspb.CryptoKeyVersion_ENABLED,
					}},
			},
		},
	}

	ts := setupTest(t)
	ts.fakeKMSClient.putFakeCryptoKeys(fakeCryptoKeys)

	ts.plugin.hooks.disposeCryptoKeysSignal = make(chan error)
	scheduleDestroySignal := make(chan error)
	ts.plugin.hooks.scheduleDestroySignal = scheduleDestroySignal

	_, err := ts.plugin.Configure(ctx, configureRequest)
	require.NoError(t, err)

	// Move the clock to start disposeCryptoKeysTask.
	ts.clockHook.Add(disposeCryptoKeysFrequency)

	// Wait for dispose disposeCryptoKeysTask to be initialized.
	_ = waitForSignal(t, ts.plugin.hooks.disposeCryptoKeysSignal)

	// The CryptoKeys are not stale yet. Assert that they are active and the
	// CryptoKeyVersions enabled.
	storedFakeCryptoKeys := ts.fakeKMSClient.store.fetchFakeCryptoKeys()
	for _, fakeKey := range storedFakeCryptoKeys {
		require.Equal(t, "true", fakeKey.getLabelValue(labelNameActive))
		storedFakeCryptoKeyVersions := fakeKey.fetchFakeCryptoKeyVersions()
		for _, fakeKeyVersion := range storedFakeCryptoKeyVersions {
			require.Equal(t, kmspb.CryptoKeyVersion_ENABLED, fakeKeyVersion.GetState(), fakeKeyVersion.GetName())
		}
	}
}

func TestEnqueueDestructionFailure(t *testing.T) {
	configureRequest := configureRequestWithDefaults(t)
	fakeCryptoKeys := []*fakeCryptoKey{
		{
			CryptoKey: &kmspb.CryptoKey{
				Name:            cryptoKeyName1,
				Labels:          map[string]string{labelNameActive: "true"},
				VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
			},
			fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
				"1": {
					publicKey: pubKey,
					CryptoKeyVersion: &kmspb.CryptoKeyVersion{
						Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
						Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
						State:     kmspb.CryptoKeyVersion_ENABLED,
					}},
			},
		},
		{
			CryptoKey: &kmspb.CryptoKey{
				Name:            cryptoKeyName2,
				Labels:          map[string]string{labelNameActive: "true"},
				VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
			},
			fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
				"1": {
					publicKey: pubKey,
					CryptoKeyVersion: &kmspb.CryptoKeyVersion{
						Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
						Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName2),
						State:     kmspb.CryptoKeyVersion_ENABLED,
					}},
			},
		},
	}

	ts := setupTest(t)
	// Change the scheduleDestroy channel to be unbuffered.
	ts.plugin.scheduleDestroy = make(chan string)

	ts.fakeKMSClient.putFakeCryptoKeys(fakeCryptoKeys)

	ts.plugin.hooks.disposeCryptoKeysSignal = make(chan error, 1)
	ts.plugin.hooks.enqueueDestructionSignal = make(chan error, 1)

	_, err := ts.plugin.Configure(ctx, configureRequest)
	require.NoError(t, err)

	// Move the clock to start disposeCryptoKeysTask.
	ts.clockHook.Add(disposeCryptoKeysFrequency)

	// Wait for dispose disposeCryptoKeysTask to be initialized.
	_ = waitForSignal(t, ts.plugin.hooks.disposeCryptoKeysSignal)

	// Move the clock to make sure that we have stale CryptoKeys.
	ts.clockHook.Add(maxStaleDuration)

	// Enqueuing the first CryptoKeyVersion for destruction should succeed.
	err = waitForSignal(t, ts.plugin.hooks.enqueueDestructionSignal)
	require.NoError(t, err)

	// Enqueuing the second CryptoKeyVersion for destruction should fail.
	err = waitForSignal(t, ts.plugin.hooks.enqueueDestructionSignal)
	require.ErrorContains(t, err, "could not enqueue CryptoKeyVersion")
}

func TestGenerateKey(t *testing.T) {
	for _, tt := range []struct {
		configureReq                 *configv1.ConfigureRequest
		expectCode                   codes.Code
		expectMsg                    string
		destroyTime                  *timestamp.Timestamp
		fakeCryptoKeys               []*fakeCryptoKey
		generateKeyReq               *keymanagerv1.GenerateKeyRequest
		logs                         []spiretest.LogEntry
		name                         string
		testDisabled                 bool
		waitForDelete                bool
		initialCryptoKeyVersionState kmspb.CryptoKeyVersion_CryptoKeyVersionState

		createKeyErr               error
		destroyCryptoKeyVersionErr error
		getCryptoKeyVersionErr     error
		getPublicKeyErr            error
		getPublicKeyErrCount       int
		getTokenInfoErr            error
		updateCryptoKeyErr         error
	}{
		{
			name: "success: non existing key",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},
		{
			name: "success: keeps retrying when crypto key is in pending generation state",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			initialCryptoKeyVersionState: kmspb.CryptoKeyVersion_PENDING_GENERATION,
			getPublicKeyErr:              errors.New("error getting public key"),
			getPublicKeyErrCount:         5,
		},
		{
			name: "success: non existing key with special characters",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   "bundle-acme-foo.bar+rsa",
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},
		{
			name: "success: non existing key with default policy",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			configureReq: configureRequestWithVars(createKeyMetadataFile(t, ""), "", validKeyRing, "service_account_file"),
		},
		{
			name: "success: non existing key with custom policy",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			configureReq: configureRequestWithVars(createKeyMetadataFile(t, ""), getCustomPolicyFile(t), validKeyRing, "service_account_file"),
		},
		{
			name: "success: replace old key",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			fakeCryptoKeys: []*fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							}},
					},
				},
			},
			waitForDelete: true,
			destroyTime:   fakeTime,
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "CryptoKeyVersion scheduled for destruction",
					Data: logrus.Fields{
						cryptoKeyVersionNameTag: fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
						scheduledDestroyTimeTag: fakeTime.AsTime().String(),
					},
				},
			},
		},
		{
			name: "success: EC 384",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P384,
			},
		},
		{
			name: "success: RSA 2048",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
		},
		{
			name: "success: RSA 4096",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_RSA_4096,
			},
		},
		{
			name: "missing key id",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   "",
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			expectMsg:  "key id is required",
			expectCode: codes.InvalidArgument,
		},
		{
			name: "missing key type",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE,
			},
			expectMsg:  "key type is required",
			expectCode: codes.InvalidArgument,
		},
		{
			name: "unsupported key type",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: 100,
			},
			expectMsg:  "failed to generate key: unsupported key type \"100\"",
			expectCode: codes.Internal,
		},
		{
			name:         "create CryptoKey error",
			expectMsg:    "failed to create CryptoKey: error creating CryptoKey",
			expectCode:   codes.Internal,
			createKeyErr: errors.New("error creating CryptoKey"),
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},
		{
			name:                 "get public key error",
			expectMsg:            "failed to get public key: public key error",
			expectCode:           codes.Internal,
			getPublicKeyErr:      errors.New("public key error"),
			getPublicKeyErrCount: 1,
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},
		{
			name: "cryptoKeyVersion not found when scheduling for destruction",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			destroyCryptoKeyVersionErr: status.Error(codes.NotFound, ""),
			fakeCryptoKeys: []*fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							},
						},
					},
				},
			},
			waitForDelete: true,
			destroyTime:   fakeTime,
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "CryptoKeyVersion not found",
					Data: logrus.Fields{
						cryptoKeyVersionNameTag: fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
					},
				},
			},
		},
		{
			name: "schedule destroy error",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			destroyCryptoKeyVersionErr: errors.New("error scheduling CryptoKeyVersion for destruction"),
			fakeCryptoKeys: []*fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							},
						},
					},
				},
			},
			waitForDelete: true,
			destroyTime:   fakeTime,
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "It was not possible to schedule CryptoKeyVersion for destruction",
					Data: logrus.Fields{
						cryptoKeyVersionNameTag: fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
						reasonTag:               "error scheduling CryptoKeyVersion for destruction",
					},
				},
			},
		},
		{
			name: "cryptoKeyVersion to destroy not enabled",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			destroyCryptoKeyVersionErr: errors.New("error scheduling CryptoKeyVersion for destruction"),
			fakeCryptoKeys: []*fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							},
						},
					},
				},
			},
			testDisabled:  true,
			waitForDelete: true,
			destroyTime:   fakeTime,
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "CryptoKeyVersion is not enabled, will not be scheduled for destruction",
					Data: logrus.Fields{
						cryptoKeyVersionNameTag:  fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
						cryptoKeyVersionStateTag: kmspb.CryptoKeyVersion_DISABLED.String(),
					},
				},
			},
		},
		{
			name: "error getting CryptoKeyVersion",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			destroyCryptoKeyVersionErr: errors.New("error scheduling CryptoKeyVersion for destruction"),
			getCryptoKeyVersionErr:     errors.New("error getting CryptoKeyVersion"),
			fakeCryptoKeys: []*fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							},
						},
					},
				},
			},
			waitForDelete: true,
			destroyTime:   fakeTime,
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Could not get the CryptoKeyVersion while trying to schedule it for destruction",
					Data: logrus.Fields{
						cryptoKeyVersionNameTag: fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
						reasonTag:               "error getting CryptoKeyVersion",
					},
				},
			},
		},
		{
			name:       "error getting token info",
			expectCode: codes.Internal,
			expectMsg:  "could not get token information: error getting token info",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P384,
			},
			getTokenInfoErr: errors.New("error getting token info"),
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.setDestroyTime(fakeTime)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)
			ts.fakeKMSClient.setCreateCryptoKeyErr(tt.createKeyErr)
			ts.fakeKMSClient.setInitialCryptoKeyVersionState(tt.initialCryptoKeyVersionState)
			ts.fakeKMSClient.setGetCryptoKeyVersionErr(tt.getCryptoKeyVersionErr)
			ts.fakeKMSClient.setGetTokeninfoErr(tt.getTokenInfoErr)
			ts.fakeKMSClient.setUpdateCryptoKeyErr(tt.updateCryptoKeyErr)
			ts.fakeKMSClient.setDestroyCryptoKeyVersionErr(tt.destroyCryptoKeyVersionErr)
			ts.fakeKMSClient.setIsKeyDisabled(tt.testDisabled)

			ts.plugin.hooks.scheduleDestroySignal = make(chan error)

			configureReq := tt.configureReq
			if configureReq == nil {
				configureReq = configureRequestWithDefaults(t)
			}

			coreConfig := catalog.CoreConfig{
				TrustDomain: spiffeid.RequireTrustDomainFromString("test.example.org"),
			}
			km := new(keymanager.V1)
			var err error

			plugintest.Load(t, builtin(ts.plugin), km,
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(coreConfig),
				plugintest.Configure(configureReq.HclConfiguration),
				plugintest.Log(ts.log),
			)
			require.NoError(t, err)

			ts.fakeKMSClient.setGetPublicKeySequentialErrs(tt.getPublicKeyErr, tt.getPublicKeyErrCount)

			resp, err := ts.plugin.GenerateKey(ctx, tt.generateKeyReq)
			if tt.expectMsg != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			_, err = ts.plugin.GetPublicKey(ctx, &keymanagerv1.GetPublicKeyRequest{
				KeyId: tt.generateKeyReq.KeyId,
			})
			require.NoError(t, err)

			if !tt.waitForDelete {
				spiretest.AssertLogsContainEntries(t, ts.logHook.AllEntries(), tt.logs)
				return
			}

			select {
			case <-ts.plugin.hooks.scheduleDestroySignal:
				// The logs emitted by the deletion goroutine and those that
				// enqueue deletion can be intermixed, so we cannot depend
				// on the exact order of the logs, so we just assert that
				// the expected log lines are present somewhere.
				spiretest.AssertLogsContainEntries(t, ts.logHook.AllEntries(), tt.logs)
			case <-time.After(testTimeout):
				t.Fail()
			}
		})
	}
}

func TestKeepActiveCryptoKeys(t *testing.T) {
	for _, tt := range []struct {
		configureRequest   *configv1.ConfigureRequest
		expectError        string
		fakeCryptoKeys     []*fakeCryptoKey
		name               string
		updateCryptoKeyErr error
	}{
		{
			name:               "keep active CryptoKeys error",
			configureRequest:   configureRequestWithDefaults(t),
			expectError:        "error updating CryptoKey",
			updateCryptoKeyErr: errors.New("error updating CryptoKey"),
			fakeCryptoKeys: []*fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							}},
					},
				},
			},
		},
		{
			name:             "keep active CryptoKeys succeeds",
			configureRequest: configureRequestWithDefaults(t),
			fakeCryptoKeys: []*fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							}},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName2,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName2),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							}},
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)
			ts.fakeKMSClient.setUpdateCryptoKeyErr(tt.updateCryptoKeyErr)
			ts.plugin.hooks.keepActiveCryptoKeysSignal = make(chan error)

			_, err := ts.plugin.Configure(ctx, tt.configureRequest)
			require.NoError(t, err)

			// Wait for keepActiveCryptoKeys task to be initialized.
			_ = waitForSignal(t, ts.plugin.hooks.keepActiveCryptoKeysSignal)

			// Move the clock forward so the task is run.
			currentTime := unixEpoch.Add(6 * time.Hour)
			ts.clockHook.Set(currentTime)

			// Wait for keepActiveCryptoKeys to be run.
			err = waitForSignal(t, ts.plugin.hooks.keepActiveCryptoKeysSignal)

			if tt.updateCryptoKeyErr != nil {
				require.NotNil(t, err)
				require.EqualError(t, err, err.Error())
				return
			}
			require.NoError(t, err)

			storedFakeCryptoKeys := ts.fakeKMSClient.store.fetchFakeCryptoKeys()
			for _, fakeKey := range storedFakeCryptoKeys {
				require.EqualValues(t, fakeKey.getLabelValue(labelNameLastUpdate), fmt.Sprint(currentTime.Unix()), fakeKey.CryptoKey.Name)
			}
		})
	}
}

func TestGetPublicKeys(t *testing.T) {
	for _, tt := range []struct {
		name           string
		err            string
		fakeCryptoKeys []*fakeCryptoKey
	}{
		{
			name: "one key",
			fakeCryptoKeys: []*fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							}},
					},
				},
			},
		},
		{
			name: "multiple keys",
			fakeCryptoKeys: []*fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							}},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName2,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName2),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							}},
					},
				},
			},
		},
		{
			name: "non existing keys",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)
			_, err := ts.plugin.Configure(ctx, configureRequestWithDefaults(t))
			require.NoError(t, err)

			resp, err := ts.plugin.GetPublicKeys(ctx, &keymanagerv1.GetPublicKeysRequest{})

			if tt.err != "" {
				require.Error(t, err)
				require.EqualError(t, err, tt.err)
				return
			}

			require.NotNil(t, resp)
			require.NoError(t, err)
			storedFakeCryptoKeys := ts.fakeKMSClient.store.fetchFakeCryptoKeys()
			for _, fakeKey := range storedFakeCryptoKeys {
				storedFakeCryptoKeyVersions := fakeKey.fetchFakeCryptoKeyVersions()
				for _, fakeKeyVersion := range storedFakeCryptoKeyVersions {
					pubKey, err := getPublicKeyFromCryptoKeyVersion(ctx, ts.plugin.log, ts.fakeKMSClient, fakeKeyVersion.CryptoKeyVersion.Name)
					require.NoError(t, err)
					require.Equal(t, pubKey, resp.PublicKeys[0].PkixData)
				}
			}
		})
	}
}

func TestGetPublicKey(t *testing.T) {
	for _, tt := range []struct {
		name                   string
		expectCodeConfigure    codes.Code
		expectMsgConfigure     string
		expectCodeGetPublicKey codes.Code
		expectMsgGetPublicKey  string
		fakeCryptoKeys         []*fakeCryptoKey
		keyID                  string
		pemCrc32C              *wrapperspb.Int64Value
	}{
		{
			name: "existing key",
			fakeCryptoKeys: []*fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							}},
					},
				},
			},
			keyID: spireKeyID1,
		},
		{
			name:                "integrity verification error",
			expectCodeConfigure: codes.Internal,
			expectMsgConfigure:  "failed to fetch entries: error getting public key: response corrupted in-transit",
			fakeCryptoKeys: []*fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          map[string]string{labelNameActive: "true"},
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: pubKey,
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_ENABLED,
							}},
					},
				},
			},
			keyID:     spireKeyID1,
			pemCrc32C: &wrapperspb.Int64Value{Value: 1},
		},
		{
			name:                   "non existing key",
			expectMsgGetPublicKey:  fmt.Sprintf("key %q not found", spireKeyID1),
			expectCodeGetPublicKey: codes.NotFound,
			keyID:                  spireKeyID1,
		},
		{
			name:                   "missing key id",
			expectMsgGetPublicKey:  "key id is required",
			expectCodeGetPublicKey: codes.InvalidArgument,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.setPEMCrc32C(tt.pemCrc32C)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)

			_, err := ts.plugin.Configure(ctx, configureRequestWithDefaults(t))
			if tt.expectMsgConfigure != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCodeConfigure, tt.expectMsgConfigure)
				return
			}

			require.NoError(t, err)
			resp, err := ts.plugin.GetPublicKey(ctx, &keymanagerv1.GetPublicKeyRequest{
				KeyId: tt.keyID,
			})
			if tt.expectMsgGetPublicKey != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCodeGetPublicKey, tt.expectMsgGetPublicKey)
				return
			}
			require.NotNil(t, resp)
			require.NoError(t, err)
			require.Equal(t, tt.keyID, resp.PublicKey.Id)
			require.Equal(t, ts.plugin.entries[tt.keyID].publicKey, resp.PublicKey)
		})
	}
}

func TestKeyManagerContract(t *testing.T) {
	create := func(t *testing.T) keymanager.KeyManager {
		dir := t.TempDir()
		c := clock.NewMock(t)
		fakeKMSClient := newKMSClientFake(t, c)
		p := newPlugin(
			func(ctx context.Context, opts ...option.ClientOption) (cloudKeyManagementService, error) {
				return fakeKMSClient, nil
			},
		)
		km := new(keymanager.V1)
		keyMetadataFile := filepath.ToSlash(filepath.Join(dir, "metadata.json"))
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

func TestSetIAMPolicy(t *testing.T) {
	for _, tt := range []struct {
		name            string
		policyErr       error
		setPolicyErr    error
		expectError     string
		useCustomPolicy bool
	}{
		{
			name: "set default policy",
		},
		{
			name:         "set default policy - error",
			expectError:  "failed to set default IAM policy: error setting default policy",
			setPolicyErr: errors.New("error setting default policy"),
		},
		{
			name:            "set custom policy",
			useCustomPolicy: true,
		},
		{
			name:            "set custom policy - error",
			expectError:     "failed to set custom IAM policy: error setting custom policy",
			setPolicyErr:    errors.New("error setting custom policy"),
			useCustomPolicy: true,
		},
		{
			name:            "get policy error",
			expectError:     "failed to retrieve IAM policy: error getting policy",
			policyErr:       errors.New("error getting policy"),
			useCustomPolicy: true,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.fakeIAMHandle.setPolicyError(tt.policyErr)
			ts.fakeKMSClient.fakeIAMHandle.setSetPolicyErr(tt.setPolicyErr)

			var configureReq *configv1.ConfigureRequest
			if tt.useCustomPolicy {
				customPolicyFile := getCustomPolicyFile(t)
				configureReq = configureRequestFromConfig(&Config{
					KeyMetadataFile:    createKeyMetadataFile(t, validServerID),
					KeyPolicyFile:      customPolicyFile,
					KeyRing:            validKeyRing,
					ServiceAccountFile: "service_account_file",
				})
				expectedPolicy, err := parsePolicyFile(customPolicyFile)
				require.NoError(t, err)
				ts.fakeKMSClient.fakeIAMHandle.setExpectedPolicy(expectedPolicy)
			} else {
				ts.fakeKMSClient.fakeIAMHandle.setExpectedPolicy(ts.fakeKMSClient.getDefaultPolicy())
				configureReq = configureRequestWithDefaults(t)
			}
			_, err := ts.plugin.Configure(ctx, configureReq)
			require.NoError(t, err)

			err = ts.plugin.setIamPolicy(ctx, cryptoKeyName1)
			if tt.expectError != "" {
				require.EqualError(t, err, tt.expectError)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestSignData(t *testing.T) {
	sum256 := sha256.Sum256(nil)
	sum384 := sha512.Sum384(nil)

	for _, tt := range []struct {
		name              string
		asymmetricSignErr error
		expectMsg         string
		expectCode        codes.Code
		generateKeyReq    *keymanagerv1.GenerateKeyRequest
		signDataReq       *keymanagerv1.SignDataRequest
		signatureCrc32C   *wrapperspb.Int64Value
	}{
		{
			name: "pass EC SHA256",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			signDataReq: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID1,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
		},
		{
			name: "pass EC SHA384",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P384,
			},
			signDataReq: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID1,
				Data:  sum384[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA384,
				},
			},
		},
		{
			name: "pass RSA 2048 SHA 256",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
			signDataReq: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID1,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
		},
		{
			name: "pass RSA 4096 SHA 256",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_RSA_4096,
			},
			signDataReq: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID1,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
		},
		{
			name: "pass RSA 2048 SHA 256",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
			signDataReq: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID1,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
		},
		{
			name:       "missing key id",
			expectCode: codes.InvalidArgument,
			expectMsg:  "key id is required",
			signDataReq: &keymanagerv1.SignDataRequest{
				KeyId: "",
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
		},
		{
			name:       "missing key signer opts",
			expectCode: codes.InvalidArgument,
			expectMsg:  "signer opts is required",
			signDataReq: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID1,
				Data:  sum256[:],
			},
		},
		{
			name:       "missing hash algorithm",
			expectCode: codes.InvalidArgument,
			expectMsg:  "hash algorithm is required",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			signDataReq: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID1,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM,
				},
			},
		},
		{
			name:       "usupported hash algorithm",
			expectCode: codes.InvalidArgument,
			expectMsg:  "hash algorithm not supported",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			signDataReq: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID1,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: 100,
				},
			},
		},
		{
			name:       "non existing key",
			expectCode: codes.NotFound,
			expectMsg:  "key \"does_not_exists\" not found",
			signDataReq: &keymanagerv1.SignDataRequest{
				KeyId: "does_not_exists",
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
		},
		{
			name:       "pss not supported",
			expectCode: codes.InvalidArgument,
			expectMsg:  "the only RSA signature scheme supported is RSASSA-PKCS1-v1_5",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
			signDataReq: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID1,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_PssOptions{
					PssOptions: &keymanagerv1.SignDataRequest_PSSOptions{
						HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
						SaltLength:    256,
					},
				},
			},
		},
		{
			name:              "sign error",
			asymmetricSignErr: errors.New("error signing"),
			expectCode:        codes.Internal,
			expectMsg:         "failed to sign: error signing",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			signDataReq: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID1,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
		},
		{
			name:       "integrity verification error",
			expectCode: codes.Internal,
			expectMsg:  "error signing: response corrupted in-transit",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			signDataReq: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID1,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
			signatureCrc32C: &wrapperspb.Int64Value{Value: 1},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.setAsymmetricSignErr(tt.asymmetricSignErr)
			ts.fakeKMSClient.setSignatureCrc32C(tt.signatureCrc32C)
			_, err := ts.plugin.Configure(ctx, configureRequestWithDefaults(t))
			require.NoError(t, err)
			if tt.generateKeyReq != nil {
				_, err := ts.plugin.GenerateKey(ctx, tt.generateKeyReq)
				require.NoError(t, err)
			}

			resp, err := ts.plugin.SignData(ctx, tt.signDataReq)
			spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
			if tt.expectCode != codes.OK {
				return
			}
			require.NotNil(t, resp)
		})
	}
}

func configureRequestFromConfig(c *Config) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration: fmt.Sprintf(`{
			"key_metadata_file":"%s",
			"key_policy_file":"%s",
			"key_ring":"%s",
			"service_account_file":"%s"
			}`,
			c.KeyMetadataFile,
			c.KeyPolicyFile,
			c.KeyRing,
			c.ServiceAccountFile),
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "test.example.org"},
	}
}

func configureRequestWithDefaults(t *testing.T) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration:  serializedConfiguration(createKeyMetadataFile(t, validServerID), validKeyRing),
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "test.example.org"},
	}
}

func configureRequestWithString(config string) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration: config,
	}
}

func configureRequestWithVars(keyMetadataFile, keyPolicyFile, keyRing, serviceAccountFile string) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration: fmt.Sprintf(`{
			"key_metadata_file":"%s",
			"key_policy_file":"%s",
			"key_ring":"%s"
			"service_account_file":"%s"
			}`,
			keyMetadataFile,
			keyPolicyFile,
			keyRing,
			serviceAccountFile),
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "test.example.org"},
	}
}

func createKeyMetadataFile(t *testing.T, content string) string {
	tempDir := t.TempDir()
	tempFilePath := filepath.ToSlash(filepath.Join(tempDir, validServerIDFile))

	if content != "" {
		err := os.WriteFile(tempFilePath, []byte(content), 0600)
		if err != nil {
			t.Error(err)
		}
	}
	return tempFilePath
}

func getCustomPolicyFile(t *testing.T) string {
	tempDir := t.TempDir()
	tempFilePath := filepath.ToSlash(filepath.Join(tempDir, validPolicyFile))
	err := os.WriteFile(tempFilePath, []byte(customPolicy), 0600)
	if err != nil {
		t.Error(err)
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

func waitForSignal(t *testing.T, ch chan error) error {
	select {
	case err := <-ch:
		return err
	case <-time.After(testTimeout):
		t.Fail()
	}
	return nil
}
