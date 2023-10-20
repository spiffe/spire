package ciphertrustkms

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"

	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
)

const (
	spireKeyID1       = "spireKeyID-1"
	spireKeyID2       = "spireKeyID-2"
	testTimeout       = 60 * time.Second
	validServerID     = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	validServerIDFile = "test-server-id"
	ctmService        = "http://testService"
	username          = "test_username"
	pwd               = "test_pwd"
)

var (
	ctx            = context.Background()
	cryptoKeyName1 = fmt.Sprintf("spire-key-%s-spireKeyID-1", validServerID)
	cryptoKeyName2 = fmt.Sprintf("spire-key-%s-spireKeyID-2", validServerID)
	unixEpoch      = time.Unix(0, 0)
	pubKeyFake     = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEki9F9qnTdHPQW01lsW++cttsgtxM\nRjGkgxU7bRTzOrabnzeZs81AEnQzO0f9Lu6ZBhnJeA2/mvghFcyxj8Itqw==\n-----END PUBLIC KEY-----\n"
)

type pluginTest struct {
	plugin        *Plugin
	fakeKMSClient *fakeKMSClientCipherTrust
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
		func(ctx context.Context, opts ...option.ClientOption) (cloudKeyManagementServiceCipherTrust, error) {
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

func TestKeepActiveCryptoKeys(t *testing.T) {
	for _, tt := range []struct {
		configureRequest *configv1.ConfigureRequest
		config           *Config
		fakeCryptoKeys   []*FakeCryptoKey
		name             string
	}{
		{
			name: "keep active CryptoKeys succeeds",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			fakeCryptoKeys: []*FakeCryptoKey{
				{
					Name: cryptoKeyName1,
					Versions: map[int]*FakeKey{
						0: {
							Key: &Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{labelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
				{
					Name: cryptoKeyName2,
					Versions: map[int]*FakeKey{
						0: {
							Key: &Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName2,
								KeyID:     spireKeyID2,
								Labels:    map[string]string{labelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)
			ts.plugin.hooks.keepActiveCryptoKeysSignal = make(chan error)

			var configureRequest *configv1.ConfigureRequest
			if tt.config != nil {
				require.Nil(t, tt.configureRequest, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = configureRequestFromConfigCipherTrust(tt.config)
			} else {
				require.Nil(t, tt.config, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = tt.configureRequest
			}
			_, err := ts.plugin.Configure(ctx, configureRequest)
			require.NoError(t, err)

			// Wait for keepActiveCryptoKeys task to be initialized.
			_ = waitForSignal(t, ts.plugin.hooks.keepActiveCryptoKeysSignal)

			// Move the clock forward so the task is run.
			currentTime := unixEpoch.Add(6 * time.Hour)
			ts.clockHook.Set(currentTime)

			// Wait for keepActiveCryptoKeys to be run.
			err = waitForSignal(t, ts.plugin.hooks.keepActiveCryptoKeysSignal)

			require.NoError(t, err)

			storedFakeCryptoKeys := ts.fakeKMSClient.store.fetchFakeCryptoKeys()
			for _, fakeCryptoKey := range storedFakeCryptoKeys {
				for _, fakeKey := range fakeCryptoKey.Versions {
					require.EqualValues(t, fakeCryptoKey.getLabelValue(fakeKey.Version, labelNameLastUpdate), fmt.Sprint(currentTime.Unix()), fakeCryptoKey.Name)
				}
			}
		})
	}
}

func TestConfigureCipherTrust(t *testing.T) {
	for _, tt := range []struct {
		name             string
		expectMsg        string
		expectCode       codes.Code
		config           *Config
		configureRequest *configv1.ConfigureRequest
		fakeCryptoKeys   []*FakeCryptoKey
	}{
		{
			name: "missing CipherTrust service",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				Username:        username,
				Password:        pwd,
			},
			expectMsg:  "configuration is missing the CipherTrust service URL",
			expectCode: codes.InvalidArgument,
		},
		{
			name: "missing CipherTrust service username",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Password:        pwd,
			},
			expectMsg:  "configuration is missing the CipherTrust service Username",
			expectCode: codes.InvalidArgument,
		},
		{
			name: "missing CipherTrust service password",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
			},
			expectMsg:  "configuration is missing CipherTrust service Password",
			expectCode: codes.InvalidArgument,
		},
		{
			name: "pass with keys",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			fakeCryptoKeys: []*FakeCryptoKey{
				{
					Name: cryptoKeyName1,
					Versions: map[int]*FakeKey{
						0: {
							Key: &Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{labelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
						1: {
							Key: &Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{labelNameActive: "true"},
								Version:   1,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},

				{
					Name: cryptoKeyName2,
					Versions: map[int]*FakeKey{
						0: {
							Key: &Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName2,
								KeyID:     spireKeyID2,
								Labels:    map[string]string{labelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
						1: {
							Key: &Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName2,
								KeyID:     spireKeyID2,
								Labels:    map[string]string{labelNameActive: "true"},
								Version:   1,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)

			var configureRequest *configv1.ConfigureRequest
			if tt.config != nil {
				require.Nil(t, tt.configureRequest, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = configureRequestFromConfigCipherTrust(tt.config)
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
				spireKeyID, ok := getSPIREKeyIDFromCryptoKeyNameCipherTrust(expectedFakeCryptoKey.Name)
				require.True(t, ok)

				entry, ok := ts.plugin.entries[spireKeyID]
				require.True(t, ok)
				require.Equal(t, expectedFakeCryptoKey.Name, entry.cryptoKey.Name)
			}

		})
	}
}

func TestGenerateKey(t *testing.T) {
	for _, tt := range []struct {
		configureRequest *configv1.ConfigureRequest
		config           *Config
		expectCode       codes.Code
		expectMsg        string
		destroyTime      *timestamp.Timestamp
		fakeCryptoKeys   []*FakeCryptoKey
		generateKeyReq   *keymanagerv1.GenerateKeyRequest
		logs             []spiretest.LogEntry
		name             string
		createKeyErr     error
	}{
		{
			name: "success: EC 256",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},

		{
			name: "success: replace old key",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			fakeCryptoKeys: []*FakeCryptoKey{
				{
					Name: cryptoKeyName1,
					Versions: map[int]*FakeKey{
						0: {
							Key: &Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{labelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
						1: {
							Key: &Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{labelNameActive: "true"},
								Version:   1,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)
			var err error

			var configureRequest *configv1.ConfigureRequest
			if tt.config != nil {
				require.Nil(t, tt.configureRequest, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = configureRequestFromConfigCipherTrust(tt.config)
			} else {
				require.Nil(t, tt.config, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = tt.configureRequest
			}

			coreConfig := catalog.CoreConfig{
				TrustDomain: spiffeid.RequireTrustDomainFromString("test.example.org"),
			}
			km := new(keymanager.V1)

			plugintest.Load(t, builtin(ts.plugin), km,
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(coreConfig),
				plugintest.Configure(configureRequest.HclConfiguration),
				plugintest.Log(ts.log),
			)
			require.NoError(t, err)

			resp, err := ts.plugin.GenerateKey(ctx, tt.generateKeyReq)
			if tt.expectMsg != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestDeactivateKeys(t *testing.T) {
	for _, tt := range []struct {
		configureRequest *configv1.ConfigureRequest
		config           *Config
		expectCode       codes.Code
		expectMsg        string
		deactivationDate string
		destroyTime      *timestamp.Timestamp
		fakeCryptoKeys   []*FakeCryptoKey
		generateKeyReq   *keymanagerv1.GenerateKeyRequest
		logs             []spiretest.LogEntry
		name             string
		createKeyErr     error
	}{
		{
			name: "success: state has changed from active to deactivated",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			deactivationDate: time.Now().Add(time.Hour * time.Duration(24)).Format(time.RFC3339Nano),
			expectMsg:        "Deactivated",
			fakeCryptoKeys: []*FakeCryptoKey{
				{
					Name: cryptoKeyName1,
					Versions: map[int]*FakeKey{
						0: {
							Key: &Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{labelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			//pre-req
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)
			ts.plugin.hooks.disposeCryptoKeysSignal = make(chan error)

			var configureRequest *configv1.ConfigureRequest
			if tt.config != nil {
				require.Nil(t, tt.configureRequest, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = configureRequestFromConfigCipherTrust(tt.config)
			} else {
				require.Nil(t, tt.config, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = tt.configureRequest
			}
			_, err := ts.plugin.Configure(ctx, configureRequest)
			require.NoError(t, err)

			// Wait for TestDeactivateKeys task to be initialized.
			_ = waitForSignal(t, ts.plugin.hooks.disposeCryptoKeysSignal)

			// Move the clock forward so the task is run.
			currentTime := unixEpoch.Add(24 * time.Hour)
			ts.clockHook.Set(currentTime)

			// Wait for TestDeactivateKeys to be run.
			err = waitForSignal(t, ts.plugin.hooks.disposeCryptoKeysSignal)

			require.NoError(t, err)

			storedFakeCryptoKeys := ts.fakeKMSClient.store.fetchFakeCryptoKeys()
			for _, fakeCryptoKey := range storedFakeCryptoKeys {
				for _, fakeKey := range fakeCryptoKey.Versions {
					require.EqualValues(t, tt.expectMsg, fakeCryptoKey.getState(fakeKey.Version))
				}
			}

		})
	}
}

func TestGetPublicKeys(t *testing.T) {
	for _, tt := range []struct {
		name             string
		configureRequest *configv1.ConfigureRequest
		config           *Config
		err              string
		fakeCryptoKeys   []*FakeCryptoKey
	}{
		{
			name: "one key",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			fakeCryptoKeys: []*FakeCryptoKey{
				{
					Name: cryptoKeyName1,
					Versions: map[int]*FakeKey{
						0: {
							Key: &Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{labelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
			},
		},
		{
			name: "multiple keys",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			fakeCryptoKeys: []*FakeCryptoKey{
				{
					Name: cryptoKeyName1,
					Versions: map[int]*FakeKey{
						0: {
							Key: &Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{labelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
						1: {
							Key: &Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{labelNameActive: "true"},
								Version:   1,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
				{
					Name: cryptoKeyName2,
					Versions: map[int]*FakeKey{
						0: {
							Key: &Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName2,
								KeyID:     spireKeyID2,
								Labels:    map[string]string{labelNameActive: "true"},
								Version:   0,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
			},
		},
		{
			name: "non existing keys",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)

			var configureRequest *configv1.ConfigureRequest
			if tt.config != nil {
				require.Nil(t, tt.configureRequest, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = configureRequestFromConfigCipherTrust(tt.config)
			} else {
				require.Nil(t, tt.config, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = tt.configureRequest
			}
			_, err := ts.plugin.Configure(ctx, configureRequest)
			require.NoError(t, err)

			resp, err := ts.plugin.GetPublicKeys(ctx, &keymanagerv1.GetPublicKeysRequest{})

			if tt.err != "" {
				require.Error(t, err)
				require.EqualError(t, err, tt.err)
				return
			}

			require.NotNil(t, resp)
			require.NoError(t, err)

			// Assert that the keys have been loaded
			storedFakeCryptoKeys := ts.fakeKMSClient.store.fetchFakeCryptoKeys()
			for _, fakeKey := range storedFakeCryptoKeys {
				for _, versions := range fakeKey.Versions {
					pubKey, err := getPublicKeyFromCryptoKeyVersionCipherTrust(ctx, ts.plugin.log, ts.fakeKMSClient, versions.Key)
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
		configureRequest       *configv1.ConfigureRequest
		config                 *Config
		expectCodeConfigure    codes.Code
		expectMsgConfigure     string
		expectCodeGetPublicKey codes.Code
		expectMsgGetPublicKey  string
		fakeCryptoKeys         []*FakeCryptoKey
		keyID                  string
	}{
		{
			name: "existing key",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			fakeCryptoKeys: []*FakeCryptoKey{
				{
					Name: cryptoKeyName1,

					Versions: map[int]*FakeKey{

						0: {
							Key: &Key{
								PublicKey: pubKeyFake,

								Name:    cryptoKeyName1,
								Labels:  map[string]string{labelNameActive: "true"},
								Version: 0,
								State:   "Active",
								CurveID: "prime256v1",
							},
						},
						1: {
							Key: &Key{
								PublicKey: pubKeyFake,
								Name:      cryptoKeyName1,
								KeyID:     spireKeyID1,
								Labels:    map[string]string{labelNameActive: "true"},
								Version:   1,
								State:     "Active",
								CurveID:   "prime256v1",
							},
						},
					},
				},
			},
			keyID: spireKeyID1,
		},
		{
			name: "non existing key",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			expectMsgGetPublicKey:  fmt.Sprintf("key %q not found", "wrongkey"),
			expectCodeGetPublicKey: codes.NotFound,
			keyID:                  "wrongkey",
		},
		{
			name: "missing key id",
			config: &Config{
				KeyMetadataFile: createKeyMetadataFile(t, validServerID),
				CTMService:      ctmService,
				Username:        username,
				Password:        pwd,
			},
			expectMsgGetPublicKey:  "key id is required",
			expectCodeGetPublicKey: codes.InvalidArgument,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)

			var configureRequest *configv1.ConfigureRequest
			if tt.config != nil {
				require.Nil(t, tt.configureRequest, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = configureRequestFromConfigCipherTrust(tt.config)
			} else {
				require.Nil(t, tt.config, "The test case must define a configuration or a configuration request, not both.")
				configureRequest = tt.configureRequest
			}
			_, err := ts.plugin.Configure(ctx, configureRequest)
			require.NoError(t, err)

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
func configureRequestFromConfigCipherTrust(c *Config) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration: fmt.Sprintf(`{
            "key_metadata_file":"%s",
			"ctm_url":"%s",
			"username":"%s",
			"password":"%s"
            }`,
			c.KeyMetadataFile,
			c.CTMService,
			c.Username,
			c.Password),
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "test.example.org"},
	}
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
