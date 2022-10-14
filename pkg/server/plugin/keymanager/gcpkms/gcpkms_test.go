package gcpkms

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
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
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	cryptoKeyName1    = "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-eb0feec5-8526-482e-a42d-094c19b7ef5d-spireKeyID-1"
	cryptoKeyName2    = "projects/test-project/locations/us-east1/keyRings/test-key-ring/cryptoKeys/test-crypto-key/spire-key-eb0feec5-8526-482e-a42d-094c19b7ef5d-spireKeyID-2"
	spireKeyID1       = "spireKeyID-1"
	spireKeyID2       = "spireKeyID-2"
	testTimeout       = 60 * time.Second
	validPolicyFile   = "custom_policy_file.json"
	validServerID     = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	validServerIDFile = "test-server-id"
	validKeyRing      = "projects/project-name/locations/location-name/keyRings/key-ring-name"
)

var (
	ctx       = context.Background()
	fakeTime  = timestamppb.Now()
	unixEpoch = time.Unix(0, 0)
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
	c.Set(unixEpoch)
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
						Name:            cryptoKeyName1,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
							},
						},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"2": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/2", cryptoKeyName1),
							},
						},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName2,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName2),
							},
						},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName2,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"2": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/2", cryptoKeyName2),
							},
						},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
							},
						},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"2": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/2", cryptoKeyName1),
							},
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
			configureRequest: configureRequestWithVars(getKeyMetadataFile(t), "", validKeyRing, "service_account_file"),
		},
		{
			name:             "missing key ring",
			configureRequest: configureRequestWithVars(getKeyMetadataFile(t), "", "", ""),
			expectMsg:        "configuration is missing the key ring",
			expectCode:       codes.InvalidArgument,
		},
		{
			name:             "missing server id file path",
			configureRequest: configureRequestWithVars("", "", validKeyRing, "service_account_file"),
			expectMsg:        "configuration is missing server ID file path",
			expectCode:       codes.InvalidArgument,
		},
		{
			name:             "custom policy file does not exist",
			configureRequest: configureRequestWithVars(getKeyMetadataFile(t), "non-existent-file.json", validKeyRing, "service_account_file"),
			expectMsg:        fmt.Sprintf("could not parse policy file: failed to read file: open non-existent-file.json: %s", spiretest.FileNotFound()),
			expectCode:       codes.Internal,
		},
		{
			name:             "use custom policy file",
			configureRequest: configureRequestWithVars(getKeyMetadataFile(t), getCustomPolicyFile(t), validKeyRing, "service_account_file"),
		},
		{
			name:             "new server id file path",
			configureRequest: configureRequestWithVars(getEmptyKeyMetadataFile(t), getCustomPolicyFile(t), validKeyRing, "service_account_file"),
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
						Name:            cryptoKeyName1,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
							},
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

func TestDisposeCryptoKeys(t *testing.T) {
	for _, tt := range []struct {
		name              string
		configureRequest  *configv1.ConfigureRequest
		err               string
		fakeCryptoKeys    []fakeCryptoKey
		listCryptoKeysErr error
	}{
		{
			name:             "dispose CryptoKeys succeeds",
			configureRequest: configureRequestWithDefaults(t),
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          make(map[string]string),
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
							}},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName2,
						Labels:          make(map[string]string),
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName2),
							}},
					},
				},
			},
		},
		{
			name:              "list CryptoKeys error",
			configureRequest:  configureRequestWithDefaults(t),
			err:               "list keys failure",
			listCryptoKeysErr: errors.New("list keys failure"),
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          make(map[string]string),
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
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

			// This is so dispose aliases blocks on init and allows to test dispose keys isolated
			ts.plugin.hooks.disposeCryptoKeysSignal = make(chan error)
			disposeCryptoKeysSignal := make(chan error)
			ts.plugin.hooks.disposeCryptoKeysSignal = disposeCryptoKeysSignal
			scheduleDestroySignal := make(chan error)
			ts.plugin.hooks.scheduleDestroySignal = scheduleDestroySignal

			// exercise
			_, err := ts.plugin.Configure(ctx, tt.configureRequest)
			require.NoError(t, err)

			ts.fakeKMSClient.listCryptoKeysErr = tt.listCryptoKeysErr

			// wait for dispose keys task to be initialized
			_ = waitForSignal(t, disposeCryptoKeysSignal)
			// move the clock forward so the task is run
			ts.clockHook.Add(48 * time.Hour)
			// wait for dispose keys to be run
			err = waitForSignal(t, disposeCryptoKeysSignal)
			// assert errors
			if tt.err != "" {
				require.NotNil(t, err)
				require.Equal(t, tt.err, err.Error())
				return
			}
			// wait for schedule delete to be run
			_ = waitForSignal(t, scheduleDestroySignal)

			// assert
			for _, cryptoKey := range ts.fakeKMSClient.store.fakeCryptoKeys {
				require.Equal(t, cryptoKey.Labels[labelNameActive], "false")
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	for _, tt := range []struct {
		configureReq   *configv1.ConfigureRequest
		expectCode     codes.Code
		expectMsg      string
		destroyTime    *timestamp.Timestamp
		fakeCryptoKeys []fakeCryptoKey
		generateKeyReq *keymanagerv1.GenerateKeyRequest
		logs           []spiretest.LogEntry
		name           string
		waitForDelete  bool

		createKeyErr               error
		destroyCryptoKeyVersionErr error
		getCryptoKeyVersionErr     error
		getPublicKeyErr            error
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
			configureReq: configureRequestWithVars(getEmptyKeyMetadataFile(t), "", validKeyRing, "service_account_file"),
		},
		{
			name: "success: non existing key with custom policy",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			configureReq: configureRequestWithVars(getEmptyKeyMetadataFile(t), getCustomPolicyFile(t), validKeyRing, "service_account_file"),
		},
		{
			name: "success: replace old key",
			generateKeyReq: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID1,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
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
			name:            "get public key error",
			expectMsg:       "failed to get public key: public key error",
			expectCode:      codes.Internal,
			getPublicKeyErr: errors.New("public key error"),
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
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
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
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
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
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
								State:     kmspb.CryptoKeyVersion_DISABLED,
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
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
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
			ts.fakeKMSClient.destroyTime = fakeTime
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)
			ts.fakeKMSClient.createCryptoKeyErr = tt.createKeyErr
			ts.fakeKMSClient.getCryptoKeyVersionErr = tt.getCryptoKeyVersionErr
			ts.fakeKMSClient.getTokeninfoErr = tt.getTokenInfoErr
			ts.fakeKMSClient.updateCryptoKeyErr = tt.updateCryptoKeyErr
			ts.fakeKMSClient.destroyCryptoKeyVersionErr = tt.destroyCryptoKeyVersionErr
			destroySignal := make(chan error)
			ts.plugin.hooks.scheduleDestroySignal = destroySignal

			configureReq := tt.configureReq
			if configureReq == nil {
				configureReq = configureRequestWithDefaults(t)
			}
			_, err := ts.plugin.Configure(ctx, configureReq)
			require.NoError(t, err)

			ts.fakeKMSClient.getPublicKeyErr = tt.getPublicKeyErr

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
			case <-destroySignal:
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

func TestGetPublicKey(t *testing.T) {
	for _, tt := range []struct {
		name           string
		expectCode     codes.Code
		expectMsg      string
		fakeCryptoKeys []fakeCryptoKey

		keyID string
	}{
		{
			name: "existing key",
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
							}},
					},
				},
			},
			keyID: spireKeyID1,
		},
		{
			name:       "non existing key",
			expectMsg:  fmt.Sprintf("key %q not found", spireKeyID1),
			expectCode: codes.NotFound,
			keyID:      spireKeyID1,
		},
		{
			name:       "missing key id",
			expectMsg:  "key id is required",
			expectCode: codes.InvalidArgument,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.putFakeCryptoKeys(tt.fakeCryptoKeys)

			_, err := ts.plugin.Configure(ctx, configureRequestWithDefaults(t))
			require.NoError(t, err)

			resp, err := ts.plugin.GetPublicKey(ctx, &keymanagerv1.GetPublicKeyRequest{
				KeyId: tt.keyID,
			})
			if tt.expectMsg != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}
			require.NotNil(t, resp)
			require.NoError(t, err)
			require.Equal(t, tt.keyID, resp.PublicKey.Id)
			require.Equal(t, ts.plugin.entries[tt.keyID].publicKey, resp.PublicKey)
		})
	}
}

func TestGetPublicKeys(t *testing.T) {
	for _, tt := range []struct {
		name           string
		err            string
		fakeCryptoKeys []fakeCryptoKey
	}{
		{
			name: "one key",
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
							}},
					},
				},
			},
		},
		{
			name: "multiple keys",
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
							}},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName2,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName2),
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
				require.Equal(t, err.Error(), tt.err)
				return
			}

			require.NotNil(t, resp)
			require.NoError(t, err)
			for i, fck := range tt.fakeCryptoKeys {
				for _, fckv := range fck.fakeCryptoKeyVersions {
					pubKey, err := ts.plugin.getPublicKeyFromCryptoKeyVersion(ctx, fckv.CryptoKeyVersion.Name)
					require.NoError(t, err)
					require.Equal(t, pubKey, resp.PublicKeys[i].PkixData)
				}
			}
		})
	}
}

func TestKeepActiveCryptoKeys(t *testing.T) {
	for _, tt := range []struct {
		configureRequest   *configv1.ConfigureRequest
		expectError        string
		fakeCryptoKeys     []fakeCryptoKey
		name               string
		updateCryptoKeyErr error
	}{
		{
			name:               "keep active CryptoKeys error",
			configureRequest:   configureRequestWithDefaults(t),
			expectError:        "error updating CryptoKey",
			updateCryptoKeyErr: errors.New("error updating CryptoKey"),
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          make(map[string]string),
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
							}},
					},
				},
			},
		},
		{
			name:             "keep active CryptoKeys succeeds",
			configureRequest: configureRequestWithDefaults(t),
			fakeCryptoKeys: []fakeCryptoKey{
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName1,
						Labels:          make(map[string]string),
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName1),
							}},
					},
				},
				{
					CryptoKey: &kmspb.CryptoKey{
						Name:            cryptoKeyName2,
						Labels:          make(map[string]string),
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
					},
					fakeCryptoKeyVersions: map[string]*fakeCryptoKeyVersion{
						"1": {
							publicKey: &kmspb.PublicKey{Pem: pemCert},
							CryptoKeyVersion: &kmspb.CryptoKeyVersion{
								Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
								Name:      fmt.Sprintf("%s/cryptoKeyVersions/1", cryptoKeyName2),
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
			ts.fakeKMSClient.updateCryptoKeyErr = tt.updateCryptoKeyErr
			keepActiveCryptoKeysSignal := make(chan error)
			ts.plugin.hooks.keepActiveCryptoKeysSignal = keepActiveCryptoKeysSignal

			_, err := ts.plugin.Configure(ctx, tt.configureRequest)
			require.NoError(t, err)

			// Wait for keepActiveCryptoKeys task to be initialized.
			_ = waitForSignal(t, keepActiveCryptoKeysSignal)

			// Move the clock forward so the task is run.
			currentTime := unixEpoch.Add(6 * time.Hour)
			ts.clockHook.Set(currentTime)

			// Wait for keepActiveCryptoKeys to be run.
			err = waitForSignal(t, keepActiveCryptoKeysSignal)

			if tt.updateCryptoKeyErr != nil {
				require.NotNil(t, err)
				require.Equal(t, tt.expectError, err.Error())
				return
			}
			require.NoError(t, err)

			for _, cryptoKey := range ts.fakeKMSClient.store.fakeCryptoKeys {
				require.EqualValues(t, cryptoKey.Labels[labelNameLastUpdate], fmt.Sprint(currentTime.Unix()), cryptoKey.CryptoKey.Name)
			}
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
			expectError:     "failed to set default IAM policy: error setting custom policy",
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
			ts.fakeKMSClient.fakeIAMHandle.policyErr = tt.policyErr
			ts.fakeKMSClient.fakeIAMHandle.setPolicyErr = tt.setPolicyErr

			var configureReq *configv1.ConfigureRequest
			if tt.useCustomPolicy {
				customPolicyFile := getCustomPolicyFile(t)
				configureReq = configureRequestWithVars(getKeyMetadataFile(t), customPolicyFile, validKeyRing, "service_account_file")
				expectedPolicy, err := parsePolicyFile(customPolicyFile)
				require.NoError(t, err)
				ts.fakeKMSClient.fakeIAMHandle.expectedPolicy = expectedPolicy
			} else {
				ts.fakeKMSClient.fakeIAMHandle.expectedPolicy = ts.fakeKMSClient.getDefaultPolicy()
				configureReq = configureRequestWithDefaults(t)
			}
			_, err := ts.plugin.Configure(ctx, configureReq)
			require.NoError(t, err)

			err = ts.plugin.setIamPolicy(ctx, cryptoKeyName1)
			if tt.expectError != "" {
				require.Error(t, err, tt.expectError)
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
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ts := setupTest(t)
			ts.fakeKMSClient.asymmetricSignErr = tt.asymmetricSignErr
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

func getKeyMetadataFile(t *testing.T) string {
	tempDir := t.TempDir()
	tempFilePath := filepath.ToSlash(filepath.Join(tempDir, validServerIDFile))
	err := os.WriteFile(tempFilePath, []byte(validServerID), 0600)
	if err != nil {
		t.Error(err)
	}
	return tempFilePath
}

func getEmptyKeyMetadataFile(t *testing.T) string {
	tempDir := t.TempDir()
	keyMetadataFile := filepath.ToSlash(filepath.Join(tempDir, validServerIDFile))
	return keyMetadataFile
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
