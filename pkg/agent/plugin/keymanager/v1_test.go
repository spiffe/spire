package keymanager_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
)

var (
	testKey            = testkey.MustRSA2048()
	testKeyPKIXData, _ = x509.MarshalPKIXPublicKey(testKey.Public())
)

func TestV1GenerateKey(t *testing.T) {
	for _, tt := range []struct {
		test          string
		err           error
		publicKey     *keymanagerv1.PublicKey
		expectCode    codes.Code
		expectMessage string
	}{
		{
			test:          "response missing key",
			expectCode:    codes.Internal,
			expectMessage: `keymanager(test): plugin response empty for key "foo"`,
		},
		{
			test:          "response has mismatched key ID",
			publicKey:     &keymanagerv1.PublicKey{Id: "bar"},
			expectCode:    codes.Internal,
			expectMessage: `keymanager(test): plugin response has unexpected key id "bar" for key "foo"`,
		},
		{
			test:          "response missing PKIX data",
			publicKey:     &keymanagerv1.PublicKey{Id: "foo"},
			expectCode:    codes.Internal,
			expectMessage: `keymanager(test): plugin response missing public key PKIX data for key "foo"`,
		},
		{
			test:          "response has malformed PKIX data",
			publicKey:     &keymanagerv1.PublicKey{Id: "foo", PkixData: []byte("malformed")},
			expectCode:    codes.Internal,
			expectMessage: `keymanager(test): unable to parse public key PKIX data for key "foo"`,
		},
		{
			test:          "RPC fails",
			err:           errors.New("ohno"),
			expectCode:    codes.Unknown,
			expectMessage: "keymanager(test): ohno",
		},
		{
			test:       "success",
			publicKey:  &keymanagerv1.PublicKey{Id: "foo", PkixData: testKeyPKIXData},
			expectCode: codes.OK,
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			plugin := fakeV1Plugin{
				generateKeyResponse: &keymanagerv1.GenerateKeyResponse{
					PublicKey: tt.publicKey,
				},
				generateKeyErr: tt.err,
			}
			km := loadV1Plugin(t, plugin)
			key, err := km.GenerateKey(context.Background(), "foo", keymanager.RSA2048)
			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMessage)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, key)
			assert.Equal(t, "foo", key.ID())
			assert.Equal(t, testKey.Public(), key.Public())
		})
	}
}

func TestV1GetKey(t *testing.T) {
	for _, tt := range []struct {
		test          string
		err           error
		publicKey     *keymanagerv1.PublicKey
		expectCode    codes.Code
		expectMessage string
	}{
		{
			test:          "response missing key",
			expectCode:    codes.NotFound,
			expectMessage: `keymanager(test): key "foo" not found`,
		},
		{
			test:          "response has mismatched key ID",
			publicKey:     &keymanagerv1.PublicKey{Id: "bar"},
			expectCode:    codes.Internal,
			expectMessage: `keymanager(test): plugin response has unexpected key id "bar" for key "foo"`,
		},
		{
			test:          "response missing PKIX data",
			publicKey:     &keymanagerv1.PublicKey{Id: "foo"},
			expectCode:    codes.Internal,
			expectMessage: `keymanager(test): plugin response missing public key PKIX data for key "foo"`,
		},
		{
			test:          "response has malformed PKIX data",
			publicKey:     &keymanagerv1.PublicKey{Id: "foo", PkixData: []byte("malformed")},
			expectCode:    codes.Internal,
			expectMessage: `keymanager(test): unable to parse public key PKIX data for key "foo"`,
		},
		{
			test:          "RPC fails",
			err:           errors.New("ohno"),
			expectCode:    codes.Unknown,
			expectMessage: "keymanager(test): ohno",
		},
		{
			test:       "success",
			publicKey:  &keymanagerv1.PublicKey{Id: "foo", PkixData: testKeyPKIXData},
			expectCode: codes.OK,
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			plugin := fakeV1Plugin{
				getPublicKeyResponse: &keymanagerv1.GetPublicKeyResponse{
					PublicKey: tt.publicKey,
				},
				getPublicKeyErr: tt.err,
			}
			km := loadV1Plugin(t, plugin)
			key, err := km.GetKey(context.Background(), "foo")
			spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMessage)
			if tt.expectCode != codes.OK {
				return
			}
			require.NotNil(t, key)
			assert.Equal(t, "foo", key.ID())
			assert.Equal(t, testKey.Public(), key.Public())
		})
	}
}

func TestV1GetKeys(t *testing.T) {
	for _, tt := range []struct {
		test          string
		err           error
		publicKey     *keymanagerv1.PublicKey
		expectCode    codes.Code
		expectMessage string
	}{
		{
			test:          "response missing PKIX data",
			publicKey:     &keymanagerv1.PublicKey{Id: "foo"},
			expectCode:    codes.Internal,
			expectMessage: `keymanager(test): plugin response missing public key PKIX data for key "foo"`,
		},
		{
			test:          "response has malformed PKIX data",
			publicKey:     &keymanagerv1.PublicKey{Id: "foo", PkixData: []byte("malformed")},
			expectCode:    codes.Internal,
			expectMessage: `keymanager(test): unable to parse public key PKIX data for key "foo"`,
		},
		{
			test:          "RPC fails",
			err:           errors.New("ohno"),
			expectCode:    codes.Unknown,
			expectMessage: "keymanager(test): ohno",
		},
		{
			test:       "success with no keys",
			expectCode: codes.OK,
		},
		{
			test:       "success with keys",
			publicKey:  &keymanagerv1.PublicKey{Id: "foo", PkixData: testKeyPKIXData},
			expectCode: codes.OK,
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			resp := &keymanagerv1.GetPublicKeysResponse{}
			if tt.publicKey != nil {
				resp.PublicKeys = []*keymanagerv1.PublicKey{tt.publicKey}
			}
			plugin := fakeV1Plugin{
				getPublicKeysResponse: resp,
				getPublicKeysErr:      tt.err,
			}
			km := loadV1Plugin(t, plugin)
			keys, err := km.GetKeys(context.Background())
			spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMessage)
			if tt.expectCode != codes.OK {
				return
			}
			if tt.publicKey != nil {
				require.Len(t, keys, 1, "expecting key in response")
				assert.Equal(t, "foo", keys[0].ID())
				assert.Equal(t, testKey.Public(), keys[0].Public())
			} else {
				require.Empty(t, keys, "expecting no keys in response")
			}
		})
	}
}

func TestV1SignData(t *testing.T) {
	hashAlgorithm := &keymanagerv1.SignDataRequest_HashAlgorithm{
		HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
	}
	pssOptions := &keymanagerv1.SignDataRequest_PssOptions{
		PssOptions: &keymanagerv1.SignDataRequest_PSSOptions{HashAlgorithm: keymanagerv1.HashAlgorithm_SHA384, SaltLength: 123},
	}

	for _, tt := range []struct {
		test             string
		err              error
		signerOpts       crypto.SignerOpts
		signature        string
		fingerprint      string
		expectSignerOpts interface{}
		expectCode       codes.Code
		expectMessage    string
	}{
		{
			test:             "response has mismatched fingerprint",
			signerOpts:       crypto.SHA256,
			signature:        "SIGNATURE",
			fingerprint:      "foo2",
			expectSignerOpts: hashAlgorithm,
			expectCode:       codes.Internal,
			expectMessage:    `keymanager(test): fingerprint "foo1" on key "foo" does not match "foo2"`,
		},
		{
			test:             "response missing signature",
			signerOpts:       crypto.SHA256,
			fingerprint:      "foo2",
			expectSignerOpts: hashAlgorithm,
			expectCode:       codes.Internal,
			expectMessage:    `keymanager(test): plugin returned empty signature data`,
		},
		{
			test:             "RPC fails",
			err:              errors.New("ohno"),
			signerOpts:       crypto.SHA256,
			expectSignerOpts: hashAlgorithm,
			expectCode:       codes.Unknown,
			expectMessage:    "keymanager(test): ohno",
		},
		{
			test:          "signer opts required",
			fingerprint:   "foo1",
			signature:     "SIGNATURE",
			expectCode:    codes.InvalidArgument,
			expectMessage: "signer opts cannot be nil",
		},
		{
			test:             "success with hash algorithm options",
			signerOpts:       crypto.SHA256,
			fingerprint:      "foo1",
			signature:        "SIGNATURE",
			expectSignerOpts: hashAlgorithm,
			expectCode:       codes.OK,
		},
		{
			test: "success with PSS options",
			signerOpts: &rsa.PSSOptions{
				SaltLength: 123,
				Hash:       crypto.SHA384,
			},
			fingerprint:      "foo1",
			signature:        "SIGNATURE",
			expectSignerOpts: pssOptions,
			expectCode:       codes.OK,
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			plugin := fakeV1Plugin{
				expectSignerOpts: tt.expectSignerOpts,
				getPublicKeysResponse: &keymanagerv1.GetPublicKeysResponse{
					PublicKeys: []*keymanagerv1.PublicKey{
						{Id: "foo", PkixData: testKeyPKIXData, Fingerprint: "foo1"},
					},
				},
				signDataResponse: &keymanagerv1.SignDataResponse{
					Signature:      []byte(tt.signature),
					KeyFingerprint: tt.fingerprint,
				},
				signDataErr: tt.err,
			}
			km := loadV1Plugin(t, plugin)
			keys, err := km.GetKeys(context.Background())
			require.NoError(t, err)
			require.Len(t, keys, 1)

			signature, err := keys[0].Sign(rand.Reader, []byte("DATA"), tt.signerOpts)
			spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMessage)
			if tt.expectCode != codes.OK {
				return
			}
			assert.Equal(t, "SIGNATURE", string(signature))
		})
	}
}

func loadV1Plugin(t *testing.T, plugin fakeV1Plugin) keymanager.KeyManager {
	server := keymanagerv1.KeyManagerPluginServer(&plugin)
	km := new(keymanager.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("test", server), km)
	return km
}

type fakeV1Plugin struct {
	keymanagerv1.UnimplementedKeyManagerServer

	expectSignerOpts interface{}

	generateKeyResponse   *keymanagerv1.GenerateKeyResponse
	generateKeyErr        error
	getPublicKeyResponse  *keymanagerv1.GetPublicKeyResponse
	getPublicKeyErr       error
	getPublicKeysResponse *keymanagerv1.GetPublicKeysResponse
	getPublicKeysErr      error
	signDataResponse      *keymanagerv1.SignDataResponse
	signDataErr           error
}

func (p *fakeV1Plugin) GenerateKey(_ context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyId != "foo" {
		return nil, status.Error(codes.InvalidArgument, "unexpected key id")
	}
	if req.KeyType != keymanagerv1.KeyType_RSA_2048 {
		return nil, status.Error(codes.InvalidArgument, "unexpected key type")
	}
	return p.generateKeyResponse, p.generateKeyErr
}

func (p *fakeV1Plugin) GetPublicKey(_ context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if req.KeyId != "foo" {
		return nil, status.Error(codes.InvalidArgument, "unexpected key id")
	}
	return p.getPublicKeyResponse, p.getPublicKeyErr
}

func (p *fakeV1Plugin) GetPublicKeys(context.Context, *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	return p.getPublicKeysResponse, p.getPublicKeysErr
}

func (p *fakeV1Plugin) SignData(_ context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	if req.KeyId != "foo" {
		return nil, status.Error(codes.InvalidArgument, "unexpected key id")
	}
	if string(req.Data) != "DATA" {
		return nil, status.Error(codes.InvalidArgument, "unexpected data to sign")
	}

	if diff := cmp.Diff(p.expectSignerOpts, req.GetSignerOpts(), protocmp.Transform()); diff != "" {
		fmt.Println("DIFF", diff)
		return nil, status.Errorf(codes.InvalidArgument, "unexpected signer opts %s", diff)
	}

	return p.signDataResponse, p.signDataErr
}
