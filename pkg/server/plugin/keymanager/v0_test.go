package keymanager_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/plugin/server/keymanager/v0"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestV0GenerateKey(t *testing.T) {
	for _, tt := range []struct {
		test          string
		err           error
		publicKey     *keymanagerv0.PublicKey
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
			publicKey:     &keymanagerv0.PublicKey{Id: "bar"},
			expectCode:    codes.Internal,
			expectMessage: `keymanager(test): plugin response has unexpected key id "bar" for key "foo"`,
		},
		{
			test:          "response missing PKIX data",
			publicKey:     &keymanagerv0.PublicKey{Id: "foo"},
			expectCode:    codes.Internal,
			expectMessage: `keymanager(test): plugin response missing public key PKIX data for key "foo"`,
		},
		{
			test:          "response has malformed PKIX data",
			publicKey:     &keymanagerv0.PublicKey{Id: "foo", PkixData: []byte("malformed")},
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
			publicKey:  &keymanagerv0.PublicKey{Id: "foo", PkixData: testKeyPKIXData},
			expectCode: codes.OK,
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			plugin := fakeV0Plugin{
				generateKeyResponse: &keymanagerv0.GenerateKeyResponse{
					PublicKey: tt.publicKey,
				},
				generateKeyErr: tt.err,
			}
			km := loadV0Plugin(t, plugin)
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

func TestV0GetKey(t *testing.T) {
	for _, tt := range []struct {
		test          string
		err           error
		publicKey     *keymanagerv0.PublicKey
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
			publicKey:     &keymanagerv0.PublicKey{Id: "bar"},
			expectCode:    codes.Internal,
			expectMessage: `keymanager(test): plugin response has unexpected key id "bar" for key "foo"`,
		},
		{
			test:          "response missing PKIX data",
			publicKey:     &keymanagerv0.PublicKey{Id: "foo"},
			expectCode:    codes.Internal,
			expectMessage: `keymanager(test): plugin response missing public key PKIX data for key "foo"`,
		},
		{
			test:          "response has malformed PKIX data",
			publicKey:     &keymanagerv0.PublicKey{Id: "foo", PkixData: []byte("malformed")},
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
			publicKey:  &keymanagerv0.PublicKey{Id: "foo", PkixData: testKeyPKIXData},
			expectCode: codes.OK,
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			plugin := fakeV0Plugin{
				getPublicKeyResponse: &keymanagerv0.GetPublicKeyResponse{
					PublicKey: tt.publicKey,
				},
				getPublicKeyErr: tt.err,
			}
			km := loadV0Plugin(t, plugin)
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

func TestV0GetKeys(t *testing.T) {
	for _, tt := range []struct {
		test          string
		err           error
		publicKey     *keymanagerv0.PublicKey
		expectCode    codes.Code
		expectMessage string
	}{
		{
			test:          "response missing PKIX data",
			publicKey:     &keymanagerv0.PublicKey{Id: "foo"},
			expectCode:    codes.Internal,
			expectMessage: `keymanager(test): plugin response missing public key PKIX data for key "foo"`,
		},
		{
			test:          "response has malformed PKIX data",
			publicKey:     &keymanagerv0.PublicKey{Id: "foo", PkixData: []byte("malformed")},
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
			publicKey:  &keymanagerv0.PublicKey{Id: "foo", PkixData: testKeyPKIXData},
			expectCode: codes.OK,
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			resp := &keymanagerv0.GetPublicKeysResponse{}
			if tt.publicKey != nil {
				resp.PublicKeys = []*keymanagerv0.PublicKey{tt.publicKey}
			}
			plugin := fakeV0Plugin{
				getPublicKeysResponse: resp,
				getPublicKeysErr:      tt.err,
			}
			km := loadV0Plugin(t, plugin)
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

func TestV0SignData(t *testing.T) {
	hashAlgorithm := &keymanagerv0.SignDataRequest_HashAlgorithm{
		HashAlgorithm: keymanagerv0.HashAlgorithm_SHA256,
	}
	pssOptions := &keymanagerv0.SignDataRequest_PssOptions{
		PssOptions: &keymanagerv0.PSSOptions{HashAlgorithm: keymanagerv0.HashAlgorithm_SHA384, SaltLength: 123},
	}

	for _, tt := range []struct {
		test             string
		err              error
		signerOpts       crypto.SignerOpts
		signature        string
		expectSignerOpts interface{}
		expectCode       codes.Code
		expectMessage    string
	}{
		{
			test:             "response missing signature",
			signerOpts:       crypto.SHA256,
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
			signature:     "SIGNATURE",
			expectCode:    codes.InvalidArgument,
			expectMessage: "signer opts cannot be nil",
		},
		{
			test:             "success with hash algorithm options",
			signerOpts:       crypto.SHA256,
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
			signature:        "SIGNATURE",
			expectSignerOpts: pssOptions,
			expectCode:       codes.OK,
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			plugin := fakeV0Plugin{
				expectSignerOpts: tt.expectSignerOpts,
				getPublicKeysResponse: &keymanagerv0.GetPublicKeysResponse{
					PublicKeys: []*keymanagerv0.PublicKey{
						{Id: "foo", PkixData: testKeyPKIXData},
					},
				},
				signDataResponse: &keymanagerv0.SignDataResponse{
					Signature: []byte(tt.signature),
				},
				signDataErr: tt.err,
			}
			km := loadV0Plugin(t, plugin)
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

func loadV0Plugin(t *testing.T, plugin fakeV0Plugin) keymanager.KeyManager {
	server := keymanagerv0.KeyManagerPluginServer(&plugin)
	km := new(keymanager.V0)
	plugintest.Load(t, catalog.MakeBuiltIn("test", server), km)
	return km
}

type fakeV0Plugin struct {
	keymanagerv0.UnimplementedKeyManagerServer

	expectSignerOpts interface{}

	generateKeyResponse   *keymanagerv0.GenerateKeyResponse
	generateKeyErr        error
	getPublicKeyResponse  *keymanagerv0.GetPublicKeyResponse
	getPublicKeyErr       error
	getPublicKeysResponse *keymanagerv0.GetPublicKeysResponse
	getPublicKeysErr      error
	signDataResponse      *keymanagerv0.SignDataResponse
	signDataErr           error
}

func (p *fakeV0Plugin) GenerateKey(ctx context.Context, req *keymanagerv0.GenerateKeyRequest) (*keymanagerv0.GenerateKeyResponse, error) {
	if req.KeyId != "foo" {
		return nil, status.Error(codes.InvalidArgument, "unexpected key id")
	}
	if req.KeyType != keymanagerv0.KeyType_RSA_2048 {
		return nil, status.Error(codes.InvalidArgument, "unexpected key type")
	}
	return p.generateKeyResponse, p.generateKeyErr
}

func (p *fakeV0Plugin) GetPublicKey(ctx context.Context, req *keymanagerv0.GetPublicKeyRequest) (*keymanagerv0.GetPublicKeyResponse, error) {
	if req.KeyId != "foo" {
		return nil, status.Error(codes.InvalidArgument, "unexpected key id")
	}
	return p.getPublicKeyResponse, p.getPublicKeyErr
}

func (p *fakeV0Plugin) GetPublicKeys(ctx context.Context, req *keymanagerv0.GetPublicKeysRequest) (*keymanagerv0.GetPublicKeysResponse, error) {
	return p.getPublicKeysResponse, p.getPublicKeysErr
}

func (p *fakeV0Plugin) SignData(ctx context.Context, req *keymanagerv0.SignDataRequest) (*keymanagerv0.SignDataResponse, error) {
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
