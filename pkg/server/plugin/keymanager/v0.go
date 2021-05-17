package keymanager

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"io"

	"github.com/spiffe/spire/pkg/common/plugin"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/plugin/server/keymanager/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type V0 struct {
	plugin.Facade
	keymanagerv0.KeyManagerPluginClient
}

func (v0 *V0) GenerateKey(ctx context.Context, id string, keyType KeyType) (Key, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	kt, err := v0.convertKeyType(keyType)
	if err != nil {
		return nil, err
	}

	resp, err := v0.KeyManagerPluginClient.GenerateKey(ctx, &keymanagerv0.GenerateKeyRequest{
		KeyId:   id,
		KeyType: kt,
	})
	if err != nil {
		return nil, v0.WrapErr(err)
	}

	return v0.makeKey(id, resp.PublicKey)
}

func (v0 *V0) GetKey(ctx context.Context, id string) (Key, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	resp, err := v0.KeyManagerPluginClient.GetPublicKey(ctx, &keymanagerv0.GetPublicKeyRequest{
		KeyId: id,
	})
	switch {
	case err != nil:
		return nil, v0.WrapErr(err)
	case resp.PublicKey == nil:
		return nil, v0.Errorf(codes.NotFound, "key %q not found", id)
	default:
		return v0.makeKey(id, resp.PublicKey)
	}
}

func (v0 *V0) GetKeys(ctx context.Context) ([]Key, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	resp, err := v0.KeyManagerPluginClient.GetPublicKeys(ctx, &keymanagerv0.GetPublicKeysRequest{})
	if err != nil {
		return nil, v0.WrapErr(err)
	}

	var keys []Key
	for _, publicKey := range resp.PublicKeys {
		key, err := v0.makeKey(publicKey.Id, publicKey)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (v0 *V0) makeKey(id string, pb *keymanagerv0.PublicKey) (Key, error) {
	switch {
	case pb == nil:
		return nil, v0.Errorf(codes.Internal, "plugin response empty for key %q", id)
	case pb.Id != id:
		return nil, v0.Errorf(codes.Internal, "plugin response has unexpected key id %q for key %q", pb.Id, id)
	case len(pb.PkixData) == 0:
		return nil, v0.Errorf(codes.Internal, "plugin response missing public key PKIX data for key %q", id)
	}

	publicKey, err := x509.ParsePKIXPublicKey(pb.PkixData)
	if err != nil {
		return nil, v0.Errorf(codes.Internal, "unable to parse public key PKIX data for key %q: %v", id, err)
	}

	return &v0Key{
		v0:        v0,
		id:        id,
		publicKey: publicKey,
	}, nil
}

func (v0 *V0) convertKeyType(t KeyType) (keymanagerv0.KeyType, error) {
	switch t {
	case KeyTypeUnset:
		return keymanagerv0.KeyType_UNSPECIFIED_KEY_TYPE, v0.Error(codes.InvalidArgument, "key type is required")
	case ECP256:
		return keymanagerv0.KeyType_EC_P256, nil
	case ECP384:
		return keymanagerv0.KeyType_EC_P384, nil
	case RSA2048:
		return keymanagerv0.KeyType_RSA_2048, nil
	case RSA4096:
		return keymanagerv0.KeyType_RSA_4096, nil
	default:
		return keymanagerv0.KeyType_UNSPECIFIED_KEY_TYPE, v0.Errorf(codes.Internal, "facade does not support key type %s", t)
	}
}

func (v0 *V0) convertHashAlgorithm(h crypto.Hash) keymanagerv0.HashAlgorithm {
	// Hash algorithm constants are aligned.
	return keymanagerv0.HashAlgorithm(h)
}

type v0Key struct {
	v0        *V0
	id        string
	publicKey crypto.PublicKey
}

func (s *v0Key) ID() string {
	return s.id
}

func (s *v0Key) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *v0Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// rand is purposefully ignored since it can't be communicated between
	// the plugin boundary. The crypto.Signer interface implies this is ok
	// when it says "possibly using entropy from rand".
	return s.signContext(context.Background(), digest, opts)
}

func (s *v0Key) signContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	req := &keymanagerv0.SignDataRequest{
		KeyId: s.id,
		Data:  digest,
	}
	switch opts := opts.(type) {
	case *rsa.PSSOptions:
		req.SignerOpts = &keymanagerv0.SignDataRequest_PssOptions{
			PssOptions: &keymanagerv0.PSSOptions{
				SaltLength:    int32(opts.SaltLength),
				HashAlgorithm: s.v0.convertHashAlgorithm(opts.Hash),
			},
		}
	case nil:
		return nil, status.Error(codes.InvalidArgument, "signer opts cannot be nil")
	default:
		req.SignerOpts = &keymanagerv0.SignDataRequest_HashAlgorithm{
			HashAlgorithm: s.v0.convertHashAlgorithm(opts.HashFunc()),
		}
	}

	resp, err := s.v0.KeyManagerPluginClient.SignData(ctx, req)
	if err != nil {
		return nil, s.v0.WrapErr(err)
	}
	if len(resp.Signature) == 0 {
		return nil, s.v0.Error(codes.Internal, "plugin returned empty signature data")
	}
	return resp.Signature, nil
}
