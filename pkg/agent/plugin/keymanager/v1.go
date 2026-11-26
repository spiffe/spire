package keymanager

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"io"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type V1 struct {
	plugin.Facade

	keymanagerv1.KeyManagerPluginClient
}

func (v1 V1) GenerateKey(ctx context.Context, id string, keyType KeyType) (Key, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	kt, err := v1.convertKeyType(keyType)
	if err != nil {
		return nil, err
	}

	resp, err := v1.KeyManagerPluginClient.GenerateKey(ctx, &keymanagerv1.GenerateKeyRequest{
		KeyId:   id,
		KeyType: kt,
	})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	return v1.makeKey(id, resp.PublicKey)
}

func (v1 V1) GetKey(ctx context.Context, id string) (Key, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	resp, err := v1.KeyManagerPluginClient.GetPublicKey(ctx, &keymanagerv1.GetPublicKeyRequest{
		KeyId: id,
	})
	switch {
	case err != nil:
		return nil, v1.WrapErr(err)
	case resp.PublicKey == nil:
		return nil, v1.Errorf(codes.NotFound, "key %q not found", id)
	default:
		return v1.makeKey(id, resp.PublicKey)
	}
}

func (v1 V1) GetKeys(ctx context.Context) ([]Key, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	resp, err := v1.KeyManagerPluginClient.GetPublicKeys(ctx, &keymanagerv1.GetPublicKeysRequest{})
	if err != nil {
		return nil, v1.WrapErr(err)
	}

	var keys []Key
	for _, publicKey := range resp.PublicKeys {
		key, err := v1.makeKey(publicKey.Id, publicKey)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (v1 V1) makeKey(id string, pb *keymanagerv1.PublicKey) (Key, error) {
	switch {
	case pb == nil:
		return nil, v1.Errorf(codes.Internal, "plugin response empty for key %q", id)
	case pb.Id != id:
		return nil, v1.Errorf(codes.Internal, "plugin response has unexpected key id %q for key %q", pb.Id, id)
	case len(pb.PkixData) == 0:
		return nil, v1.Errorf(codes.Internal, "plugin response missing public key PKIX data for key %q", id)
	}

	publicKey, err := x509.ParsePKIXPublicKey(pb.PkixData)
	if err != nil {
		return nil, v1.Errorf(codes.Internal, "unable to parse public key PKIX data for key %q: %v", id, err)
	}

	return &v1Key{
		v1:          v1,
		id:          id,
		fingerprint: pb.Fingerprint,
		publicKey:   publicKey,
	}, nil
}

func (v1 *V1) convertKeyType(t KeyType) (keymanagerv1.KeyType, error) {
	switch t {
	case KeyTypeUnset:
		return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, v1.Error(codes.InvalidArgument, "key type is required")
	case ECP256:
		return keymanagerv1.KeyType_EC_P256, nil
	case ECP384:
		return keymanagerv1.KeyType_EC_P384, nil
	case RSA2048:
		return keymanagerv1.KeyType_RSA_2048, nil
	case RSA4096:
		return keymanagerv1.KeyType_RSA_4096, nil
	case MLDSA44:
		return keymanagerv1.KeyType_ML_DSA_44, nil
	case MLDSA65:
		return keymanagerv1.KeyType_ML_DSA_65, nil
	case MLDSA87:
		return keymanagerv1.KeyType_ML_DSA_87, nil
	default:
		return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, v1.Errorf(codes.Internal, "facade does not support key type %q", t)
	}
}

func (v1 *V1) convertHashAlgorithm(h crypto.Hash) keymanagerv1.HashAlgorithm {
	// Hash algorithm constants are aligned.
	return util.MustCast[keymanagerv1.HashAlgorithm](h)
}

type v1Key struct {
	v1          V1
	id          string
	fingerprint string
	publicKey   crypto.PublicKey
}

func (s *v1Key) ID() string {
	return s.id
}

func (s *v1Key) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *v1Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// rand is purposefully ignored since it can't be communicated between
	// the plugin boundary. The crypto.Signer interface implies this is ok
	// when it says "possibly using entropy from rand".
	return s.signContext(context.Background(), digest, opts)
}

func (s *v1Key) signContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	if _, ok := s.publicKey.(*mldsa.PublicKey); ok {
		if _, isPSS := opts.(*rsa.PSSOptions); isPSS || (opts != nil && opts.HashFunc() != crypto.Hash(0)) {
			return nil, status.Error(codes.InvalidArgument, "ML-DSA keys sign the full message; hash algorithm must not be set")
		}
	}

	req := &keymanagerv1.SignDataRequest{
		KeyId: s.id,
		Data:  digest,
	}
	switch opts := opts.(type) {
	case *rsa.PSSOptions:
		req.SignerOpts = &keymanagerv1.SignDataRequest_PssOptions{
			PssOptions: &keymanagerv1.SignDataRequest_PSSOptions{
				SaltLength:    util.MustCast[int32](opts.SaltLength),
				HashAlgorithm: s.v1.convertHashAlgorithm(opts.Hash),
			},
		}
	case *mldsa.Options:
		// Context can't be sent to plugins. A nil *mldsa.Options means no context.
		if opts != nil && opts.Context != "" {
			return nil, status.Error(codes.InvalidArgument, "ML-DSA context is not supported")
		}
		req.SignerOpts = &keymanagerv1.SignDataRequest_HashAlgorithm{}
	case nil:
		return nil, status.Error(codes.InvalidArgument, "signer opts cannot be nil")
	default:
		req.SignerOpts = &keymanagerv1.SignDataRequest_HashAlgorithm{
			HashAlgorithm: s.v1.convertHashAlgorithm(opts.HashFunc()),
		}
	}

	resp, err := s.v1.KeyManagerPluginClient.SignData(ctx, req)
	if err != nil {
		return nil, s.v1.WrapErr(err)
	}
	if len(resp.Signature) == 0 {
		return nil, s.v1.Error(codes.Internal, "plugin returned empty signature data")
	}
	if resp.KeyFingerprint != s.fingerprint {
		return nil, s.v1.Errorf(codes.Internal, "fingerprint %q on key %q does not match %q", s.fingerprint, s.id, resp.KeyFingerprint)
	}
	return resp.Signature, nil
}
