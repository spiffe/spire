package gcpkms

import (
	"context"

	"cloud.google.com/go/iam"
	kms "cloud.google.com/go/kms/apiv1"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	iampb "google.golang.org/genproto/googleapis/iam/v1"
)

type kmsClient interface {
	AsymmetricSign(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	Close() error
	CreateCryptoKey(context.Context, *kmspb.CreateCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
	CreateCryptoKeyVersion(context.Context, *kmspb.CreateCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	DestroyCryptoKeyVersion(context.Context, *kmspb.DestroyCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	GetCryptoKeyVersion(context.Context, *kmspb.GetCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	GetPublicKey(context.Context, *kmspb.GetPublicKeyRequest, ...gax.CallOption) (*kmspb.PublicKey, error)
	ResourceIAM(string) *iam.Handle
	SetIamPolicy(ctx context.Context, req *iampb.SetIamPolicyRequest, opts ...gax.CallOption) (*iampb.Policy, error)
	UpdateCryptoKey(context.Context, *kmspb.UpdateCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
}

type cryptoKeyIterator interface {
	Next() (*kmspb.CryptoKey, error)
}

type cryptoKeyVersionIterator interface {
	Next() (*kmspb.CryptoKeyVersion, error)
}

func newKMSClient(ctx context.Context, opts ...option.ClientOption) (kmsClient, error) {
	return kms.NewKeyManagementClient(ctx, opts...)
}

func listCryptoKeys(ctx context.Context, kmsClient kmsClient, req *kmspb.ListCryptoKeysRequest, opts ...gax.CallOption) cryptoKeyIterator {
	kmc := kmsClient.(*kms.KeyManagementClient)
	return kmc.ListCryptoKeys(ctx, req, opts...)
}

func listCryptoKeyVersions(ctx context.Context, kmsClient kmsClient, req *kmspb.ListCryptoKeyVersionsRequest, opts ...gax.CallOption) cryptoKeyVersionIterator {
	kmc := kmsClient.(*kms.KeyManagementClient)
	return kmc.ListCryptoKeyVersions(ctx, req, opts...)
}

type oauth2Service interface {
	Tokeninfo() *oauth2.TokeninfoCall
}

func newOauth2Service(ctx context.Context, opts ...option.ClientOption) (oauth2Service, error) {
	return oauth2.NewService(ctx)
}
