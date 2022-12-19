package gcpkms

import (
	"context"

	"cloud.google.com/go/iam"
	"cloud.google.com/go/iam/apiv1/iampb"
	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

type cloudKeyManagementService interface {
	AsymmetricSign(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	Close() error
	CreateCryptoKey(context.Context, *kmspb.CreateCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
	CreateCryptoKeyVersion(context.Context, *kmspb.CreateCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	DestroyCryptoKeyVersion(context.Context, *kmspb.DestroyCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	GetCryptoKeyVersion(context.Context, *kmspb.GetCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	GetPublicKey(context.Context, *kmspb.GetPublicKeyRequest, ...gax.CallOption) (*kmspb.PublicKey, error)
	GetTokeninfo() (*oauth2.Tokeninfo, error)
	ListCryptoKeys(context.Context, *kmspb.ListCryptoKeysRequest, ...gax.CallOption) cryptoKeyIterator
	ListCryptoKeyVersions(context.Context, *kmspb.ListCryptoKeyVersionsRequest, ...gax.CallOption) cryptoKeyVersionIterator
	ResourceIAM(string) iamHandler
	UpdateCryptoKey(context.Context, *kmspb.UpdateCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
}

type kmsClient struct {
	client        *kms.KeyManagementClient
	oauth2Service *oauth2.Service
}

func (c *kmsClient) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	return c.client.AsymmetricSign(ctx, req, opts...)
}

func (c *kmsClient) Close() error {
	return c.client.Close()
}

func (c *kmsClient) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...gax.CallOption) (*kmspb.CryptoKey, error) {
	return c.client.CreateCryptoKey(ctx, req, opts...)
}

func (c *kmsClient) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	return c.client.CreateCryptoKeyVersion(ctx, req, opts...)
}

func (c *kmsClient) DestroyCryptoKeyVersion(ctx context.Context, req *kmspb.DestroyCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	return c.client.DestroyCryptoKeyVersion(ctx, req, opts...)
}

func (c *kmsClient) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	return c.client.GetCryptoKeyVersion(ctx, req, opts...)
}

func (c *kmsClient) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	return c.client.GetPublicKey(ctx, req, opts...)
}

func (c *kmsClient) GetTokeninfo() (*oauth2.Tokeninfo, error) {
	return c.oauth2Service.Tokeninfo().Do()
}

func (c *kmsClient) ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest, opts ...gax.CallOption) cryptoKeyIterator {
	return c.client.ListCryptoKeys(ctx, req, opts...)
}

func (c *kmsClient) ListCryptoKeyVersions(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest, opts ...gax.CallOption) cryptoKeyVersionIterator {
	return c.client.ListCryptoKeyVersions(ctx, req, opts...)
}

func (c *kmsClient) ResourceIAM(resourcePath string) iamHandler {
	return &iamHandle{
		h: c.client.ResourceIAM(resourcePath),
	}
}

func (c *kmsClient) SetIamPolicy(ctx context.Context, req *iampb.SetIamPolicyRequest, opts ...gax.CallOption) (*iampb.Policy, error) {
	return c.client.SetIamPolicy(ctx, req, opts...)
}

func (c *kmsClient) UpdateCryptoKey(ctx context.Context, req *kmspb.UpdateCryptoKeyRequest, opts ...gax.CallOption) (*kmspb.CryptoKey, error) {
	return c.client.UpdateCryptoKey(ctx, req, opts...)
}

type cryptoKeyIterator interface {
	Next() (*kmspb.CryptoKey, error)
}

type cryptoKeyVersionIterator interface {
	Next() (*kmspb.CryptoKeyVersion, error)
}

type iamHandler interface {
	V3() iamHandler3
}

type iamHandler3 interface {
	Policy(context.Context) (*iam.Policy3, error)
	SetPolicy(context.Context, *iam.Policy3) error
}

type iamHandle struct {
	h *iam.Handle
}

func (i *iamHandle) V3() iamHandler3 {
	return i.h.V3()
}

func newKMSClient(ctx context.Context, opts ...option.ClientOption) (cloudKeyManagementService, error) {
	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, err
	}

	oauth2Service, err := oauth2.NewService(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return &kmsClient{
		client:        client,
		oauth2Service: oauth2Service,
	}, nil
}
