package azurekeyvault

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
)

type cloudKeyManagementService interface {
	CreateKey(ctx context.Context, name string, parameters azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error)
	DeleteKey(ctx context.Context, name string, options *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error)
	UpdateKey(ctx context.Context, name string, version string, parameters azkeys.UpdateKeyParameters, options *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error)
	GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	NewListKeysPager(options *azkeys.ListKeysOptions) *runtime.Pager[azkeys.ListKeysResponse]
	Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
}

type keyVaultClient struct {
	client *azkeys.Client
}

func (c *keyVaultClient) CreateKey(ctx context.Context, name string, parameters azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
	return c.client.CreateKey(ctx, name, parameters, options)
}

func (c *keyVaultClient) DeleteKey(ctx context.Context, name string, options *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error) {
	return c.client.DeleteKey(ctx, name, options)
}

func (c *keyVaultClient) UpdateKey(ctx context.Context, name string, version string, parameters azkeys.UpdateKeyParameters, options *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error) {
	return c.client.UpdateKey(ctx, name, version, parameters, options)
}

func (c *keyVaultClient) GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	return c.client.GetKey(ctx, name, version, options)
}

func (c *keyVaultClient) NewListKeysPager(options *azkeys.ListKeysOptions) *runtime.Pager[azkeys.ListKeysResponse] {
	return c.client.NewListKeysPager(options)
}

func (c *keyVaultClient) Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
	return c.client.Sign(ctx, name, version, parameters, options)
}

func newKeyVaultClient(creds azcore.TokenCredential, keyVaultURI string) (cloudKeyManagementService, error) {
	client, err := azkeys.NewClient(keyVaultURI, creds, nil)
	if err != nil {
		return nil, err
	}

	return &keyVaultClient{
		client: client,
	}, nil
}
