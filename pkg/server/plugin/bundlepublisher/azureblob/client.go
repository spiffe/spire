package azureblob

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

type blobStorage interface {
	UploadBuffer(ctx context.Context, containerName string, blobName string, buffer []byte, o *azblob.UploadBufferOptions) (azblob.UploadBufferResponse, error)
}

type blobClient struct {
	client *azblob.Client
}

func (c *blobClient) UploadBuffer(ctx context.Context, containerName string, blobName string, buffer []byte, o *azblob.UploadBufferOptions) (azblob.UploadBufferResponse, error) {
	return c.client.UploadBuffer(ctx, containerName, blobName, buffer, o)
}

func newAzureBlobClient(cred azcore.TokenCredential, accountURL string) (blobStorage, error) {
	client, err := azblob.NewClient(accountURL, cred, nil)
	if err != nil {
		return nil, err
	}

	return &blobClient{
		client: client,
	}, nil
}

func newAzureBlobClientWithSharedKey(accountURL string, cred *azblob.SharedKeyCredential) (blobStorage, error) {
	client, err := azblob.NewClientWithSharedKeyCredential(accountURL, cred, nil)
	if err != nil {
		return nil, err
	}

	return &blobClient{
		client: client,
	}, nil
}
