package gcloudsecretsmanager

import (
	"context"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

type secretsClient interface {
	AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
	Close() error
	CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error)
	DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...gax.CallOption) error
	GetSecret(ctx context.Context, req *secretmanagerpb.GetSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error)
}

func newClient(ctx context.Context, serviceAccountFile string) (secretsClient, error) {
	var opts []option.ClientOption
	if serviceAccountFile != "" {
		opts = append(opts, option.WithCredentialsFile(serviceAccountFile))
	}

	return secretmanager.NewClient(ctx, opts...)
}
