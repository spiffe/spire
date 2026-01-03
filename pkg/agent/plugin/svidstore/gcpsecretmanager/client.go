package gcpsecretmanager

import (
	"context"

	"cloud.google.com/go/iam/apiv1/iampb"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
)

type secretManagerClient interface {
	AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
	Close() error
	CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error)
	DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...gax.CallOption) error
	GetSecret(ctx context.Context, req *secretmanagerpb.GetSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error)
	SetIamPolicy(ctx context.Context, req *iampb.SetIamPolicyRequest, opts ...gax.CallOption) (*iampb.Policy, error)
	GetIamPolicy(ctx context.Context, req *iampb.GetIamPolicyRequest, opts ...gax.CallOption) (*iampb.Policy, error)
}

func newSecretManagerClient(ctx context.Context, serviceAccountFile string) (secretManagerClient, error) {
	var opts []option.ClientOption
	if serviceAccountFile != "" {
		opts = append(opts, option.WithAuthCredentialsFile(option.ServiceAccount, serviceAccountFile))
	}

	return secretmanager.NewClient(ctx, opts...)
}
