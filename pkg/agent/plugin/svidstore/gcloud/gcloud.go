package gcloud

import (
	"context"
	"fmt"
	"sync"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/api/option"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "gcloud_secretsmanager"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *SecretsManagerPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, svidstore.PluginServer(p))
}

func New() *SecretsManagerPlugin {
	return newPlugin(newClient)
}

func newPlugin(newClient func(context.Context, string) (secretsClient, error)) *SecretsManagerPlugin {
	p := &SecretsManagerPlugin{}
	p.hooks.newClient = newClient

	return p
}

type Config struct {
	ServiceAccountFile string `hcl:"service_account_file"`
}

type secretsClient interface {
	AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
	CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error)
	GetSecret(ctx context.Context, req *secretmanagerpb.GetSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error)
}

type SecretsManagerPlugin struct {
	svidstore.UnsafeSVIDStoreServer

	log    hclog.Logger
	config *Config
	mtx    sync.RWMutex

	hooks struct {
		newClient func(context.Context, string) (secretsClient, error)
	}
}

func (p *SecretsManagerPlugin) SetLogger(log hclog.Logger) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.log = log
}

// Configure configures the SecretsMangerPlugin.
func (p *SecretsManagerPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &Config{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config

	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and other metadata of the plugin.
func (*SecretsManagerPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// PutX509SVID puts the specified X509-SVID in the configured Google Cloud Secrets Manager
func (p *SecretsManagerPlugin) PutX509SVID(ctx context.Context, req *svidstore.PutX509SVIDRequest) (*svidstore.PutX509SVIDResponse, error) {
	// Create client
	client, err := p.hooks.newClient(ctx, p.config.ServiceAccountFile)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secretmanager client: %v", err)
	}

	data := svidstore.ParseSelectors(pluginName, req.Selectors)

	// Getting secret name and project, both are required.
	name, ok := data["secretname"]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "selector 'secretname' is required")
	}

	// Secret not found, create it
	parent, ok := data["secretproject"]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "selector 'secretproject' is required")
	}

	// Get secret, if it does not exists a secret is created
	secret, err := client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s", parent, name),
	})
	switch status.Code(err) {
	case codes.OK:
		// Verify that secret contains "spire-svid" label and it is enabled
		if ok := validateLabels(secret.Labels); !ok {
			return nil, status.Error(codes.InvalidArgument, "secret that not contains 'spire-svid' label")
		}
	case codes.NotFound:
		secret, err = client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
			Parent:   fmt.Sprintf("projects/%s", parent),
			SecretId: name,
			Secret: &secretmanagerpb.Secret{
				// TODO: what replication type must we use here?
				Replication: &secretmanagerpb.Replication{
					Replication: &secretmanagerpb.Replication_Automatic_{
						Automatic: &secretmanagerpb.Replication_Automatic{},
					},
				},
				Labels: map[string]string{
					"spire-svid": "true",
				},
			},
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create secret: %v", err)
		}
		p.log.With("name", secret.Name).Debug("Secret created")
	default:
		return nil, status.Errorf(codes.Internal, "failed to get secret: %v", err)
	}

	secretBinary, err := svidstore.EncodeSecret(req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to encode secret: %v", err)
	}

	resp, err := client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: secret.Name,
		Payload: &secretmanagerpb.SecretPayload{
			Data: secretBinary,
		},
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to add secret version: %v", err)
	}

	p.log.With("state", resp.State).With("name", resp.Name).Debug("Secret payload updated")

	return &svidstore.PutX509SVIDResponse{}, nil
}

func newClient(ctx context.Context, serviceAccountFile string) (secretsClient, error) {
	var opts []option.ClientOption
	if serviceAccountFile != "" {
		opts = append(opts, option.WithCredentialsFile(serviceAccountFile))
	}

	return secretmanager.NewClient(ctx, opts...)
}

func validateLabels(labels map[string]string) bool {
	spireLabel, ok := labels["spire-svid"]
	return ok && spireLabel == "true"
}
