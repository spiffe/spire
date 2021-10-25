package gcloudsecretmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	svidstorev1 "github.com/spiffe/spire/proto/spire/plugin/agent/svidstore/v1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "gcloud_secretmanager"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *SecretManagerPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		svidstorev1.SVIDStorePluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

func New() *SecretManagerPlugin {
	return newPlugin(newClient)
}

func newPlugin(newClient func(context.Context, string) (secretsClient, error)) *SecretManagerPlugin {
	p := &SecretManagerPlugin{}
	p.hooks.newClient = newClient

	return p
}

type Configuration struct {
	ServiceAccountFile string `hcl:"service_account_file" json:"service_account_file"`
}

type SecretManagerPlugin struct {
	svidstorev1.UnsafeSVIDStoreServer
	configv1.UnsafeConfigServer

	log    hclog.Logger
	config *Configuration
	mtx    sync.RWMutex

	hooks struct {
		newClient func(context.Context, string) (secretsClient, error)
	}
}

func (p *SecretManagerPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure configures the SecretsMangerPlugin.
func (p *SecretManagerPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &Configuration{}
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config

	return &configv1.ConfigureResponse{}, nil
}

// PutX509SVID puts the specified X509-SVID in the configured Google Cloud Secrets Manager
func (p *SecretManagerPlugin) PutX509SVID(ctx context.Context, req *svidstorev1.PutX509SVIDRequest) (*svidstorev1.PutX509SVIDResponse, error) {
	opt, err := optionsFromSecretData(req.Metadata)
	if err != nil {
		return nil, err
	}

	// Create client
	client, err := p.hooks.newClient(ctx, p.config.ServiceAccountFile)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secretmanager client: %v", err)
	}
	defer client.Close()

	// Get secret, if it does not exist, a secret is created
	secret, err := getSecret(ctx, client, opt.secretName())
	if err != nil {
		return nil, err
	}

	// Secret not found, create it
	if secret == nil {
		secret, err = client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
			Parent:   opt.parent(),
			SecretId: opt.name,
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
		p.log.With("secret_name", secret.Name).Debug("Secret created")
	}

	secretData, err := svidstore.SecretFromProto(req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse request: %v", err)
	}

	secretBinary, err := json.Marshal(secretData)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse payload: %v", err)
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

	return &svidstorev1.PutX509SVIDResponse{}, nil
}

// DeleteX509SVID deletes a Secret in the configured Google Cloud Secrets manager
func (p *SecretManagerPlugin) DeleteX509SVID(ctx context.Context, req *svidstorev1.DeleteX509SVIDRequest) (*svidstorev1.DeleteX509SVIDResponse, error) {
	opt, err := optionsFromSecretData(req.Metadata)
	if err != nil {
		return nil, err
	}

	client, err := p.hooks.newClient(ctx, p.config.ServiceAccountFile)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secretmanager client: %v", err)
	}
	defer client.Close()

	secret, err := getSecret(ctx, client, opt.secretName())
	if err != nil {
		return nil, err
	}

	if secret == nil {
		p.log.With("secret_name", opt.secretName()).Warn("Secret to delete not found")
		return &svidstorev1.DeleteX509SVIDResponse{}, nil
	}

	if err := client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: secret.Name,
		Etag: secret.Etag,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete secret: %v", err)
	}

	p.log.With("secret_name", opt.secretName()).Debug("Secret deleted")
	return &svidstorev1.DeleteX509SVIDResponse{}, nil
}

// getSecret gets secret from GCloud and validtes if it has `spire-svid` label, nil if not found
func getSecret(ctx context.Context, client secretsClient, secretName string) (*secretmanagerpb.Secret, error) {
	secret, err := client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{
		Name: secretName,
	})
	switch status.Code(err) {
	case codes.OK:
		// Verify that secret contains "spire-svid" label and it is enabled
		if ok := validateLabels(secret.Labels); !ok {
			return nil, status.Error(codes.InvalidArgument, "secret does not contain the 'spire-svid' label")
		}
	case codes.NotFound:
		return nil, nil
	default:
		return nil, status.Errorf(codes.Internal, "failed to get secret: %v", err)
	}

	return secret, nil
}

type secretOptions struct {
	projectID string
	name      string
}

// parent gets parent in the format `projects/*`
func (s *secretOptions) parent() string {
	return fmt.Sprintf("projects/%s", s.projectID)
}

// secretName gets secret name in format `projects/*/secrets/*`
func (s *secretOptions) secretName() string {
	return fmt.Sprintf("projects/%s/secrets/%s", s.projectID, s.name)
}

func optionsFromSecretData(selectorData []string) (*secretOptions, error) {
	data, err := svidstore.ParseMetadata(selectorData)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid metadata: %v", err)
	}

	// Getting secret name and project, both are required.
	name, ok := data["secretname"]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "secretname is required")
	}

	projectID, ok := data["secretproject"]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "secretproject is required")
	}

	return &secretOptions{
		name:      name,
		projectID: projectID,
	}, nil
}

func validateLabels(labels map[string]string) bool {
	spireLabel, ok := labels["spire-svid"]
	return ok && spireLabel == "true"
}
