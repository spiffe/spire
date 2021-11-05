package gcpsecretmanager

import (
	"context"
	"crypto/sha1" //nolint: gosec // We use sha1 to hash trust domain names in 128 bytes to avoid secret label restrictions
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	svidstorev1 "github.com/spiffe/spire/proto/spire/plugin/agent/svidstore/v1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"google.golang.org/genproto/googleapis/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "gcp_secretmanager"
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
	return newPlugin(newSecretManagerClient)
}

func newPlugin(newClient func(context.Context, string) (secretManagerClient, error)) *SecretManagerPlugin {
	p := &SecretManagerPlugin{}
	p.hooks.newClient = newClient

	return p
}

type Configuration struct {
	ServiceAccountFile string   `hcl:"service_account_file" json:"service_account_file"`
	UnusedKeys         []string `hcl:",unusedKeys" json:",omitempty"`
}

type SecretManagerPlugin struct {
	svidstorev1.UnsafeSVIDStoreServer
	configv1.UnsafeConfigServer

	log    hclog.Logger
	mtx    sync.RWMutex
	client secretManagerClient
	tdHash string

	hooks struct {
		newClient func(context.Context, string) (secretManagerClient, error)
	}
}

func (p *SecretManagerPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure configures the SecretMangerPlugin.
func (p *SecretManagerPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &Configuration{}
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if len(config.UnusedKeys) != 0 {
		return nil, status.Errorf(codes.InvalidArgument, "unknown configurations detected: %s", strings.Join(config.UnusedKeys, ","))
	}

	client, err := p.hooks.newClient(ctx, config.ServiceAccountFile)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secretmanager client: %v", err)
	}

	// gcp secret manager does not allow ".", hash td as label
	tdHash := sha1.Sum([]byte(req.CoreConfiguration.TrustDomain)) //nolint: gosec // We use sha1 to hash trust domain names in 128 bytes to avoid secret label restrictions

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.client = client
	p.tdHash = hex.EncodeToString(tdHash[:])

	return &configv1.ConfigureResponse{}, nil
}

// PutX509SVID puts the specified X509-SVID in the configured Google Cloud Secrets Manager
func (p *SecretManagerPlugin) PutX509SVID(ctx context.Context, req *svidstorev1.PutX509SVIDRequest) (*svidstorev1.PutX509SVIDResponse, error) {
	opt, err := optionsFromSecretData(req.Metadata)
	if err != nil {
		return nil, err
	}

	// Get secret, if it does not exist, a secret is created
	secret, err := getSecret(ctx, p.client, opt.secretName(), p.tdHash)
	if err != nil {
		return nil, err
	}

	// Secret not found, create it
	if secret == nil {
		secret, err = p.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
			Parent:   opt.parent(),
			SecretId: opt.name,
			Secret: &secretmanagerpb.Secret{
				Replication: &secretmanagerpb.Replication{
					Replication: &secretmanagerpb.Replication_Automatic_{
						Automatic: &secretmanagerpb.Replication_Automatic{},
					},
				},
				Labels: map[string]string{
					"spire-svid": p.tdHash,
				},
			},
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create secret: %v", err)
		}
		p.log.With("secret_name", secret.Name).Debug("Secret created")

		if opt.roleName != "" && opt.serviceAccount != "" {
			// Create a policy without conditions and a single binding
			resp, err := p.client.SetIamPolicy(ctx, &iam.SetIamPolicyRequest{
				Resource: opt.secretName(),
				Policy: &iam.Policy{
					Bindings: []*iam.Binding{
						{
							Role:    opt.roleName,
							Members: []string{opt.serviceAccount},
						},
					},
				},
			})
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to set IAM policy to secret: %v", err)
			}
			p.log.With("version", resp.Version).With("etag", resp.Etag).With("secret_name", secret.Name).Debug("Secret IAM Policy updated")
		}
	}

	secretData, err := svidstore.SecretFromProto(req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse request: %v", err)
	}

	secretBinary, err := json.Marshal(secretData)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal payload: %v", err)
	}

	resp, err := p.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
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

// DeleteX509SVID deletes a secret in the configured Google Cloud Secret manager
func (p *SecretManagerPlugin) DeleteX509SVID(ctx context.Context, req *svidstorev1.DeleteX509SVIDRequest) (*svidstorev1.DeleteX509SVIDResponse, error) {
	opt, err := optionsFromSecretData(req.Metadata)
	if err != nil {
		return nil, err
	}

	secret, err := getSecret(ctx, p.client, opt.secretName(), p.tdHash)
	if err != nil {
		return nil, err
	}

	if secret == nil {
		p.log.With("secret_name", opt.secretName()).Debug("Secret to delete not found")
		return &svidstorev1.DeleteX509SVIDResponse{}, nil
	}

	if err := p.client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: secret.Name,
		Etag: secret.Etag,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete secret: %v", err)
	}

	p.log.With("secret_name", opt.secretName()).Debug("Secret deleted")
	return &svidstorev1.DeleteX509SVIDResponse{}, nil
}

// getSecret gets secret from Google Cloud and validates if it has `spire-svid` label with hashed trust domain as value,
// nil if not found
func getSecret(ctx context.Context, client secretManagerClient, secretName string, tdHash string) (*secretmanagerpb.Secret, error) {
	secret, err := client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{
		Name: secretName,
	})
	switch status.Code(err) {
	case codes.OK:
		// Verify that secret contains "spire-svid" label and it is enabled
		if ok := validateLabels(secret.Labels, tdHash); !ok {
			return nil, status.Error(codes.InvalidArgument, "secret is not managed by this SPIRE deployment")
		}
	case codes.NotFound:
		return nil, nil
	default:
		return nil, status.Errorf(codes.Internal, "failed to get secret: %v", err)
	}

	return secret, nil
}

type secretOptions struct {
	projectID      string
	name           string
	roleName       string
	serviceAccount string
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
	name, ok := data["name"]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	projectID, ok := data["projectid"]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "projectid is required")
	}

	// example: "serviceAccount:project-id@appspot.gserviceaccount.com"
	var serviceAccount string
	if sa, ok := data["serviceaccount"]; ok {
		serviceAccount = fmt.Sprintf("serviceAccount:%s", sa)
	}

	roleName := data["role"]
	switch {
	case serviceAccount != "" && roleName == "":
		return nil, status.Error(codes.InvalidArgument, "role is required when service account is set")

	case serviceAccount == "" && roleName != "":
		return nil, status.Error(codes.InvalidArgument, "service account is required when role is set")
	}

	return &secretOptions{
		name:           name,
		projectID:      projectID,
		roleName:       roleName,
		serviceAccount: serviceAccount,
	}, nil
}

func validateLabels(labels map[string]string, tdHash string) bool {
	spireLabel, ok := labels["spire-svid"]
	return ok && spireLabel == tdHash
}
