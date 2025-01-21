package gcpsecretmanager

import (
	"context"
	"crypto/sha1" //nolint: gosec // We use sha1 to hash trust domain names in 128 bytes to avoid secret label restrictions
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/token"
	svidstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/svidstore/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
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

func newPlugin(newSecretManagerClient func(context.Context, string) (secretManagerClient, error)) *SecretManagerPlugin {
	p := &SecretManagerPlugin{}
	p.hooks.newSecretManagerClient = newSecretManagerClient

	return p
}

type Configuration struct {
	ServiceAccountFile string                 `hcl:"service_account_file" json:"service_account_file"`
	UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions" json:",omitempty"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Configuration {
	newConfig := &Configuration{}
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if len(newConfig.UnusedKeyPositions) != 0 {
		var keys []string
		for k := range newConfig.UnusedKeyPositions {
			keys = append(keys, k)
		}

		sort.Strings(keys)
		status.ReportErrorf("unknown configurations detected: %s", strings.Join(keys, ","))
	}

	return newConfig
}

type SecretManagerPlugin struct {
	svidstorev1.UnsafeSVIDStoreServer
	configv1.UnsafeConfigServer

	log                 hclog.Logger
	mtx                 sync.RWMutex
	secretManagerClient secretManagerClient
	tdHash              string

	hooks struct {
		newSecretManagerClient func(context.Context, string) (secretManagerClient, error)
	}
}

func (p *SecretManagerPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure configures the SecretManagerPlugin.
func (p *SecretManagerPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	secretMangerClient, err := p.hooks.newSecretManagerClient(ctx, newConfig.ServiceAccountFile)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secretmanager client: %v", err)
	}

	// gcp secret manager does not allow ".", hash td as label
	tdHash := sha1.Sum([]byte(req.CoreConfiguration.TrustDomain)) //nolint: gosec // We use sha1 to hash trust domain names in 128 bytes to avoid secret label restrictions

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.secretManagerClient = secretMangerClient
	p.tdHash = hex.EncodeToString(tdHash[:])

	return &configv1.ConfigureResponse{}, nil
}

func (p *SecretManagerPlugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

// PutX509SVID puts the specified X509-SVID in the configured Google Cloud Secrets Manager
func (p *SecretManagerPlugin) PutX509SVID(ctx context.Context, req *svidstorev1.PutX509SVIDRequest) (*svidstorev1.PutX509SVIDResponse, error) {
	opt, err := optionsFromSecretData(req.Metadata)
	if err != nil {
		return nil, err
	}

	// Get secret, if it does not exist, a secret is created
	secret, secretFound, err := getSecret(ctx, p.secretManagerClient, opt.secretName(), p.tdHash)
	if err != nil {
		return nil, err
	}

	// Secret not found, create it
	if !secretFound {
		secret, err = p.secretManagerClient.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
			Parent:   opt.parent(),
			SecretId: opt.name,
			Secret: &secretmanagerpb.Secret{
				Replication: opt.replication,
				Labels: map[string]string{
					"spire-svid": p.tdHash,
				},
			},
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create secret: %v", err)
		}
		p.log.With("secret_name", secret.Name).Debug("Secret created")
	}

	if opt.roleName != "" && opt.serviceAccount != "" {
		ok, err := p.shouldSetPolicy(ctx, secret.Name, opt, secretFound)
		if err != nil {
			return nil, err
		}

		if ok {
			if err := p.setIamPolicy(ctx, secret.Name, opt); err != nil {
				return nil, err
			}
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

	resp, err := p.secretManagerClient.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
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

	secret, ok, err := getSecret(ctx, p.secretManagerClient, opt.secretName(), p.tdHash)
	if err != nil {
		return nil, err
	}

	if !ok {
		p.log.With("secret_name", opt.secretName()).Debug("Secret to delete not found")
		return &svidstorev1.DeleteX509SVIDResponse{}, nil
	}

	if err := p.secretManagerClient.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
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
func getSecret(ctx context.Context, client secretManagerClient, secretName string, tdHash string) (*secretmanagerpb.Secret, bool, error) {
	secret, err := client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{
		Name: secretName,
	})
	switch status.Code(err) {
	case codes.OK:
		// Verify that secret contains "spire-svid" label and it is enabled
		if ok := validateLabels(secret.Labels, tdHash); !ok {
			return nil, false, status.Error(codes.InvalidArgument, "secret is not managed by this SPIRE deployment")
		}
	case codes.NotFound:
		return nil, false, nil
	default:
		return nil, false, status.Errorf(codes.Internal, "failed to get secret: %v", err)
	}

	return secret, true, nil
}

func (p *SecretManagerPlugin) shouldSetPolicy(ctx context.Context, secretName string, opt *secretOptions, secretFound bool) (bool, error) {
	if !secretFound {
		return true, nil
	}
	policy, err := p.secretManagerClient.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: secretName,
	})
	if err != nil {
		return false, status.Errorf(codes.Internal, "failed to get IAM policy: %v", err)
	}

	bindings := policy.Bindings
	if len(bindings) != 1 {
		return true, nil
	}

	binding := bindings[0]
	switch {
	case binding.Role != opt.roleName:
		return true, nil
	// Expecting a single Service account as member
	case !expectedBindingMembers(binding.Members, opt.serviceAccount):
		return true, nil
	default:
		return false, nil
	}
}

func (p *SecretManagerPlugin) setIamPolicy(ctx context.Context, secretName string, opt *secretOptions) error {
	// Create a policy without conditions and a single binding
	resp, err := p.secretManagerClient.SetIamPolicy(ctx, &iampb.SetIamPolicyRequest{
		Resource: opt.secretName(),
		Policy: &iampb.Policy{
			Bindings: []*iampb.Binding{
				{
					Role:    opt.roleName,
					Members: []string{opt.serviceAccount},
				},
			},
		},
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed to set IAM policy to secret: %v", err)
	}
	p.log.With("version", resp.Version).With("etag", string(resp.Etag)).With("secret_name", secretName).Debug("Secret IAM Policy updated")

	return nil
}

type secretOptions struct {
	projectID      string
	name           string
	roleName       string
	serviceAccount string
	replication    *secretmanagerpb.Replication
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

	regions, ok := data["regions"]

	var replica *secretmanagerpb.Replication

	if !ok {
		replica = &secretmanagerpb.Replication{
			Replication: &secretmanagerpb.Replication_Automatic_{
				Automatic: &secretmanagerpb.Replication_Automatic{},
			},
		}
	} else {
		regionsSlice := strings.Split(regions, ",")

		var replicas []*secretmanagerpb.Replication_UserManaged_Replica

		for _, region := range regionsSlice {
			// Avoid adding empty strings as region
			if region == "" {
				continue
			}
			replica := &secretmanagerpb.Replication_UserManaged_Replica{
				Location: region,
			}

			replicas = append(replicas, replica)
		}

		if len(replicas) == 0 {
			return nil, status.Error(codes.InvalidArgument, "need to specify at least one region")
		}

		replica = &secretmanagerpb.Replication{
			Replication: &secretmanagerpb.Replication_UserManaged_{
				UserManaged: &secretmanagerpb.Replication_UserManaged{
					Replicas: replicas,
				},
			},
		}
	}

	return &secretOptions{
		name:           name,
		projectID:      projectID,
		roleName:       roleName,
		serviceAccount: serviceAccount,
		replication:    replica,
	}, nil
}

func validateLabels(labels map[string]string, tdHash string) bool {
	spireLabel, ok := labels["spire-svid"]
	return ok && spireLabel == tdHash
}

// expectedBindingMembers ensures that there is exactly one binding member, and
// that it matches the provided service account name
func expectedBindingMembers(bindingMembers []string, serviceAccount string) bool {
	return len(bindingMembers) == 1 && bindingMembers[0] == serviceAccount
}
