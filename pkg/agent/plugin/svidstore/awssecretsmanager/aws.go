package awssecretsmanager

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	svidstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/svidstore/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "aws_secretsmanager"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *SecretsManagerPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		svidstorev1.SVIDStorePluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

func New() *SecretsManagerPlugin {
	return newPlugin(createSecretManagerClient)
}

func newPlugin(newClient func(ctx context.Context, secretAccessKey, accessKeyID, region string) (SecretsManagerClient, error)) *SecretsManagerPlugin {
	p := &SecretsManagerPlugin{}
	p.hooks.newClient = newClient
	p.hooks.getenv = os.Getenv

	return p
}

type Configuration struct {
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	Region          string `hcl:"region" json:"region"`
}

func (p *SecretsManagerPlugin) buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Configuration {
	newConfig := &Configuration{}
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if newConfig.AccessKeyID == "" {
		newConfig.AccessKeyID = p.hooks.getenv("AWS_ACCESS_KEY_ID")
	}

	if newConfig.SecretAccessKey == "" {
		newConfig.SecretAccessKey = p.hooks.getenv("AWS_SECRET_ACCESS_KEY")
	}

	if newConfig.Region == "" {
		status.ReportError("region is required")
	}

	return newConfig
}

type SecretsManagerPlugin struct {
	svidstorev1.UnsafeSVIDStoreServer
	configv1.UnsafeConfigServer

	log      hclog.Logger
	smClient SecretsManagerClient
	mtx      sync.RWMutex

	hooks struct {
		newClient func(ctx context.Context, secretAccessKey, accessKeyID, region string) (SecretsManagerClient, error)
		getenv    func(string) string
	}
}

func (p *SecretsManagerPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure configures the SecretsManagerPlugin.
func (p *SecretsManagerPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, p.buildConfig)
	if err != nil {
		return nil, err
	}

	smClient, err := p.hooks.newClient(ctx, newConfig.SecretAccessKey, newConfig.AccessKeyID, newConfig.Region)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secrets manager client: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.smClient = smClient

	return &configv1.ConfigureResponse{}, nil
}

func (p *SecretsManagerPlugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, p.buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

// PutX509SVID puts the specified X509-SVID in the configured AWS Secrets Manager
func (p *SecretsManagerPlugin) PutX509SVID(ctx context.Context, req *svidstorev1.PutX509SVIDRequest) (*svidstorev1.PutX509SVIDResponse, error) {
	opt, err := optionsFromSecretData(req.Metadata)
	if err != nil {
		return nil, err
	}

	secretID := opt.getSecretID()

	// Encode the secret from PutX509SVIDRequest
	secret, err := svidstore.SecretFromProto(req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse request: %v", err)
	}

	secretBinary, err := json.Marshal(secret)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse payload: %v", err)
	}

	// Call DescribeSecret to retrieve the details of the secret
	// and be able to determine if the secret exists
	secretDesc, err := p.smClient.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		var resourceNorFoundErr *types.ResourceNotFoundException
		if errors.As(err, &resourceNorFoundErr) {
			// Secret not found, creating one with provided `name`
			resp, err := createSecret(ctx, p.smClient, secretBinary, opt)
			if err != nil {
				return nil, err
			}
			p.log.With("version_id", aws.ToString(resp.VersionId)).With("arn", aws.ToString(resp.ARN)).With("name", aws.ToString(resp.Name)).Debug("Secret created")

			return &svidstorev1.PutX509SVIDResponse{}, nil
		}

		// Purely defensive. This should never happen.
		return nil, status.Errorf(codes.Internal, "failed to describe secret: %v", err)
	}

	// Validate that the secret has the 'spire-svid' tag. This tag is used to distinguish the secrets
	// that have SVID information handled by SPIRE
	if err := validateTag(secretDesc.Tags); err != nil {
		return nil, err
	}

	// If the secret has been scheduled for deletion, restore it
	if secretDesc.DeletedDate != nil {
		resp, err := p.smClient.RestoreSecret(ctx, &secretsmanager.RestoreSecretInput{
			SecretId: aws.String(secretID),
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to restore secret %q: %v", secretID, err)
		}
		p.log.With("arn", aws.ToString(resp.ARN)).With("name", aws.ToString(resp.Name)).Debug("Secret was scheduled for deletion and has been restored")
	}

	putResp, err := p.smClient.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     secretDesc.ARN,
		SecretBinary: secretBinary,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to put secret value: %v", err)
	}

	p.log.With("version_id", aws.ToString(putResp.VersionId)).With("arn", aws.ToString(putResp.ARN)).With("name", aws.ToString(putResp.Name)).Debug("Secret value updated")
	return &svidstorev1.PutX509SVIDResponse{}, nil
}

// DeleteX509SVID schedules a deletion to a Secret using AWS secret manager
func (p *SecretsManagerPlugin) DeleteX509SVID(ctx context.Context, req *svidstorev1.DeleteX509SVIDRequest) (*svidstorev1.DeleteX509SVIDResponse, error) {
	opt, err := optionsFromSecretData(req.Metadata)
	if err != nil {
		return nil, err
	}

	secretID := opt.getSecretID()

	// Call DescribeSecret to retrieve the details of the secret
	// and be able to determine if the secret exists
	secretDesc, err := p.smClient.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		var resourceNotFoundErr *types.ResourceNotFoundException
		if errors.As(err, &resourceNotFoundErr) {
			p.log.With("secret_id", secretID).Warn("Secret not found")
			return &svidstorev1.DeleteX509SVIDResponse{}, nil
		}
		return nil, status.Errorf(codes.Internal, "failed to describe secret: %v", err)
	}

	// Validate that the secret has the 'spire-svid' tag. This tag is used to distinguish the secrets
	// that have SVID information handled by SPIRE
	if err := validateTag(secretDesc.Tags); err != nil {
		return nil, err
	}

	resp, err := p.smClient.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
		SecretId:             secretDesc.ARN,
		RecoveryWindowInDays: aws.Int64(7),
	})

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete secret %q: %v", secretID, err)
	}

	p.log.With("arn", aws.ToString(resp.ARN)).With("name", aws.ToString(resp.Name)).With("deletion_date", aws.ToTime(resp.DeletionDate)).Debug("Secret deleted")

	return &svidstorev1.DeleteX509SVIDResponse{}, nil
}

type secretOptions struct {
	name     string
	arn      string
	kmsKeyID string
}

// getSecretID gets ARN if it is configured. If not configured, use secret name
func (o *secretOptions) getSecretID() string {
	if o.arn != "" {
		return o.arn
	}

	return o.name
}

func optionsFromSecretData(metadata []string) (*secretOptions, error) {
	data, err := svidstore.ParseMetadata(metadata)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse Metadata: %v", err)
	}

	opt := &secretOptions{
		name:     data["secretname"],
		arn:      data["arn"],
		kmsKeyID: data["kmskeyid"],
	}

	if opt.name == "" && opt.arn == "" {
		return nil, status.Error(codes.InvalidArgument, "either the secret name or ARN is required")
	}

	return opt, nil
}

func createSecret(ctx context.Context, sm SecretsManagerClient, secretBinary []byte, opt *secretOptions) (*secretsmanager.CreateSecretOutput, error) {
	if opt.name == "" {
		return nil, status.Error(codes.InvalidArgument, "failed to create secret: name selector is required")
	}

	input := &secretsmanager.CreateSecretInput{
		Name: aws.String(opt.name),
		Tags: []types.Tag{
			{
				Key:   aws.String("spire-svid"),
				Value: aws.String("true"),
			},
		},
		SecretBinary: secretBinary,
	}
	if opt.kmsKeyID != "" {
		input.KmsKeyId = aws.String(opt.kmsKeyID)
	}

	resp, err := sm.CreateSecret(ctx, input)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secret: %v", err)
	}

	return resp, nil
}

// validateTag expects that "spire-svid" tag is provided
func validateTag(tags []types.Tag) error {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == "spire-svid" && aws.ToString(tag.Value) == "true" {
			return nil
		}
	}

	return status.Error(codes.InvalidArgument, "secret does not contain the 'spire-svid' tag")
}
