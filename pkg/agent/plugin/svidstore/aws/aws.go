package aws

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "aws_secretsmanager"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *SecretsManagerPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, svidstore.PluginServer(p))
}

func New() *SecretsManagerPlugin {
	return newPlugin(createSecretManagerClient)
}

func newPlugin(newClient func(secretAccessKey, accessKeyID, region string) (SecretsManagerClient, error)) *SecretsManagerPlugin {
	p := &SecretsManagerPlugin{}
	p.hooks.newClient = newClient
	p.hooks.getenv = os.Getenv

	return p
}

type secretOptions struct {
	name     string
	arn      string
	kmsKeyID string
}

func secretFromSelectors(req *svidstore.PutX509SVIDRequest) (*secretOptions, error) {
	data := svidstore.ParseSelectors(pluginName, req.Selectors)

	opt := &secretOptions{
		name:     data["secretname"],
		arn:      data["arn"],
		kmsKeyID: data["kmskeyid"],
	}

	if opt.name == "" && opt.arn == "" {
		return nil, status.Error(codes.InvalidArgument, "secret name or ARN are required")
	}

	return opt, nil
}

type Config struct {
	AccessKeyID     string   `hcl:"access_key_id"`
	SecretAccessKey string   `hcl:"secret_access_key"`
	Regions         []string `hcl:"regions"`
}

type SecretsManagerPlugin struct {
	svidstore.UnsafeSVIDStoreServer

	log    hclog.Logger
	config *Config
	mtx    sync.RWMutex

	hooks struct {
		newClient func(secretAccessKey, accessKeyID, region string) (SecretsManagerClient, error)
		getenv    func(string) string
	}
}

func (p *SecretsManagerPlugin) SetLogger(log hclog.Logger) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.log = log
}

// Configure configures the SecretsManagerPlugin.
func (p *SecretsManagerPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &Config{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config

	if config.AccessKeyID == "" {
		config.AccessKeyID = p.hooks.getenv("AWS_ACCESS_KEY_ID")
	}

	if config.SecretAccessKey == "" {
		config.SecretAccessKey = p.hooks.getenv("AWS_SECRET_ACCESS_KEY")
	}

	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and other metadata of the plugin.
func (*SecretsManagerPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// PutX509SVID puts the specified X509-SVID in the configured AWS Secrets Manager
func (p *SecretsManagerPlugin) PutX509SVID(_ context.Context, req *svidstore.PutX509SVIDRequest) (*svidstore.PutX509SVIDResponse, error) {
	opt, err := secretFromSelectors(req)
	if err != nil {
		return nil, err
	}

	regions := p.config.Regions
	// TODO: may we allow default regions to be replaced for selectors?
	if len(regions) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one region is required")
	}

	for _, region := range regions {
		if err := p.putX509SVID(opt, region, req); err != nil {
			return nil, err
		}
	}
	return &svidstore.PutX509SVIDResponse{}, nil
}

func (p *SecretsManagerPlugin) putX509SVID(opt *secretOptions, region string, req *svidstore.PutX509SVIDRequest) error {
	// Create client
	sm, err := p.hooks.newClient(p.config.SecretAccessKey, p.config.AccessKeyID, region)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create secrets manager client: %v", err)
	}

	// Use arn if it is configured if not use name
	secretID := opt.name
	if opt.arn != "" {
		secretID = opt.arn
	}

	// Encode the secret from a 'workload.X509SVIDResponse'
	svidResponse, err := svidstore.X509ResponseFromProto(req)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to parse request : %v", err)
	}

	secretBinary, err := json.Marshal(svidResponse)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to parse payload: %v", err)
	}

	// Call DescribeSecret to retrieve the details of the secret
	// and be able to determine if the secret exists
	secretDesc, err := sm.DescribeSecret(&secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeResourceNotFoundException:
				// Secret not found, creating one with provided `name`
				resp, err := createSecret(sm, secretBinary, opt)
				if err != nil {
					return err
				}
				p.log.With("version_id", aws.StringValue(resp.VersionId)).With("arn", aws.StringValue(resp.ARN)).With("name", aws.StringValue(resp.Name)).Debug("Secret created")

				return nil
			default:
				return status.Errorf(codes.Internal, "failed to describe secret: %v", err)
			}
		}
		// It must not happens.
		return status.Errorf(codes.Internal, "failed to describe secret: %v", err)
	}

	// Validate that the secret has the 'spire-svid' tag. This tag is used to distinguish the secrets
	// that have SVID information handled by SPIRE
	if ok := validateTag(secretDesc.Tags); !ok {
		return status.Error(codes.InvalidArgument, "secret does not contain the 'spire-svid' tag")
	}

	putResp, err := sm.PutSecretValue(&secretsmanager.PutSecretValueInput{
		SecretId:     secretDesc.ARN,
		SecretBinary: secretBinary,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed to put secret value: %v", err)
	}

	p.log.With("version_id", aws.StringValue(putResp.VersionId)).With("arn", aws.StringValue(putResp.ARN)).With("name", aws.StringValue(putResp.Name)).Debug("Secret value updated")
	return nil
}

func createSecret(sm SecretsManagerClient, secretBinary []byte, opt *secretOptions) (*secretsmanager.CreateSecretOutput, error) {
	if opt.name == "" {
		return nil, status.Error(codes.InvalidArgument, "failed to create secret: name selector is required")
	}

	input := &secretsmanager.CreateSecretInput{
		Name: aws.String(opt.name),
		Tags: []*secretsmanager.Tag{
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

	resp, err := sm.CreateSecret(input)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secret: %v", err)
	}

	return resp, nil
}

// validateTag expects that "spire-svid" tag is provided
func validateTag(tags []*secretsmanager.Tag) bool {
	for _, tag := range tags {
		if aws.StringValue(tag.Key) == "spire-svid" && aws.StringValue(tag.Value) == "true" {
			return true
		}
	}

	return false
}
