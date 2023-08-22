package awss3

import (
	"bytes"
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk/support/bundleformat"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	pluginName = "aws_s3"
)

type pluginHooks struct {
	newS3ClientFunc func(c aws.Config) (simpleStorageService, error)
}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func New() *Plugin {
	return newPlugin(newS3Client)
}

// Config holds the configuration of the plugin.
type Config struct {
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	Region          string `hcl:"region" json:"region"`
	Bucket          string `hcl:"bucket" json:"bucket"`
	ObjectKey       string `hcl:"object_key" json:"object_key"`
	Format          string `hcl:"format" json:"format"`

	// bundleFormat is used to store the content of Format, parsed
	// as bundleformat.Format.
	bundleFormat bundleformat.Format
}

// Plugin is the main representation of this bundle publisher plugin.
type Plugin struct {
	bundlepublisherv1.UnsafeBundlePublisherServer
	configv1.UnsafeConfigServer

	config    *Config
	configMtx sync.RWMutex

	bundle    *types.Bundle
	bundleMtx sync.RWMutex

	hooks    pluginHooks
	s3Client simpleStorageService
	log      hclog.Logger
}

// SetLogger sets a logger in the plugin.
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure configures the plugin.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config, err := parseAndValidateConfig(req.HclConfiguration)
	if err != nil {
		return nil, err
	}

	awsCfg, err := newAWSConfig(ctx, config)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create client configuration: %v", err)
	}
	s3Client, err := p.hooks.newS3ClientFunc(awsCfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create client: %v", err)
	}
	p.s3Client = s3Client

	p.setConfig(config)
	p.setBundle(nil)
	return &configv1.ConfigureResponse{}, nil
}

// PublishBundle puts the bundle in the configured S3 bucket name and
// object key.
func (p *Plugin) PublishBundle(ctx context.Context, req *bundlepublisherv1.PublishBundleRequest) (*bundlepublisherv1.PublishBundleResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	if req.Bundle == nil {
		return nil, status.Error(codes.InvalidArgument, "missing bundle in request")
	}

	currentBundle := p.getBundle()
	if proto.Equal(req.Bundle, currentBundle) {
		// Bundle not changed. No need to publish.
		return &bundlepublisherv1.PublishBundleResponse{}, nil
	}

	formatter := bundleformat.NewFormatter(req.Bundle)
	bundleBytes, err := formatter.Format(config.bundleFormat)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not format bundle: %v", err.Error())
	}

	_, err = p.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(config.Bucket),
		Body:   bytes.NewReader(bundleBytes),
		Key:    aws.String(config.ObjectKey),
	})

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to put object: %v", err)
	}

	p.setBundle(req.Bundle)
	p.log.Debug("Bundle published")
	return &bundlepublisherv1.PublishBundleResponse{}, nil
}

// getBundle gets the latest bundle that the plugin has.
func (p *Plugin) getBundle() *types.Bundle {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()

	return p.bundle
}

// getConfig gets the configuration of the plugin.
func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()

	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

// setBundle updates the current bundle in the plugin with the provided bundle.
func (p *Plugin) setBundle(bundle *types.Bundle) {
	p.bundleMtx.Lock()
	defer p.bundleMtx.Unlock()

	p.bundle = bundle
}

// setConfig sets the configuration for the plugin.
func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	defer p.configMtx.Unlock()

	p.config = config
}

// builtin creates a new BundlePublisher built-in plugin.
func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		bundlepublisherv1.BundlePublisherPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// newPlugin returns a new plugin instance.
func newPlugin(newS3ClientFunc func(c aws.Config) (simpleStorageService, error)) *Plugin {
	return &Plugin{
		hooks: pluginHooks{
			newS3ClientFunc: newS3ClientFunc,
		},
	}
}

// parseAndValidateConfig returns an error if any configuration provided does
// not meet acceptable criteria
func parseAndValidateConfig(c string) (*Config, error) {
	config := new(Config)

	if err := hcl.Decode(config, c); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.Region == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing the region")
	}

	if config.Bucket == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing the bucket name")
	}

	if config.ObjectKey == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing the object key")
	}

	if config.Format == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing the bundle format")
	}
	bundleFormat, err := bundleformat.FromString(config.Format)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "could not parse bundle format from configuration: %v", err)
	}
	// The bundleformat package may support formats that this plugin does not
	// support. Validate that the format is a supported format in this plugin.
	switch bundleFormat {
	case bundleformat.JWKS:
	case bundleformat.SPIFFE:
	case bundleformat.PEM:
	default:
		return nil, status.Errorf(codes.InvalidArgument, "format not supported %q", config.Format)
	}

	config.bundleFormat = bundleFormat
	return config, nil
}
