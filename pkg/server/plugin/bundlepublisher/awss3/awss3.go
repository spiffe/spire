package awss3

import (
	"bytes"
	"context"
	"net/url"
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
	"github.com/spiffe/spire/pkg/common/pluginconf"
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
	Endpoint        string `hcl:"endpoint" json:"endpoint"`

	// bundleFormat is used to store the content of Format, parsed
	// as bundleformat.Format.
	bundleFormat bundleformat.Format
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Config {
	newConfig := new(Config)

	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if newConfig.Region == "" {
		status.ReportError("configuration is missing the region")
	}
	if newConfig.Bucket == "" {
		status.ReportError("configuration is missing the bucket name")
	}
	if newConfig.ObjectKey == "" {
		status.ReportError("configuration is missing the object key")
	}
	if newConfig.Format == "" {
		status.ReportError("configuration is missing the bundle format")
	}
	if newConfig.Endpoint != "" {
		if _, err := url.ParseRequestURI(newConfig.Endpoint); err != nil {
			status.ReportErrorf("could not parse endpoint url: %v", err)
		}
	}

	bundleFormat, err := bundleformat.FromString(newConfig.Format)
	if err != nil {
		status.ReportErrorf("could not parse bundle format from configuration: %v", err)
	} else {
		// This plugin only supports some bundleformats.
		switch bundleFormat {
		case bundleformat.JWKS:
		case bundleformat.SPIFFE:
		case bundleformat.PEM:
		default:
			status.ReportErrorf("bundle format %q is not supported", newConfig.Format)
		}
		newConfig.bundleFormat = bundleFormat
	}

	return newConfig
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
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	// seems wrong to change plugin s3Client before config change
	awsCfg, err := newAWSConfig(ctx, newConfig)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create client configuration: %v", err)
	}
	s3Client, err := p.hooks.newS3ClientFunc(awsCfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create client: %v", err)
	}
	p.s3Client = s3Client

	p.setConfig(newConfig)
	p.setBundle(nil)
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, err
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
