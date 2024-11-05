package gcpcloudstorage

import (
	"context"
	"io"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk/support/bundleformat"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	pluginName = "gcp_cloudstorage"
)

type pluginHooks struct {
	newGCSClientFunc     func(ctx context.Context, opts ...option.ClientOption) (gcsService, error)
	newStorageWriterFunc func(ctx context.Context, o *storage.ObjectHandle) io.WriteCloser
	wroteObjectFunc      func() // Test hook called when an object was written.
}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func New() *Plugin {
	return newPlugin(newGCSClient, newStorageWriter)
}

// Config holds the configuration of the plugin.
type Config struct {
	BucketName         string `hcl:"bucket_name" json:"bucket_name"`
	ObjectName         string `hcl:"object_name" json:"object_name"`
	Format             string `hcl:"format" json:"format"`
	ServiceAccountFile string `hcl:"service_account_file" json:"service_account_file"`

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

	if newConfig.BucketName == "" {
		status.ReportError("configuration is missing the bucket name")
	}
	if newConfig.ObjectName == "" {
		status.ReportError("configuration is missing the object name")
	}

	if newConfig.Format == "" {
		status.ReportError("configuration is missing the bundle format")
	}
	bundleFormat, err := bundleformat.FromString(newConfig.Format)
	if err != nil {
		status.ReportErrorf("could not parse bundle format from configuration: %v", err)
	} else {
		// Only some bundleformats are supported by this plugin.
		switch bundleFormat {
		case bundleformat.JWKS:
		case bundleformat.SPIFFE:
		case bundleformat.PEM:
		default:
			status.ReportErrorf("format not supported %q", newConfig.Format)
		}
	}
	newConfig.bundleFormat = bundleFormat

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

	hooks     pluginHooks
	gcsClient gcsService
	log       hclog.Logger
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

	var opts []option.ClientOption
	if newConfig.ServiceAccountFile != "" {
		opts = append(opts, option.WithCredentialsFile(newConfig.ServiceAccountFile))
	}
	gcsClient, err := p.hooks.newGCSClientFunc(ctx, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create client: %v", err)
	}
	p.gcsClient = gcsClient

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

// PublishBundle puts the bundle in the configured GCS bucket and object name.
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

	bucketHandle := p.gcsClient.Bucket(config.BucketName)
	if bucketHandle == nil { // Purely defensive, the Bucket function implemented in GCS always returns a BucketHandle.
		return nil, status.Error(codes.Internal, "could not get bucket handle")
	}

	objectHandle := bucketHandle.Object(config.ObjectName)
	if objectHandle == nil { // Purely defensive, the Object function implemented in GCS always returns an ObjectHandle.
		return nil, status.Error(codes.Internal, "could not get object handle")
	}

	storageWriter := p.hooks.newStorageWriterFunc(ctx, objectHandle)
	if storageWriter == nil { // Purely defensive, the NewWriter function implemented in GCS always returns a storage writer
		return nil, status.Error(codes.Internal, "could not initialize storage writer")
	}

	log := p.log.With(
		"bucket_name", config.BucketName,
		"object_name", config.ObjectName)

	_, err = storageWriter.Write(bundleBytes)
	// The number of bytes written can be safely ignored. To determine if an
	// object was successfully uploaded, we need to look at the error returned
	// from storageWriter.Close().
	if err != nil {
		// Close the storage writer before returning.
		if closeErr := storageWriter.Close(); closeErr != nil {
			log.With(telemetry.Error, closeErr).Error("Failed to close storage writer")
		}
		return nil, status.Errorf(codes.Internal, "failed to write bundle: %v", err)
	}

	if err := storageWriter.Close(); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to close storage writer: %v", err)
	}

	if p.hooks.wroteObjectFunc != nil {
		p.hooks.wroteObjectFunc()
	}

	p.setBundle(req.Bundle)
	log.Debug("Bundle published")
	return &bundlepublisherv1.PublishBundleResponse{}, nil
}

// Close is called when the plugin is unloaded. Closes the client.
func (p *Plugin) Close() error {
	if p.gcsClient == nil {
		return nil
	}
	p.log.Debug("Closing the connection to the Cloud Storage API service")
	return p.gcsClient.Close()
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
func newPlugin(newGCSClientFunc func(ctx context.Context, opts ...option.ClientOption) (gcsService, error),
	newStorageWriterFunc func(ctx context.Context, o *storage.ObjectHandle) io.WriteCloser) *Plugin {
	return &Plugin{
		hooks: pluginHooks{
			newGCSClientFunc:     newGCSClientFunc,
			newStorageWriterFunc: newStorageWriterFunc,
		},
	}
}
