package azureblob

import (
	"context"
	"fmt"
	"net/url"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk/support/bundleformat"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	pluginName      = "azure_blob"
	defaultEndpoint = "blob.core.windows.net"
)

type pluginHooks struct {
	newBlobClientFunc          func(cred azcore.TokenCredential, accountURL string) (blobStorage, error)
	newBlobClientSharedKeyFunc func(accountURL string, cred *azblob.SharedKeyCredential) (blobStorage, error)
	fetchCredential            func() (azcore.TokenCredential, error)
}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func New() *Plugin {
	return newPlugin(newAzureBlobClient)
}

// Config holds the configuration of the plugin.
type Config struct {
	StorageAccountName string `hcl:"storage_account_name" json:"storage_account_name"`
	StorageAccountKey  string `hcl:"storage_account_key" json:"storage_account_key"`
	ServiceEndpoint    string `hcl:"service_endpoint" json:"service_endpoint"`
	ContainerName      string `hcl:"container_name" json:"container_name"`
	BlobName           string `hcl:"blob_name" json:"blob_name"`
	Format             string `hcl:"format" json:"format"`
	TenantID           string `hcl:"tenant_id" json:"tenant_id"`
	AppID              string `hcl:"app_id" json:"app_id"`
	AppSecret          string `hcl:"app_secret" json:"app_secret"`
	RefreshHint        string `hcl:"refresh_hint" json:"refresh_hint"`

	bundleFormat      bundleformat.Format
	parsedRefreshHint int64
	accountURL        string
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Config {
	newConfig := new(Config)

	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if newConfig.StorageAccountName == "" {
		status.ReportError("configuration is missing the storage account name")
	}
	if newConfig.ContainerName == "" {
		status.ReportError("configuration is missing the container name")
	}
	if newConfig.BlobName == "" {
		status.ReportError("configuration is missing the blob name")
	}
	if newConfig.Format == "" {
		status.ReportError("configuration is missing the bundle format")
	}

	bundleFormat, err := bundleformat.FromString(newConfig.Format)
	if err != nil {
		status.ReportErrorf("could not parse bundle format from configuration: %v", err)
	} else {
		switch bundleFormat {
		case bundleformat.JWKS:
		case bundleformat.SPIFFE:
		case bundleformat.PEM:
		default:
			status.ReportErrorf("bundle format %q is not supported", newConfig.Format)
		}
		newConfig.bundleFormat = bundleFormat
	}

	serviceEndpoint := newConfig.ServiceEndpoint
	if serviceEndpoint == "" {
		serviceEndpoint = defaultEndpoint
	}
	newConfig.accountURL = fmt.Sprintf("https://%s.%s", newConfig.StorageAccountName, serviceEndpoint)
	if _, err := url.ParseRequestURI(newConfig.accountURL); err != nil {
		status.ReportErrorf("could not parse service endpoint url: %v", err)
	}

	if newConfig.RefreshHint != "" {
		refreshHint, err := common.ParseRefreshHint(newConfig.RefreshHint, status)
		if err != nil {
			status.ReportErrorf("could not parse refresh_hint: %v", err)
		}
		newConfig.parsedRefreshHint = refreshHint
	}

	switch {
	case newConfig.StorageAccountKey != "":
		if newConfig.TenantID != "" || newConfig.AppID != "" || newConfig.AppSecret != "" {
			status.ReportError("storage account key and client secret credentials are mutually exclusive")
		}
	case newConfig.TenantID != "" || newConfig.AppID != "" || newConfig.AppSecret != "":
		if newConfig.TenantID == "" {
			status.ReportError("configuration is missing the tenant ID")
		}
		if newConfig.AppID == "" {
			status.ReportError("configuration is missing the app ID")
		}
		if newConfig.AppSecret == "" {
			status.ReportError("configuration is missing the app secret")
		}
	}

	return newConfig
}

// Plugin is the main representation of this bundle publisher plugin.
type Plugin struct {
	bundlepublisherv1.UnsafeBundlePublisherServer
	configv1.UnsafeConfigServer

	config     *Config
	blobClient blobStorage
	configMtx  sync.RWMutex

	bundle    *types.Bundle
	bundleMtx sync.RWMutex

	hooks pluginHooks
	log   hclog.Logger
}

// SetLogger sets a logger in the plugin.
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure configures the plugin.
func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, notes, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}
	for _, note := range notes {
		p.log.Warn(note)
	}

	var blobClient blobStorage

	switch {
	case newConfig.StorageAccountKey != "":
		sharedKeyCred, sharedKeyErr := azblob.NewSharedKeyCredential(newConfig.StorageAccountName, newConfig.StorageAccountKey)
		if sharedKeyErr != nil {
			return nil, status.Errorf(codes.Internal, "unable to get shared key credential: %v", sharedKeyErr)
		}

		blobClient, err = p.hooks.newBlobClientSharedKeyFunc(newConfig.accountURL, sharedKeyCred)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create client: %v", err)
		}

	case newConfig.TenantID != "" || newConfig.AppID != "" || newConfig.AppSecret != "":
		var cred azcore.TokenCredential
		cred, err = azidentity.NewClientSecretCredential(newConfig.TenantID, newConfig.AppID, newConfig.AppSecret, nil)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to get client credential: %v", err)
		}

		blobClient, err = p.hooks.newBlobClientFunc(cred, newConfig.accountURL)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create client: %v", err)
		}

	default:
		var cred azcore.TokenCredential
		cred, err = p.hooks.fetchCredential()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to fetch default credential: %v", err)
		}

		blobClient, err = p.hooks.newBlobClientFunc(cred, newConfig.accountURL)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create client: %v", err)
		}
	}
	// Store the config and client together under one lock so that
	// PublishBundle always observes a matching pair, even when Configure
	// runs concurrently as a result of a dynamic reconfiguration.
	p.setConfig(newConfig, blobClient)
	p.setBundle(nil)
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

// PublishBundle puts the bundle in the configured Azure Blob Storage container.
func (p *Plugin) PublishBundle(ctx context.Context, req *bundlepublisherv1.PublishBundleRequest) (*bundlepublisherv1.PublishBundleResponse, error) {
	config, blobClient, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	if req.Bundle == nil {
		return nil, status.Error(codes.InvalidArgument, "missing bundle in request")
	}

	currentBundle := p.getBundle()
	if proto.Equal(req.Bundle, currentBundle) {
		return &bundlepublisherv1.PublishBundleResponse{}, nil
	}

	bundleToPublish := proto.Clone(req.Bundle).(*types.Bundle)
	if config.parsedRefreshHint != 0 {
		bundleToPublish.RefreshHint = config.parsedRefreshHint
	}

	formatter := bundleformat.NewFormatter(bundleToPublish)
	bundleBytes, err := formatter.Format(config.bundleFormat)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not format bundle: %v", err.Error())
	}

	_, err = blobClient.UploadBuffer(ctx, config.ContainerName, config.BlobName, bundleBytes, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to upload blob: %v", err)
	}

	p.setBundle(req.Bundle)
	p.log.Debug("Bundle published")
	return &bundlepublisherv1.PublishBundleResponse{}, nil
}

// getBundle gets the latest bundle that the plugin has.
func (p *Plugin) getBundle() *types.Bundle {
	p.bundleMtx.RLock()
	defer p.bundleMtx.RUnlock()

	return p.bundle
}

// getConfig gets the configuration and blob client of the plugin.
func (p *Plugin) getConfig() (*Config, blobStorage, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()

	if p.config == nil {
		return nil, nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, p.blobClient, nil
}

// setBundle updates the current bundle in the plugin with the provided bundle.
func (p *Plugin) setBundle(bundle *types.Bundle) {
	p.bundleMtx.Lock()
	defer p.bundleMtx.Unlock()

	p.bundle = bundle
}

// setConfig sets the configuration and blob client for the plugin.
func (p *Plugin) setConfig(config *Config, blobClient blobStorage) {
	p.configMtx.Lock()
	defer p.configMtx.Unlock()

	p.config = config
	p.blobClient = blobClient
}

// builtin creates a new BundlePublisher built-in plugin.
func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		bundlepublisherv1.BundlePublisherPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// newPlugin returns a new plugin instance.
func newPlugin(newBlobClientFunc func(cred azcore.TokenCredential, accountURL string) (blobStorage, error)) *Plugin {
	return &Plugin{
		hooks: pluginHooks{
			newBlobClientFunc:          newBlobClientFunc,
			newBlobClientSharedKeyFunc: newAzureBlobClientWithSharedKey,
			fetchCredential: func() (azcore.TokenCredential, error) {
				return azidentity.NewDefaultAzureCredential(nil)
			},
		},
	}
}
