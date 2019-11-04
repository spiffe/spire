package gcsbundle

import (
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/hostservices"
	"github.com/spiffe/spire/proto/spire/server/notifier"
	"github.com/zeebo/errs"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func BuiltIn() catalog.Plugin {
	return builtIn(New())
}

func builtIn(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin("gcs_bundle",
		notifier.PluginServer(p),
	)
}

type bucketClient interface {
	GetObjectGeneration(ctx context.Context, bucket, object string) (int64, error)
	PutObject(ctx context.Context, bucket, object string, data []byte, generation int64) error
	Close() error
}

type pluginConfig struct {
	Bucket             string `hcl:"bucket"`
	ObjectPath         string `hcl:"object_path"`
	ServiceAccountFile string `hcl:"service_account_file"`
}

type Plugin struct {
	mu               sync.RWMutex
	log              hclog.Logger
	config           *pluginConfig
	identityProvider hostservices.IdentityProvider

	hooks struct {
		newBucketClient func(ctx context.Context, configPath string) (bucketClient, error)
	}
}

func New() *Plugin {
	p := &Plugin{}
	p.hooks.newBucketClient = newGCSBucketClient
	return p
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) BrokerHostServices(broker catalog.HostServiceBroker) error {
	has, err := broker.GetHostService(hostservices.IdentityProviderHostServiceClient(&p.identityProvider))
	if err != nil {
		return err
	}
	if !has {
		return status.Errorf(codes.FailedPrecondition, "IdentityProvider host service is required")
	}
	return nil
}

func (p *Plugin) Notify(ctx context.Context, req *notifier.NotifyRequest) (*notifier.NotifyResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	switch req.Event.(type) {
	case *notifier.NotifyRequest_BundleUpdated:
		// ignore the bundle presented in the request. see updateBundleObject for details on why.
		if err := p.updateBundleObject(ctx, config); err != nil {
			return nil, err
		}
	}
	return &notifier.NotifyResponse{}, nil
}

func (p *Plugin) NotifyAndAdvise(ctx context.Context, req *notifier.NotifyAndAdviseRequest) (*notifier.NotifyAndAdviseResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	switch req.Event.(type) {
	case *notifier.NotifyAndAdviseRequest_BundleLoaded:
		// ignore the bundle presented in the request. see updateBundleObject for details on why.
		if err := p.updateBundleObject(ctx, config); err != nil {
			return nil, err
		}
	}
	return &notifier.NotifyAndAdviseResponse{}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (resp *spi.ConfigureResponse, err error) {
	if p.identityProvider == nil {
		return nil, status.Error(codes.FailedPrecondition, "IdentityProvider host service is required but not brokered")
	}

	config := new(pluginConfig)
	if err := hcl.Decode(&config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.Bucket == "" {
		return nil, status.Error(codes.InvalidArgument, "bucket must be set")
	}
	if config.ObjectPath == "" {
		return nil, status.Error(codes.InvalidArgument, "object_path must be set")
	}

	p.setConfig(config)
	return &spi.ConfigureResponse{}, nil
}

func (p *Plugin) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *Plugin) getConfig() (*pluginConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (p *Plugin) setConfig(config *pluginConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func (p *Plugin) updateBundleObject(ctx context.Context, c *pluginConfig) (err error) {
	client, err := p.hooks.newBucketClient(ctx, c.ServiceAccountFile)
	if err != nil {
		return status.Errorf(codes.Unknown, "unable to instantiate bucket client: %v", err)
	}
	defer client.Close()

	for {
		// Get the bundle object generation that we can use to resolve
		// conflicts racing on updates from other servers.
		generation, err := client.GetObjectGeneration(ctx, c.Bucket, c.ObjectPath)
		if err != nil {
			return status.Errorf(codes.Unknown, "unable to get bundle object %s/%s: %v", c.Bucket, c.ObjectPath, err)
		}
		p.log.Debug("Bundle object retrieved", telemetry.Generation, generation)

		// Load bundle data from the the identity provider. The bundle has to
		// be loaded after fetching the generation so we can properly detect
		// and correct a race updating the bundle (i.e. read-modify-write
		// semantics).
		resp, err := p.identityProvider.FetchX509Identity(ctx, &hostservices.FetchX509IdentityRequest{})
		if err != nil {
			st := status.Convert(err)
			return status.Errorf(st.Code(), "unable to fetch bundle from SPIRE server: %v", st.Message())
		}

		// Upload the bundle, handling version conflicts
		if err := client.PutObject(ctx, c.Bucket, c.ObjectPath, bundleData(resp.Bundle), generation); err != nil {
			// If there is a conflict then some other server won the race updating
			// the object. We need to retrieve the latest bundle and try again.
			if isConditionNotMetError(err) {
				p.log.Debug("Conflict detected setting bundle object", telemetry.Generation, generation)
				continue
			}
			return status.Errorf(codes.Unknown, "unable to update bundle object %s/%s: %v", c.Bucket, c.ObjectPath, err)
		}

		return nil
	}
}

type gcsBucketClient struct {
	client *storage.Client
}

func newGCSBucketClient(ctx context.Context, serviceAccountFile string) (bucketClient, error) {
	var opts []option.ClientOption
	if serviceAccountFile != "" {
		opts = append(opts, option.WithCredentialsFile(serviceAccountFile))
	}
	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	return &gcsBucketClient{
		client: client,
	}, nil
}

func (c *gcsBucketClient) GetObjectGeneration(ctx context.Context, bucket, object string) (int64, error) {
	attrs, err := c.client.Bucket(bucket).Object(object).Attrs(ctx)
	if err != nil {
		if err == storage.ErrObjectNotExist {
			return 0, nil
		}
		return 0, errs.Wrap(err)
	}
	return attrs.Generation, nil
}

func (c *gcsBucketClient) PutObject(ctx context.Context, bucket, object string, data []byte, generation int64) error {
	// If for whatever reason we don't make it to w.Close(), canceling the
	// context will cleanly release resources held by the writer.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	conds := storage.Conditions{
		GenerationMatch: generation,
		DoesNotExist:    generation == 0,
	}
	w := c.client.Bucket(bucket).Object(object).If(conds).NewWriter(ctx)
	w.ContentType = "application/x-pem-file"
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return nil
}

func (c *gcsBucketClient) Close() error {
	return c.client.Close()
}

// bundleData formats the bundle data for storage in GCS
func bundleData(bundle *common.Bundle) []byte {
	bundleData := new(bytes.Buffer)
	for _, rootCA := range bundle.RootCas {
		pem.Encode(bundleData, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootCA.DerBytes,
		})
	}
	return bundleData.Bytes()
}

func isConditionNotMetError(err error) bool {
	if e, ok := err.(*googleapi.Error); ok && e.Code == http.StatusPreconditionFailed {
		for _, errorItem := range e.Errors {
			if errorItem.Reason == "conditionNotMet" {
				return true
			}
		}
	}
	return false
}
