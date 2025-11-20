package gcsbundle

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	notifierv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/notifier/v1"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func BuiltIn() catalog.BuiltIn {
	return builtIn(New())
}

func builtIn(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn("gcs_bundle",
		notifierv1.NotifierPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type bucketClient interface {
	GetObjectGeneration(ctx context.Context, bucket, object string) (int64, error)
	PutObject(ctx context.Context, bucket, object string, data []byte, generation int64) error
	Close() error
}

type configuration struct {
	Bucket             string `hcl:"bucket"`
	ObjectPath         string `hcl:"object_path"`
	ServiceAccountFile string `hcl:"service_account_file"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *configuration {
	newConfig := new(configuration)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("plugin configuration is malformed: %s", err)
		return nil
	}

	if newConfig.Bucket == "" {
		status.ReportError("bucket must be set")
	}
	if newConfig.ObjectPath == "" {
		status.ReportError("object_path must be set")
	}

	return newConfig
}

type Plugin struct {
	notifierv1.UnsafeNotifierServer
	configv1.UnsafeConfigServer

	mu               sync.RWMutex
	log              hclog.Logger
	config           *configuration
	identityProvider identityproviderv1.IdentityProviderServiceClient

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

func (p *Plugin) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
	if !broker.BrokerClient(&p.identityProvider) {
		return status.Errorf(codes.FailedPrecondition, "IdentityProvider host service is required")
	}
	return nil
}

func (p *Plugin) Notify(ctx context.Context, req *notifierv1.NotifyRequest) (*notifierv1.NotifyResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	if _, ok := req.Event.(*notifierv1.NotifyRequest_BundleUpdated); ok {
		// ignore the bundle presented in the request. see updateBundleObject for details on why.
		if err := p.updateBundleObject(ctx, config); err != nil {
			return nil, err
		}
	}
	return &notifierv1.NotifyResponse{}, nil
}

func (p *Plugin) NotifyAndAdvise(ctx context.Context, req *notifierv1.NotifyAndAdviseRequest) (*notifierv1.NotifyAndAdviseResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	if _, ok := req.Event.(*notifierv1.NotifyAndAdviseRequest_BundleLoaded); ok {
		// ignore the bundle presented in the request. see updateBundleObject for details on why.
		if err := p.updateBundleObject(ctx, config); err != nil {
			return nil, err
		}
	}
	return &notifierv1.NotifyAndAdviseResponse{}, nil
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (resp *configv1.ConfigureResponse, err error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = newConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (resp *configv1.ValidateResponse, err error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *Plugin) getConfig() (*configuration, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (p *Plugin) updateBundleObject(ctx context.Context, c *configuration) (err error) {
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

		// Load bundle data from the identity provider. The bundle has to
		// be loaded after fetching the generation so we can properly detect
		// and correct a race updating the bundle (i.e. read-modify-write
		// semantics).
		resp, err := p.identityProvider.FetchX509Identity(ctx, &identityproviderv1.FetchX509IdentityRequest{})
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
		p.log.Debug("Bundle object updated", telemetry.Generation, generation)
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
		return nil, err
	}

	return &gcsBucketClient{
		client: client,
	}, nil
}

func (c *gcsBucketClient) GetObjectGeneration(ctx context.Context, bucket, object string) (int64, error) {
	attrs, err := c.client.Bucket(bucket).Object(object).Attrs(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return 0, nil
		}
		return 0, err
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
	return w.Close()
}

func (c *gcsBucketClient) Close() error {
	return c.client.Close()
}

// bundleData formats the bundle data for storage in GCS
func bundleData(bundle *plugintypes.Bundle) []byte {
	bundleData := new(bytes.Buffer)
	for _, x509Authority := range bundle.X509Authorities {
		// no need to check the error since we're encoding into a memory buffer
		_ = pem.Encode(bundleData, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: x509Authority.Asn1,
		})
	}
	return bundleData.Bytes()
}

func isConditionNotMetError(err error) bool {
	var e *googleapi.Error
	ok := errors.As(err, &e)
	if ok && e.Code == http.StatusPreconditionFailed {
		for _, errorItem := range e.Errors {
			if errorItem.Reason == "conditionNotMet" {
				return true
			}
		}
	}
	return false
}
