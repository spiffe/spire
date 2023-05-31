package akeylesssecretsmanager

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/akeylesslabs/akeyless-go/v3"
	log "github.com/hashicorp/go-hclog"

	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	svidstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/svidstore/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName    = "akeyless_secretsmanager"
	pluginItemTag = "spire-svid"
)

var (
	// This compile-time assertion ensures the plugin conforms properly to the
	// pluginsdk.NeedsLogger interface.
	// TODO: Remove if the plugin does not need the logger.
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

type secretEntry struct {
	Name     string
	KeyId    string
	Metadata string
}

// Plugin implements the SVIDStore plugin
type Plugin struct {
	svidstorev1.UnsafeSVIDStoreServer
	configv1.UnsafeConfigServer

	// Configuration should be set atomically
	mu                           sync.RWMutex
	config                       *Config
	authenticationRoutineRunning bool

	// The logger received from the framework via the SetLogger method
	logger log.Logger
}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		svidstorev1.SVIDStorePluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

func checkIfSecretExist(ctx context.Context, name string) (bool, error) {
	body := akeyless.DescribeItem{}
	body.SetName(name)
	body.SetToken(GetAuthToken())

	out, _, err := AklClient.DescribeItem(ctx).Body(body).Execute()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "found") {
			return false, nil
		}
		return false, status.Errorf(codes.Internal, "failed to describe item %v: %v", name, err.Error())
	}

	//validate tag
	for _, t := range out.GetItemTags() {
		if t == pluginItemTag {
			return true, nil
		}
	}

	return false, status.Errorf(codes.InvalidArgument, "item %v does not contain the '%v' tag", name, pluginItemTag)
}

// DeleteX509SVID implements the SVIDStore DeleteX509SVID RPC. Deletes an SVID from the store.
func (p *Plugin) DeleteX509SVID(ctx context.Context, req *svidstorev1.DeleteX509SVIDRequest) (*svidstorev1.DeleteX509SVIDResponse, error) {
	opt, err := secretEntryFromSecretData(req.Metadata)
	if err != nil {
		return nil, err
	}

	exist, err := checkIfSecretExist(ctx, opt.Name)
	if err != nil {
		return nil, err
	}

	if !exist {
		p.logger.Warn("Secret %v n ot found", opt.Name)
		return &svidstorev1.DeleteX509SVIDResponse{}, nil
	}

	body := akeyless.DeleteItem{}
	body.SetName(opt.Name)
	body.SetToken(GetAuthToken())
	_, _, err = AklClient.DeleteItem(ctx).Body(body).Execute()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete item %v: %v", opt.Name, err.Error())
	}

	return &svidstorev1.DeleteX509SVIDResponse{}, nil
}

// PutX509SVID implements the SVIDStore PutX509SVID RPC. Puts an X509-SVID in a configured secrets store.
func (p *Plugin) PutX509SVID(ctx context.Context, req *svidstorev1.PutX509SVIDRequest) (*svidstorev1.PutX509SVIDResponse, error) {
	opt, err := secretEntryFromSecretData(req.Metadata)
	if err != nil {
		return nil, err
	}

	// Encode the secret from PutX509SVIDRequest
	secret, err := svidstore.SecretFromProto(req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse request: %v", err.Error())
	}

	secretMarshalled, err := json.Marshal(secret)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse payload: %v", err.Error())
	}

	exist, err := checkIfSecretExist(ctx, opt.Name)
	if err != nil {
		return nil, err
	}

	if exist {
		//update
		p.logger.Info("secret %v already exists. Updating its value", opt.Name)
		body := akeyless.UpdateSecretVal{}
		body.SetName(opt.Name)
		body.SetValue(string(secretMarshalled))
		body.SetToken(GetAuthToken())
		_, _, err = AklClient.UpdateSecretVal(ctx).Body(body).Execute()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to update item %v: %v", opt.Name, err.Error())
		}

	} else {
		//create
		p.logger.Info("creting secret %v", opt.Name)
		body := akeyless.CreateSecret{}
		body.SetName(opt.Name)
		body.SetValue(string(secretMarshalled))
		body.SetTags([]string{pluginItemTag})
		body.SetToken(GetAuthToken())
		_, _, err = AklClient.CreateSecret(ctx).Body(body).Execute()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create item %v: %v", opt.Name, err.Error())
		}
	}

	return &svidstorev1.PutX509SVIDResponse{}, nil
}

// Configure configures the plugin. This is invoked by SPIRE when the plugin is
// first loaded. In the future, it may be invoked to reconfigure the plugin.
// As such, it should replace the previous configuration atomically.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config, err := ParseAndValidateConfig(req, p.logger)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.authenticationRoutineRunning {
		p.logger.Info("starting authentication routine to %v", config.AkeylessGatewayURL)
		closed := make(chan bool, 1)
		err = config.StartAuthentication(ctx, closed)

		if err != nil {
			p.logger.Error("failed to start authentication routine, error: %v", err)
			return nil, err
		}

		p.authenticationRoutineRunning = true
	}

	p.config = config

	return &configv1.ConfigureResponse{}, nil
}

// SetLogger is called by the framework when the plugin is loaded and provides
// the plugin with a logger wired up to SPIRE's logging facilities.
func (p *Plugin) SetLogger(logger log.Logger) {
	p.logger = logger
}

// getConfig gets the configuration under a read lock.
func (p *Plugin) getConfig() (*Config, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func secretEntryFromSecretData(metadata []string) (*secretEntry, error) {
	data, err := svidstore.ParseMetadata(metadata)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse Metadata: %v", err)
	}

	secretName := data["secretname"]
	if secretName == "" {
		secretName = data["secret"]
	}
	if secretName == "" {
		secretName = data["name"]
	}

	opt := &secretEntry{
		Name:     secretName,
		KeyId:    data["kmskeyid"],
		Metadata: strings.Join(metadata, ","),
	}

	if opt.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "Secret name is required")
	}

	return opt, nil
}

func New() *Plugin {
	return &Plugin{
		logger: log.Default(),
	}
}

func main() {
	plugin := New()
	// Serve the plugin. This function call will not return. If there is a
	// failure to serve, the process will exit with a non-zero exit code.
	pluginmain.Serve(
		svidstorev1.SVIDStorePluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
