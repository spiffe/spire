package cassandra

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/sirupsen/logrus"
	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

// PluginName is the name of the Cassandra datastore plugin.
const PluginName = "cassandra"

// Plugin implements the datastore plugin interface for Cassandra.
type Plugin struct {
	datastorev1.UnsafeDataStoreServer
	configv1.UnsafeConfigServer

	rlock  *sync.Mutex
	rwLock *sync.Mutex
	log    logrus.FieldLogger
	cfg    *Configuration
	db     *cassandraDB
}

// New creates a new instance of the Cassandra datastore plugin with the provided logger.
func New(log logrus.FieldLogger) Plugin {
	return Plugin{
		rlock:  &sync.Mutex{},
		rwLock: &sync.Mutex{},
		log:    log,
	}
}

// NewPlugin creates a new instance of the Cassandra datastore plugin with a default logger.
func NewPlugin() *Plugin {
	return &Plugin{
		rlock:  &sync.Mutex{},
		rwLock: &sync.Mutex{},
		log:    logrus.New().WithField("component", "datastore-cassandra"), // TODO(tjons): this is weird?
	}
}

// TODO(tjons): figure out what to do with this
func (p *Plugin) SetLogger(log hclog.Logger) {
	// p.log = log
}

// Name returns the name of the plugin, which is "cassandra".
func (p *Plugin) Name() string {
	return PluginName
}

func (p *Plugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	return &configv1.ValidateResponse{}, nil // TODO(tjons): IMPLEMENT!!
}

// Close terminates the plugin and releases any resources, including closing the connection to the Cassandra database.
func (p *Plugin) Close() error {
	p.db.session.Close()
	p.log.Infof("Closing connection to cassandra...")
	return nil
}

// Configure initializes the plugin with the provided configuration, including establishing a connection to the Cassandra database.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	cfg := &Configuration{}
	if err := hcl.Decode(cfg, req.HclConfiguration); err != nil {
		return nil, err
	}

	p.cfg = cfg

	runtimeCfg := &runtimeConfiguration{}
	if err := runtimeCfg.FromUserConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	var (
		successful bool
		err        error
	)
	for range runtimeCfg.MaxConnectionAttempts {
		// open connections to cassandra and initialize the session
		err = p.openConnections(ctx, runtimeCfg)
		if err != nil {
			p.log.Errorf("Error attempting to initialize connection to Cassandra: %s", err.Error())
			time.Sleep(initialConnectionBackoff)
			continue
		}

		successful = true
		break
	}

	if !successful {
		return nil, err
	}

	return &configv1.ConfigureResponse{}, nil
}
