package agent

import (
	"crypto/x509"
	"net"
	"net/url"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"

	common_catalog "github.com/spiffe/spire/pkg/common/catalog"
	tomb "gopkg.in/tomb.v2"
)

type Config struct {
	// Address to bind the workload api to
	BindAddress *net.UnixAddr

	// Directory to store runtime data
	DataDir string

	// Configurations for agent plugins
	PluginConfigs common_catalog.PluginConfigMap

	Log logrus.FieldLogger

	// Address of SPIRE server
	ServerAddress *net.TCPAddr

	// Trust domain and associated CA bundle
	TrustDomain url.URL
	TrustBundle []*x509.Certificate

	// Join token to use for attestation, if needed
	JoinToken string

	// Umask value to use
	Umask int

	// If true enables profiling.
	ProfilingEnabled bool

	// Port used by the pprof web server when ProfilingEnabled == true
	ProfilingPort int

	// Frequency in seconds by which each profile file will be generated.
	ProfilingFreq int

	// Array of profiles names that will be generated on each profiling tick.
	ProfilingNames []string
}

func New(c *Config) *Agent {
	catConfig := &catalog.Config{
		PluginConfigs: c.PluginConfigs,
		Log:           c.Log.WithField("subsystem_name", "catalog"),
	}

	t := new(tomb.Tomb)
	telConfig := &telemetry.SinkConfig{
		Logger:      c.Log.WithField("subsystem_name", "telemetry").Writer(),
		ServiceName: "spire_agent",
		StopChan:    t.Dying(),
	}

	return &Agent{
		c:       c,
		t:       t,
		mtx:     new(sync.RWMutex),
		tel:     telemetry.NewSink(telConfig),
		Catalog: catalog.New(catConfig),
	}
}
