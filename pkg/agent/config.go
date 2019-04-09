package agent

import (
	"crypto/x509"
	"net"
	"net/url"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

type Config struct {
	// Address to bind the workload api to
	BindAddress *net.UnixAddr

	// Directory to store runtime data
	DataDir string

	// If true, enables an Envoy SecretDiscoveryService server
	EnableSDS bool

	// Configurations for agent plugins
	PluginConfigs catalog.PluginConfigMap

	Log logrus.FieldLogger

	// Address of SPIRE server
	ServerAddress string

	// Trust domain and associated CA bundle
	TrustDomain url.URL
	TrustBundle []*x509.Certificate

	// Join token to use for attestation, if needed
	JoinToken string

	// If true enables profiling.
	ProfilingEnabled bool

	// Port used by the pprof web server when ProfilingEnabled == true
	ProfilingPort int

	// Frequency in seconds by which each profile file will be generated.
	ProfilingFreq int

	// Array of profiles names that will be generated on each profiling tick.
	ProfilingNames []string

	// Telemetry provides the configuration for metrics exporting
	Telemetry telemetry.FileConfig
}

func New(c *Config) *Agent {
	return &Agent{
		c: c,
	}
}

func (c *Config) GlobalConfig() *catalog.GlobalConfig {
	return &catalog.GlobalConfig{
		TrustDomain: c.TrustDomain.Host,
	}
}
