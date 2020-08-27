package agent

import (
	"crypto/x509"
	"net"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

type Config struct {
	// Address to bind the workload api to
	BindAddress *net.UnixAddr

	// Directory to store runtime data
	DataDir string

	// The Validation Context resource name to use for the default X.509 bundle with Envoy SDS
	DefaultBundleName string

	// The TLS Certificate resource name to use for the default X509-SVID with Envoy SDS
	DefaultSVIDName string

	// If true, the agent will bootstrap insecurely with the server
	InsecureBootstrap bool

	// HealthChecks provides the configuration for health monitoring
	HealthChecks health.Config

	// Configurations for agent plugins
	PluginConfigs catalog.HCLPluginConfigMap

	Log logrus.FieldLogger

	// Address of SPIRE server
	ServerAddress string

	// SyncInterval controls how often the agent sync synchronizer waits
	SyncInterval time.Duration

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
