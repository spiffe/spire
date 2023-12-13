package agent

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

type Config struct {
	// Address to bind the workload api to
	BindAddress net.Addr

	// Directory to store runtime data
	DataDir string

	// Directory to bind the admin api to
	AdminBindAddress net.Addr

	// The Validation Context resource name to use when fetching X.509 bundle together with federated bundles with Envoy SDS
	DefaultAllBundlesName string

	// The Validation Context resource name to use for the default X.509 bundle with Envoy SDS
	DefaultBundleName string

	// Disable custom Envoy SDS validator
	DisableSPIFFECertValidation bool

	// The TLS Certificate resource name to use for the default X509-SVID with Envoy SDS
	DefaultSVIDName string

	// If true, the agent will bootstrap insecurely with the server
	InsecureBootstrap bool

	// HealthChecks provides the configuration for health monitoring
	HealthChecks health.Config

	// Configurations for agent plugins
	PluginConfigs catalog.PluginConfigs

	Log logrus.FieldLogger

	// LogReopener facilitates handling a signal to rotate log file.
	LogReopener func(context.Context) error

	// Address of SPIRE server
	ServerAddress string

	// SVID key type
	WorkloadKeyType workloadkey.KeyType

	// SyncInterval controls how often the agent sync synchronizer waits
	SyncInterval time.Duration

	// UseSyncAuthorizedEntries controls if the new SyncAuthorizedEntries RPC
	// is used to sync entries from the server.
	UseSyncAuthorizedEntries bool

	// X509SVIDCacheMaxSize is a soft limit of max number of SVIDs that would be stored in cache
	X509SVIDCacheMaxSize int

	// Trust domain and associated CA bundle
	TrustDomain spiffeid.TrustDomain
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

	AllowUnauthenticatedVerifiers bool

	// List of allowed claims response when calling ValidateJWTSVID using a foreign identity
	AllowedForeignJWTClaims []string

	AuthorizedDelegates []string
}

func New(c *Config) *Agent {
	return &Agent{
		c: c,
	}
}
