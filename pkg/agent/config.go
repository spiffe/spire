package agent

import (
	"context"
	"net"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	loggerv1 "github.com/spiffe/spire/pkg/agent/api/logger/v1"
	"github.com/spiffe/spire/pkg/agent/broker"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/agent/trustbundlesources"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
)

const (
	RebootstrapNever  = "never"
	RebootstrapAuto   = "auto"
	RebootstrapAlways = "always"
)

// WorkloadAPIRateLimitConfig is an alias for endpoints.WorkloadAPIRateLimitConfig.
type WorkloadAPIRateLimitConfig = endpoints.WorkloadAPIRateLimitConfig

type Config struct {
	// Address to bind the public Workload API/SDS endpoint to. Nil disables the endpoint.
	BindAddress net.Addr

	// DisableWorkloadAPI disables serving the SPIFFE Workload API.
	DisableWorkloadAPI bool

	// DisableSDSAPI disables serving the Envoy SDS API.
	DisableSDSAPI bool

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

	// How the agent will behave when seeing an unknown x509 cert from the server
	RebootstrapMode string

	// The agent will rebootstrap after configured amount of time on unknown x509 cert from the server
	RebootstrapDelay time.Duration

	// HealthChecks provides the configuration for health monitoring
	HealthChecks health.Config

	// Configurations for agent plugins
	PluginConfigs catalog.PluginConfigs

	Log loggerv1.Logger

	// Workload selector prefixes allowed to be included in diagnostic logs.
	LogSelectors []string

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

	// X509SVIDCacheMaxSize is a soft limit of max number of X509-SVIDs that would be stored in cache
	X509SVIDCacheMaxSize int

	// JWTSVIDCacheMaxSize is a soft limit of max number of JWT-SVIDs that would be stored in cache
	JWTSVIDCacheMaxSize int

	// Trust domain and associated CA bundle
	TrustDomain spiffeid.TrustDomain

	// Sources for getting Trust Bundles
	TrustBundleSources trustbundlesources.Bundle

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

	// Broker holds the SPIFFE Broker API endpoint configuration. Distinct
	// from AuthorizedDelegates, which gates the Delegated Identity API.
	// Modeled as a struct (rather than a bare slice) so future top-level
	// broker configuration can be added without breaking this field's API.
	Broker BrokerConfig

	// AvailabilityTarget controls how frequently rotate SVIDs
	AvailabilityTarget time.Duration

	// TLSPolicy determines the post-quantum-safe TLS policy to apply to all TLS connections.
	TLSPolicy tlspolicy.Policy

	// WorkloadAPIRateLimit configures per-selector-set rate limiting for Workload API and SDS methods.
	WorkloadAPIRateLimit WorkloadAPIRateLimitConfig
}

// BrokerConfig mirrors the agent's `experimental.broker {}` HCL block.
type BrokerConfig struct {
	// BindAddresses are the addresses the broker endpoint listens on. Each
	// element is a `*net.UnixAddr` (UDS, POSIX only) or a `*net.TCPAddr`.
	// Multiple entries are served simultaneously by a single gRPC server.
	// Empty disables the broker endpoint.
	BindAddresses []net.Addr

	// Brokers enumerates the brokers authorized to talk to this agent's
	// broker endpoint.
	Brokers []broker.Broker
}

func New(c *Config) *Agent {
	return &Agent{
		c: c,
	}
}
