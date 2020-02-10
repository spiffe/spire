package server

import (
	"crypto/x509/pkix"
	"net"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
	common "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/telemetry"
	bundle_client "github.com/spiffe/spire/pkg/server/bundle/client"
	"github.com/spiffe/spire/pkg/server/endpoints/bundle"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
)

type Config struct {
	// Configurations for server plugins
	PluginConfigs common.HCLPluginConfigMap

	Log logrus.FieldLogger

	// Address of SPIRE server
	BindAddress *net.TCPAddr

	// Address of the UDS SPIRE server
	BindUDSAddress *net.UnixAddr

	// Directory to store runtime data
	DataDir string

	// Trust domain
	TrustDomain url.URL

	UpstreamBundle bool

	Experimental ExperimentalConfig

	// If true enables profiling.
	ProfilingEnabled bool

	// Port used by the pprof web server when ProfilingEnabled == true
	ProfilingPort int

	// Frequency in seconds by which each profile file will be generated.
	ProfilingFreq int

	// Array of profiles names that will be generated on each profiling tick.
	ProfilingNames []string

	// SVIDTTL is default time-to-live for SVIDs
	SVIDTTL time.Duration

	// CATTL is the time-to-live for the server CA. This only applies to
	// self-signed CA certificates, otherwise it is up to the upstream CA.
	CATTL time.Duration

	// JWTIssuer is used as the issuer claim in JWT-SVIDs minted by the server.
	// If unset, the JWT-SVID will not have an issuer claim.
	JWTIssuer string

	// CASubject is the subject used in the CA certificate
	CASubject pkix.Name

	// Telemetry provides the configuration for metrics exporting
	Telemetry telemetry.FileConfig

	// HealthChecks provides the configuration for health monitoring
	HealthChecks health.Config

	// CAKeyType is the key type used for the X509 and JWT signing keys
	CAKeyType keymanager.KeyType

	// TolerateStale allows some level of staleness by using read replica for few readOnly operations
	TolerateStale bool
}

type ExperimentalConfig struct {
	// Skip agent id validation in node attestation
	AllowAgentlessNodeAttestors bool

	// BundleEndpointEnabled, if true, enables the federation bundle endpoint
	BundleEndpointEnabled bool

	// BundleEndpointAddress is the address on which to serve the federation
	// bundle endpoint.
	BundleEndpointAddress *net.TCPAddr

	// BundleEndpointACME is the ACME configuration for the bundle endpoint.
	// If unset, the bundle endpoint will use SPIFFE auth.
	BundleEndpointACME *bundle.ACMEConfig

	// FederatesWith holds the federation configuration for trust domains this
	// server federates with.
	FederatesWith map[string]bundle_client.TrustDomainConfig
}

func New(config Config) *Server {
	return &Server{
		config: config,
	}
}
