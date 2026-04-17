package endpoints

import (
	"net"

	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/sirupsen/logrus"
	workload_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	healthv1 "github.com/spiffe/spire/pkg/agent/api/health/v1"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv3"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// WorkloadAPIRateLimitConfig configures per-SPIFFE-ID rate limits for Workload API methods.
// A value of 0 means no limit is applied for that method.
type WorkloadAPIRateLimitConfig struct {
	FetchX509SVID int
	FetchJWTSVID  int
}

type Config struct {
	BindAddr net.Addr

	Attestor attestor.Attestor

	Manager manager.Manager

	Log logrus.FieldLogger

	Metrics telemetry.Metrics

	// The TLS Certificate resource name to use for the default X509-SVID with Envoy SDS
	DefaultSVIDName string

	// The Validation Context resource name to use when fetching X.509 bundle together with federated bundles with Envoy SDS
	DefaultAllBundlesName string

	// The Validation Context resource name to use for the default X.509 bundle with Envoy SDS
	DefaultBundleName string

	// Disable custom Envoy SDS validator
	DisableSPIFFECertValidation bool

	AllowUnauthenticatedVerifiers bool

	AllowedForeignJWTClaims []string

	TrustDomain spiffeid.TrustDomain

	// WorkloadAPIRateLimit configures per-SPIFFE-ID rate limiting for Workload API methods.
	WorkloadAPIRateLimit WorkloadAPIRateLimitConfig

	// Hooks used by the unit tests to assert that the configuration provided
	// to each handler is correct and return fake handlers.
	newWorkloadAPIServer func(workload.Config) workload_pb.SpiffeWorkloadAPIServer
	newSDSv3Server       func(sdsv3.Config) secret_v3.SecretDiscoveryServiceServer
	newHealthServer      func(healthv1.Config) grpc_health_v1.HealthServer
}
