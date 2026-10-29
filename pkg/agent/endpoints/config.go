package endpoints

import (
	"fmt"
	"net"
	"strings"

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

// WorkloadAPIRateLimitConfig configures per-selector-set rate limits for Workload API methods.
// A value of 0 means no limit is applied for that method.
type WorkloadAPIRateLimitConfig struct {
	FetchX509SVID    int
	FetchJWTSVID     int
	FetchX509Bundles int
	FetchJWTBundles  int
	FetchWITSVID     int
	FetchWITBundles  int
	StreamSecrets    int
	FetchSecrets     int
}

// WorkloadAPIStreamLimitsConfig bounds active streams and optional waiting.
// Zero disables an active ceiling or disables waiting for MaxPending.
type WorkloadAPIStreamLimitsConfig struct {
	FetchX509SVID    int
	FetchX509Bundles int
	FetchJWTBundles  int
	StreamSecrets    int
	PerWorkload      int
	Global           int
	MaxPending       int
	Pools            []WorkloadAPIStreamPoolConfig
}

// WorkloadAPIStreamPoolConfig caps streams matching every configured selector.
type WorkloadAPIStreamPoolConfig struct {
	Name      string
	Selectors []string
	Limit     int
}

func (c WorkloadAPIStreamLimitsConfig) clone() WorkloadAPIStreamLimitsConfig {
	pools := c.Pools
	c.Pools = make([]WorkloadAPIStreamPoolConfig, len(pools))
	for i, pool := range pools {
		c.Pools[i] = pool
		c.Pools[i].Selectors = append([]string(nil), pool.Selectors...)
	}
	return c
}

// Validate checks stream policy settings before startup or policy replacement.
func (c WorkloadAPIStreamLimitsConfig) Validate() error {
	for _, setting := range []struct {
		key   string
		value int
	}{
		{"fetch_x509_svid", c.FetchX509SVID},
		{"fetch_x509_bundles", c.FetchX509Bundles},
		{"fetch_jwt_bundles", c.FetchJWTBundles},
		{"stream_secrets", c.StreamSecrets},
		{"per_workload", c.PerWorkload},
		{"global", c.Global},
		{"max_pending", c.MaxPending},
	} {
		if setting.value < 0 {
			return fmt.Errorf("experimental.stream_limits.%s must not be negative", setting.key)
		}
	}
	names := make(map[string]struct{}, len(c.Pools))
	for i, pool := range c.Pools {
		if pool.Name == "" {
			return fmt.Errorf("experimental.stream_limits.pool[%d].name must not be empty", i)
		}
		if _, ok := names[pool.Name]; ok {
			return fmt.Errorf("experimental.stream_limits.pool[%d].name duplicates %q", i, pool.Name)
		}
		names[pool.Name] = struct{}{}
		if pool.Limit < 0 {
			return fmt.Errorf("experimental.stream_limits.pool[%d].limit must not be negative", i)
		}
		for _, raw := range pool.Selectors {
			kind, value, ok := strings.Cut(raw, ":")
			if !ok || kind == "" || value == "" {
				return fmt.Errorf("experimental.stream_limits.pool[%d].selectors contains an invalid type:value pair", i)
			}
		}
	}
	return nil
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

	LogSelectors []string

	TrustDomain spiffeid.TrustDomain

	DisableWorkloadAPI bool

	DisableSDSAPI bool

	// WorkloadAPIRateLimit configures per-selector-set rate limiting for Workload API and SDS methods.
	WorkloadAPIRateLimit WorkloadAPIRateLimitConfig

	WorkloadAPIStreamLimits WorkloadAPIStreamLimitsConfig

	// Hooks used by the unit tests to assert that the configuration provided
	// to each handler is correct and return fake handlers.
	newWorkloadAPIServer func(workload.Config) workload_pb.SpiffeWorkloadAPIServer
	newSDSv3Server       func(sdsv3.Config) secret_v3.SecretDiscoveryServiceServer
	newHealthServer      func(healthv1.Config) grpc_health_v1.HealthServer
}
