package endpoints

import (
	"net"

	discovery_v2 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/sirupsen/logrus"
	workload_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv2"
	"github.com/spiffe/spire/pkg/agent/endpoints/sdsv3"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

type Config struct {
	BindAddr *net.UnixAddr

	Attestor attestor.Attestor

	Manager manager.Manager

	Log logrus.FieldLogger

	Metrics telemetry.Metrics

	// The TLS Certificate resource name to use for the default X509-SVID with Envoy SDS
	DefaultSVIDName string

	// The Validation Context resource name to use for the default X.509 bundle with Envoy SDS
	DefaultBundleName string

	// Hooks used by the unit tests to assert that the configuration provided
	// to each handler is correct and return fake handlers.
	newWorkloadAPIHandler func(workload.Config) workload_pb.SpiffeWorkloadAPIServer
	newSDSv2Handler       func(sdsv2.Config) discovery_v2.SecretDiscoveryServiceServer
	newSDSv3Handler       func(sdsv3.Config) secret_v3.SecretDiscoveryServiceServer
}
