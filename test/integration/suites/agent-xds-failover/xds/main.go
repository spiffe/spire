// Command xds-control-plane is a minimal xDS management server used by the
// agent-xds-failover integration suite. It serves a single, static ADS
// snapshot that steers a gRPC xDS client (the SPIRE agent) at two SPIRE
// servers using EDS locality priorities:
//
//	priority 0 -> spire-server-1   (preferred)
//	priority 1 -> spire-server-2   (failover)
//
// gRPC's priority load balancing policy uses priority 0 while it has a ready
// connection and falls over to priority 1 when priority 0 goes into
// TRANSIENT_FAILURE (i.e. the preferred server is down). This is exactly the
// "prefer the closest server, fail over to the other" behavior the suite
// verifies.
//
// The endpoint addresses in an EDS assignment must be IP addresses (gRPC does
// not DNS-resolve EDS endpoints), so the two server hostnames are resolved once
// at startup and baked into the snapshot. The suite only stop/starts the server
// containers (never recreates them), so their addresses are stable for the run.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// listenerName is the xDS listener (service) name. It must match the name
	// used in the agent's gRPC target ("xds:///spire-server").
	listenerName = "spire-server"
	routeName    = "spire-server-route"
	clusterName  = "spire-servers"

	// nodeID must match the "node.id" in the agent's xDS bootstrap.
	nodeID = "spire-agent"

	serverPort = 8081
	bindAddr   = ":18000"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("xds-control-plane: %v", err)
	}
}

func run() error {
	// The two upstream SPIRE servers, in priority order. Overridable for
	// flexibility, but the suite relies on the defaults.
	primary := envOr("PRIMARY_SERVER", "spire-server-1")
	secondary := envOr("SECONDARY_SERVER", "spire-server-2")

	primaryIP, err := resolve(primary)
	if err != nil {
		return err
	}
	secondaryIP, err := resolve(secondary)
	if err != nil {
		return err
	}
	log.Printf("resolved %s=%s (priority 0), %s=%s (priority 1)", primary, primaryIP, secondary, secondaryIP)

	snapshot, err := makeSnapshot(primaryIP, secondaryIP)
	if err != nil {
		return fmt.Errorf("building snapshot: %w", err)
	}

	snapshotCache := cachev3.NewSnapshotCache(true, cachev3.IDHash{}, nil)
	if err := snapshotCache.SetSnapshot(context.Background(), nodeID, snapshot); err != nil {
		return fmt.Errorf("setting snapshot: %w", err)
	}

	srv := serverv3.NewServer(context.Background(), snapshotCache, nil)
	grpcServer := grpc.NewServer()
	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(grpcServer, srv)

	lis, err := net.Listen("tcp", bindAddr) //nolint: gosec
	if err != nil {
		return fmt.Errorf("listening on %s: %w", bindAddr, err)
	}
	log.Printf("serving ADS on %s", bindAddr)
	return grpcServer.Serve(lis)
}

// makeSnapshot builds the static LDS/RDS/CDS/EDS resources. The EDS assignment
// places the primary server at priority 0 and the secondary at priority 1.
func makeSnapshot(primaryIP, secondaryIP string) (*cachev3.Snapshot, error) {
	router, err := anypb.New(&routerv3.Router{})
	if err != nil {
		return nil, err
	}

	hcm := &hcmv3.HttpConnectionManager{
		StatPrefix: "spire",
		RouteSpecifier: &hcmv3.HttpConnectionManager_Rds{
			Rds: &hcmv3.Rds{
				ConfigSource:    adsConfigSource(),
				RouteConfigName: routeName,
			},
		},
		HttpFilters: []*hcmv3.HttpFilter{{
			Name:       "envoy.filters.http.router",
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: router},
		}},
	}
	hcmAny, err := anypb.New(hcm)
	if err != nil {
		return nil, err
	}

	listener := &listenerv3.Listener{
		Name:        listenerName,
		ApiListener: &listenerv3.ApiListener{ApiListener: hcmAny},
	}

	route := &routev3.RouteConfiguration{
		Name: routeName,
		VirtualHosts: []*routev3.VirtualHost{{
			Name:    "spire",
			Domains: []string{listenerName, "*"},
			Routes: []*routev3.Route{{
				Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
				Action: &routev3.Route_Route{Route: &routev3.RouteAction{
					ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: clusterName},
				}},
			}},
		}},
	}

	cluster := &clusterv3.Cluster{
		Name:                 clusterName,
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_EDS},
		EdsClusterConfig:     &clusterv3.Cluster_EdsClusterConfig{EdsConfig: adsConfigSource()},
		LbPolicy:             clusterv3.Cluster_ROUND_ROBIN,
	}

	endpoints := &endpointv3.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpointv3.LocalityLbEndpoints{
			localityEndpoints(0, "dc1", primaryIP),
			localityEndpoints(1, "dc2", secondaryIP),
		},
	}

	return cachev3.NewSnapshot("1", map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ListenerType: {listener},
		resourcev3.RouteType:    {route},
		resourcev3.ClusterType:  {cluster},
		resourcev3.EndpointType: {endpoints},
	})
}

func localityEndpoints(priority uint32, zone, ip string) *endpointv3.LocalityLbEndpoints {
	return &endpointv3.LocalityLbEndpoints{
		Priority: priority,
		Locality: &corev3.Locality{Region: zone, Zone: zone},
		// gRPC's EDS parsing requires a non-zero locality weight.
		LoadBalancingWeight: wrapperspb.UInt32(1),
		LbEndpoints: []*endpointv3.LbEndpoint{{
			HostIdentifier: &endpointv3.LbEndpoint_Endpoint{Endpoint: &endpointv3.Endpoint{
				Address: &corev3.Address{Address: &corev3.Address_SocketAddress{
					SocketAddress: &corev3.SocketAddress{
						Address:       ip,
						PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: serverPort},
					},
				}},
			}},
		}},
	}
}

func adsConfigSource() *corev3.ConfigSource {
	return &corev3.ConfigSource{
		ResourceApiVersion:    corev3.ApiVersion_V3,
		ConfigSourceSpecifier: &corev3.ConfigSource_Ads{Ads: &corev3.AggregatedConfigSource{}},
	}
}

// resolve looks up the first IP for host, retrying for a while so the control
// plane can start alongside the servers.
func resolve(host string) (string, error) {
	deadline := time.Now().Add(60 * time.Second)
	for {
		addrs, err := net.LookupHost(host)
		if err == nil && len(addrs) > 0 {
			return addrs[0], nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("could not resolve %q: %w", host, err)
		}
		time.Sleep(time.Second)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
