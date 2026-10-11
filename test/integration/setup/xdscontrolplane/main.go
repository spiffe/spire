// Command xds-control-plane is a minimal xDS management server used by the
// agent-xds-failover integration suite. It serves an ADS snapshot that steers
// a gRPC xDS client (the SPIRE agent) at two SPIRE servers using EDS locality
// priorities:
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
// not DNS-resolve EDS endpoints), so the two server hostnames are resolved
// periodically and a new snapshot is pushed whenever an address changes. Docker
// may assign a new IP when a stopped container is started again.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
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
	"google.golang.org/grpc/credentials"
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

	certFile = "/opt/xds/conf/xds.crt.pem"
	keyFile  = "/opt/xds/conf/xds.key.pem"

	// SPIRE server hostnames, in priority order.
	primary   = "spire-server-1"
	secondary = "spire-server-2"

	resolveInterval = time.Second
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("xds-control-plane: %v", err)
	}
}

func run() error {
	primaryIP, err := resolve(primary)
	if err != nil {
		return err
	}
	secondaryIP, err := resolve(secondary)
	if err != nil {
		return err
	}

	snapshotCache := cachev3.NewSnapshotCache(true, cachev3.IDHash{}, nil)
	version := 1
	if err := setSnapshot(snapshotCache, version, primaryIP, secondaryIP); err != nil {
		return err
	}

	go func() {
		for range time.Tick(resolveInterval) {
			// Keep the last known IP when a lookup fails: a stopped container
			// drops out of DNS, and its stale endpoint is what failover expects.
			newPrimaryIP := lookup(primary, primaryIP)
			newSecondaryIP := lookup(secondary, secondaryIP)
			if newPrimaryIP == primaryIP && newSecondaryIP == secondaryIP {
				continue
			}
			if err := setSnapshot(snapshotCache, version+1, newPrimaryIP, newSecondaryIP); err != nil {
				log.Printf("updating snapshot: %v", err)
				continue
			}
			version++
			primaryIP, secondaryIP = newPrimaryIP, newSecondaryIP
		}
	}()

	srv := serverv3.NewServer(context.Background(), snapshotCache, nil)
	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("loading TLS credentials: %w", err)
	}
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(grpcServer, srv)

	lis, err := net.Listen("tcp", bindAddr) //nolint: gosec
	if err != nil {
		return fmt.Errorf("listening on %s: %w", bindAddr, err)
	}
	log.Printf("serving ADS on %s", bindAddr)
	return grpcServer.Serve(lis)
}

func setSnapshot(snapshotCache cachev3.SnapshotCache, version int, primaryIP, secondaryIP string) error {
	snapshot, err := makeSnapshot(strconv.Itoa(version), primaryIP, secondaryIP)
	if err != nil {
		return fmt.Errorf("building snapshot: %w", err)
	}
	if err := snapshotCache.SetSnapshot(context.Background(), nodeID, snapshot); err != nil {
		return fmt.Errorf("setting snapshot: %w", err)
	}
	log.Printf("snapshot version %d: %s=%s (priority 0), %s=%s (priority 1)", version, primary, primaryIP, secondary, secondaryIP)
	return nil
}

// makeSnapshot builds the LDS/RDS/CDS/EDS resources. The EDS assignment
// places the primary server at priority 0 and the secondary at priority 1.
func makeSnapshot(version, primaryIP, secondaryIP string) (*cachev3.Snapshot, error) {
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

	return cachev3.NewSnapshot(version, map[resourcev3.Type][]cachetypes.Resource{
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
		if ip := lookup(host, ""); ip != "" {
			return ip, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("could not resolve %q", host)
		}
		time.Sleep(time.Second)
	}
}

// lookup returns the first IP for host, or fallback if it can't be resolved.
func lookup(host, fallback string) string {
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return fallback
	}
	return addrs[0]
}
