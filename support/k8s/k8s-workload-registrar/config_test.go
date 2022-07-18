package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

var (
	testMinimalConfig = `
		trust_domain = "domain.test"
		cluster = "CLUSTER"
		server_socket_path = "SOCKETPATH"
		mode = "reconcile"
`
)

func TestLoadMode(t *testing.T) {
	require := require.New(t)

	dir := spiretest.TempDir(t)

	confPath := filepath.Join(dir, "test.conf")

	_, err := LoadMode(confPath)
	require.Error(err)
	require.Contains(err.Error(), "unable to load configuration:")

	err = os.WriteFile(confPath, []byte(testMinimalConfig), 0600)
	require.NoError(err)

	config, err := LoadMode(confPath)
	require.NoError(err)

	require.Equal(&ReconcileMode{
		CommonMode: CommonMode{
			ServerSocketPath:   "SOCKETPATH",
			ServerAddress:      "unix://SOCKETPATH",
			TrustDomain:        "domain.test",
			Cluster:            "CLUSTER",
			LogLevel:           defaultLogLevel,
			Mode:               "reconcile",
			DisabledNamespaces: []string{"kube-system", "kube-public"},
			trustDomain:        spiffeid.RequireTrustDomainFromString("domain.test"),
		},
		ControllerName:             "spire-k8s-registrar",
		ClusterDNSZone:             "cluster.local",
		LeaderElectionResourceLock: "leases",
		MetricsAddr:                ":8080",
	}, config)

	testCases := []struct {
		name string
		in   string
		out  *ReconcileMode
		err  string
	}{
		{
			name: "defaults",
			in:   testMinimalConfig,
			out: &ReconcileMode{
				CommonMode: CommonMode{
					LogLevel:           defaultLogLevel,
					ServerSocketPath:   "SOCKETPATH",
					ServerAddress:      "unix://SOCKETPATH",
					TrustDomain:        "domain.test",
					Cluster:            "CLUSTER",
					Mode:               "reconcile",
					DisabledNamespaces: []string{"kube-system", "kube-public"},
					trustDomain:        spiffeid.RequireTrustDomainFromString("domain.test"),
				},
				ControllerName:             "spire-k8s-registrar",
				ClusterDNSZone:             "cluster.local",
				LeaderElectionResourceLock: "leases",
				MetricsAddr:                ":8080",
			},
		},
		{
			name: "overrides",
			in: `
				mode = "reconcile"
				log_level = "LEVELOVERRIDE"
				log_path = "PATHOVERRIDE"
				server_socket_path = "SOCKETPATHOVERRIDE"
				trust_domain = "domain.test"
				cluster = "CLUSTEROVERRIDE"
				pod_label = "PODLABEL"
				controller_name = "override"
				cluster_dns_zone = "override.local"
				leader_election_resource_lock = "endpointsleases"
				metrics_addr = ":8081"
			`,
			out: &ReconcileMode{
				CommonMode: CommonMode{
					LogLevel:           "LEVELOVERRIDE",
					LogPath:            "PATHOVERRIDE",
					ServerSocketPath:   "SOCKETPATHOVERRIDE",
					ServerAddress:      "unix://SOCKETPATHOVERRIDE",
					TrustDomain:        "domain.test",
					Cluster:            "CLUSTEROVERRIDE",
					PodLabel:           "PODLABEL",
					Mode:               "reconcile",
					DisabledNamespaces: []string{"kube-system", "kube-public"},
					trustDomain:        spiffeid.RequireTrustDomainFromString("domain.test"),
				},
				ControllerName:             "override",
				ClusterDNSZone:             "override.local",
				LeaderElectionResourceLock: "endpointsleases",
				MetricsAddr:                ":8081",
			},
		},
		{
			name: "bad HCL",
			in:   `INVALID`,
			err:  "unable to decode configuration",
		},
		{
			name: "missing server_socket_path/address",
			in: `
				trust_domain = "domain.test"
				cluster = "CLUSTER"
			`,
			err: "server_address or server_socket_path must be specified",
		},
		{
			name: "missing trust domain",
			in: `
				cluster = "CLUSTER"
				server_socket_path = "SOCKETPATH"
			`,
			err: "trust_domain must be specified",
		},
		{
			name: "missing cluster",
			in: `
				trust_domain = "domain.test"
				server_socket_path = "SOCKETPATH"
			`,
			err: "cluster must be specified",
		},
		{
			name: "workload registration mode specification is incorrect",
			in: testMinimalConfig + `
				pod_label = "PODLABEL"
				pod_annotation = "PODANNOTATION"
			`,
			err: "workload registration mode specification is incorrect, can't specify both pod_label and pod_annotation",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase // alias loop variable as it is used in the closure
		t.Run(testCase.name, func(t *testing.T) {
			err := os.WriteFile(confPath, []byte(testCase.in), 0600)
			require.NoError(err)

			actual, err := LoadMode(confPath)
			if testCase.err != "" {
				require.Error(err)
				require.Contains(err.Error(), testCase.err)
				return
			}
			require.NoError(err)
			require.Equal(testCase.out, actual)
		})
	}
}
