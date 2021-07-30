package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

var (
	testMinimalCRDConfig = `
		trust_domain = "TRUSTDOMAIN"
		cluster = "CLUSTER"
		server_socket_path = "SOCKETPATH"
		mode = "crd"
	`

	minimalWithTemplate = testMinimalCRDConfig + `
	identity_template = "IDENTITYTEMPLATE"
	`
)

func TestLoadModeCRD(t *testing.T) {
	require := require.New(t)

	dir := spiretest.TempDir(t)

	confPath := filepath.Join(dir, "test.conf")

	_, err := LoadMode(confPath)
	require.Error(err)
	require.Contains(err.Error(), "unable to load configuration:")

	err = os.WriteFile(confPath, []byte(minimalWithTemplate), 0600)
	require.NoError(err)

	config, err := LoadMode(confPath)
	require.NoError(err)

	require.Equal(&CRDMode{
		CommonMode: CommonMode{
			ServerSocketPath:   "SOCKETPATH",
			ServerAddress:      "unix://SOCKETPATH",
			TrustDomain:        "TRUSTDOMAIN",
			Cluster:            "CLUSTER",
			LogLevel:           defaultLogLevel,
			Mode:               "crd",
			DisabledNamespaces: []string{"kube-system", "kube-public"},
		},
		AddSvcDNSName:    true,
		MetricsBindAddr:  ":8080",
		PodController:    true,
		WebhookEnabled:   false,
		WebhookCertDir:   "/run/spire/serving-certs",
		WebhookPort:      9443,
		IdentityTemplate: "IDENTITYTEMPLATE",
	}, config)

	testCases := []struct {
		name string
		in   string
		out  *CRDMode
		err  string
	}{
		{
			name: "defaults",
			in:   minimalWithTemplate,
			out: &CRDMode{
				CommonMode: CommonMode{
					LogLevel:           defaultLogLevel,
					ServerSocketPath:   "SOCKETPATH",
					ServerAddress:      "unix://SOCKETPATH",
					TrustDomain:        "TRUSTDOMAIN",
					Cluster:            "CLUSTER",
					Mode:               "crd",
					DisabledNamespaces: []string{"kube-system", "kube-public"},
				},
				AddSvcDNSName:    true,
				LeaderElection:   false,
				MetricsBindAddr:  ":8080",
				PodController:    true,
				WebhookEnabled:   false,
				WebhookCertDir:   "/run/spire/serving-certs",
				WebhookPort:      9443,
				IdentityTemplate: "IDENTITYTEMPLATE",
			},
		},
		{
			name: "overrides",
			in: `
				log_level = "LEVELOVERRIDE"
				log_path = "PATHOVERRIDE"
				addr = ":1234"
				cert_path = "CERTOVERRIDE"
				key_path = "KEYOVERRIDE"
				cacert_path = "CACERTOVERRIDE"
				insecure_skip_client_verification = true
				server_socket_path = "SOCKETPATHOVERRIDE"
				trust_domain = "TRUSTDOMAINOVERRIDE"
				cluster = "CLUSTEROVERRIDE"
				add_svc_dns_name = false
				leader_election = false
				metrics_bind_addr = "addr"
				pod_controller = true
				webhook_enabled = false
				mode = "crd"
				identity_template = "IDENTITYTEMPLATE"
			`,
			out: &CRDMode{
				CommonMode: CommonMode{
					LogLevel:           "LEVELOVERRIDE",
					LogPath:            "PATHOVERRIDE",
					ServerSocketPath:   "SOCKETPATHOVERRIDE",
					ServerAddress:      "unix://SOCKETPATHOVERRIDE",
					TrustDomain:        "TRUSTDOMAINOVERRIDE",
					Cluster:            "CLUSTEROVERRIDE",
					Mode:               "crd",
					DisabledNamespaces: []string{"kube-system", "kube-public"},
				},
				AddSvcDNSName:    false,
				LeaderElection:   false,
				MetricsBindAddr:  "addr",
				PodController:    true,
				WebhookEnabled:   false,
				WebhookCertDir:   "/run/spire/serving-certs",
				WebhookPort:      9443,
				IdentityTemplate: "IDENTITYTEMPLATE",
			},
		},
		{
			name: "identity_template",
			in: testMinimalCRDConfig + `
				identity_template = "region/{{.Context.region}}/cluster_name/{{.Context.cluster_name}}/ns/{{.Pod.namespace}}/sa/{{.Pod.service_account}}"
				identity_template_label = "IDENTITYLABEL"
				context {
					region = "EU-DE"
					cluster_name = "CLUSTER"
				}
			`,
			out: &CRDMode{
				CommonMode: CommonMode{
					LogLevel:           "info",
					ServerSocketPath:   "SOCKETPATH",
					ServerAddress:      "unix://SOCKETPATH",
					TrustDomain:        "TRUSTDOMAIN",
					Cluster:            "CLUSTER",
					Mode:               "crd",
					DisabledNamespaces: []string{"kube-system", "kube-public"},
				},
				AddSvcDNSName:         true,
				MetricsBindAddr:       ":8080",
				PodController:         true,
				WebhookCertDir:        "/run/spire/serving-certs",
				WebhookPort:           9443,
				IdentityTemplate:      "region/{{.Context.region}}/cluster_name/{{.Context.cluster_name}}/ns/{{.Pod.namespace}}/sa/{{.Pod.service_account}}",
				IdentityTemplateLabel: "IDENTITYLABEL",
				Context: map[string]string{
					"region":       "EU-DE",
					"cluster_name": "CLUSTER",
				},
			},
		},
		{
			name: "identity_template_minimal",
			in: testMinimalCRDConfig + `
			identity_template = "region/{{.Context.region}}/cluster_name/{{.Context.cluster_name}}/ns/{{.Pod.namespace}}/sa/{{.Pod.service_account}}"
			identity_template = "IDENTITYTEMPLATE"
			context {
				cluster_name = "CLUSTER"
			}
			`,
			out: &CRDMode{
				CommonMode: CommonMode{
					LogLevel:           "info",
					ServerSocketPath:   "SOCKETPATH",
					ServerAddress:      "unix://SOCKETPATH",
					TrustDomain:        "TRUSTDOMAIN",
					Cluster:            "CLUSTER",
					Mode:               "crd",
					DisabledNamespaces: []string{"kube-system", "kube-public"},
				},
				AddSvcDNSName:    true,
				MetricsBindAddr:  ":8080",
				PodController:    true,
				WebhookCertDir:   "/run/spire/serving-certs",
				WebhookPort:      9443,
				IdentityTemplate: "IDENTITYTEMPLATE",
				Context: map[string]string{
					"cluster_name": "CLUSTER",
				},
			},
		},
		{
			name: "identity_template no context",
			in: testMinimalCRDConfig + `
				identity_template = "ns/{{.Pod.namespace}}/sa/{{.Pod.service_account}}"
			`,
			out: &CRDMode{
				CommonMode: CommonMode{
					LogLevel:           "info",
					ServerSocketPath:   "SOCKETPATH",
					ServerAddress:      "unix://SOCKETPATH",
					TrustDomain:        "TRUSTDOMAIN",
					Cluster:            "CLUSTER",
					Mode:               "crd",
					DisabledNamespaces: []string{"kube-system", "kube-public"},
				},
				IdentityTemplate: "ns/{{.Pod.namespace}}/sa/{{.Pod.service_account}}",
				AddSvcDNSName:    true,
				MetricsBindAddr:  ":8080",
				PodController:    true,
				WebhookCertDir:   "/run/spire/serving-certs",
				WebhookPort:      9443,
			},
		},
		{
			name: "bad HCL",
			in:   `INVALID`,
			err:  "unable to decode configuration",
		},
		{
			name: "identity_template and pod_label",
			in: testMinimalCRDConfig + `
				pod_label = "PODLABEL"
				identity_template = "IDENTITYTEMPLATE"
				identity_template_label = "IDENTITYLABEL"
				context {
					cluster_name = "CLUSTER"
				}
			`,
			err: "workload registration configuration is incorrect, can only use one of identity_template, pod_annotation, or pod_label",
		},
		{
			name: "identity_template and pod_annotation",
			in: testMinimalCRDConfig + `
				pod_annotation = "PODANNOTATION"
				identity_template = "IDENTITYTEMPLATE"
				context {
					region = "EU-DE"
					cluster_name = "MYCLUSTER"
				}
			`,
			err: "workload registration configuration is incorrect, can only use one of identity_template, pod_annotation, or pod_label",
		},
		{
			name: "missing context 1",
			in: `
				trust_domain = "TRUSTDOMAIN"
				server_socket_path = "SOCKETPATH"
				cluster = "CLUSTER"
				mode = "crd"
				identity_template = "region/{{ .Context.region}}"
			`,
			err: "identity_template references non-existing context",
		},
		{
			name: "missing context 2",
			in: `
				trust_domain = "TRUSTDOMAIN"
				server_socket_path = "SOCKETPATH"
				cluster = "CLUSTER"
				mode = "crd"
				identity_template = "region/{{.Context.region}}"
			`,
			err: "identity_template references non-existing context",
		},
		{
			name: "invalid identity_template",
			in: `
				trust_domain = "TRUSTDOMAIN"
				server_socket_path = "SOCKETPATH"
				cluster = "CLUSTER"
				mode = "crd"
				identity_template = "spiffe://TRUSTDOMAIN/region"
			`,
			err: "identity_template cannot start with spiffe:// or /",
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
