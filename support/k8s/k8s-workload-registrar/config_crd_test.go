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
	testMinimalCRDConfig = `
		trust_domain = "domain.test"
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
			TrustDomain:        "domain.test",
			Cluster:            "CLUSTER",
			LogLevel:           defaultLogLevel,
			Mode:               "crd",
			DisabledNamespaces: []string{"kube-system", "kube-public"},
			trustDomain:        spiffeid.RequireTrustDomainFromString("domain.test"),
		},
		AddSvcDNSName:              true,
		LeaderElectionResourceLock: defaultLeaderElectionResourceLock,
		MetricsBindAddr:            ":8080",
		PodController:              true,
		WebhookEnabled:             false,
		WebhookCertDir:             defaultWebhookCertDir,
		WebhookPort:                defaultWebhookPort,
		WebhookServiceName:         defaultWebhookServiceName,
		IdentityTemplate:           "IDENTITYTEMPLATE",
		DNSNameTemplates:           &[]string{defaultDNSTemplate},
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
					TrustDomain:        "domain.test",
					Cluster:            "CLUSTER",
					Mode:               "crd",
					DisabledNamespaces: []string{"kube-system", "kube-public"},
					trustDomain:        spiffeid.RequireTrustDomainFromString("domain.test"),
				},
				AddSvcDNSName:              true,
				LeaderElection:             false,
				LeaderElectionResourceLock: defaultLeaderElectionResourceLock,
				MetricsBindAddr:            ":8080",
				PodController:              true,
				WebhookEnabled:             false,
				WebhookCertDir:             defaultWebhookCertDir,
				WebhookPort:                defaultWebhookPort,
				WebhookServiceName:         defaultWebhookServiceName,
				IdentityTemplate:           "IDENTITYTEMPLATE",
				DNSNameTemplates:           &[]string{defaultDNSTemplate},
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
				trust_domain = "override-domain.test"
				cluster = "CLUSTEROVERRIDE"
				add_svc_dns_name = false
				leader_election = true
				leader_election_resource_lock = "leases"
				metrics_bind_addr = "addr"
				pod_controller = true
				webhook_enabled = false
				mode = "crd"
				identity_template = "IDENTITYTEMPLATE"
				dns_name_templates = ["DNSNAMETEMPLATE"]
			`,
			out: &CRDMode{
				CommonMode: CommonMode{
					LogLevel:           "LEVELOVERRIDE",
					LogPath:            "PATHOVERRIDE",
					ServerSocketPath:   "SOCKETPATHOVERRIDE",
					ServerAddress:      "unix://SOCKETPATHOVERRIDE",
					TrustDomain:        "override-domain.test",
					Cluster:            "CLUSTEROVERRIDE",
					Mode:               "crd",
					DisabledNamespaces: []string{"kube-system", "kube-public"},
					trustDomain:        spiffeid.RequireTrustDomainFromString("override-domain.test"),
				},
				AddSvcDNSName:              false,
				LeaderElection:             true,
				LeaderElectionResourceLock: "leases",
				MetricsBindAddr:            "addr",
				PodController:              true,
				WebhookEnabled:             false,
				WebhookCertDir:             defaultWebhookCertDir,
				WebhookPort:                defaultWebhookPort,
				WebhookServiceName:         defaultWebhookServiceName,
				IdentityTemplate:           "IDENTITYTEMPLATE",
				DNSNameTemplates:           &[]string{"DNSNAMETEMPLATE"},
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
					TrustDomain:        "domain.test",
					Cluster:            "CLUSTER",
					Mode:               "crd",
					DisabledNamespaces: []string{"kube-system", "kube-public"},
					trustDomain:        spiffeid.RequireTrustDomainFromString("domain.test"),
				},
				AddSvcDNSName:              true,
				LeaderElectionResourceLock: defaultLeaderElectionResourceLock,
				MetricsBindAddr:            ":8080",
				PodController:              true,
				WebhookCertDir:             defaultWebhookCertDir,
				WebhookPort:                defaultWebhookPort,
				WebhookServiceName:         defaultWebhookServiceName,
				IdentityTemplate:           "region/{{.Context.region}}/cluster_name/{{.Context.cluster_name}}/ns/{{.Pod.namespace}}/sa/{{.Pod.service_account}}",
				IdentityTemplateLabel:      "IDENTITYLABEL",
				Context: map[string]string{
					"region":       "EU-DE",
					"cluster_name": "CLUSTER",
				},
				DNSNameTemplates: &[]string{defaultDNSTemplate},
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
					TrustDomain:        "domain.test",
					Cluster:            "CLUSTER",
					Mode:               "crd",
					DisabledNamespaces: []string{"kube-system", "kube-public"},
					trustDomain:        spiffeid.RequireTrustDomainFromString("domain.test"),
				},
				AddSvcDNSName:              true,
				LeaderElectionResourceLock: defaultLeaderElectionResourceLock,
				MetricsBindAddr:            ":8080",
				PodController:              true,
				WebhookCertDir:             defaultWebhookCertDir,
				WebhookPort:                defaultWebhookPort,
				WebhookServiceName:         defaultWebhookServiceName,
				IdentityTemplate:           "IDENTITYTEMPLATE",
				Context: map[string]string{
					"cluster_name": "CLUSTER",
				},
				DNSNameTemplates: &[]string{defaultDNSTemplate},
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
					TrustDomain:        "domain.test",
					Cluster:            "CLUSTER",
					Mode:               "crd",
					DisabledNamespaces: []string{"kube-system", "kube-public"},
					trustDomain:        spiffeid.RequireTrustDomainFromString("domain.test"),
				},
				IdentityTemplate:           "ns/{{.Pod.namespace}}/sa/{{.Pod.service_account}}",
				AddSvcDNSName:              true,
				LeaderElectionResourceLock: defaultLeaderElectionResourceLock,
				MetricsBindAddr:            ":8080",
				PodController:              true,
				WebhookCertDir:             defaultWebhookCertDir,
				WebhookPort:                defaultWebhookPort,
				WebhookServiceName:         defaultWebhookServiceName,
				DNSNameTemplates:           &[]string{defaultDNSTemplate},
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
			name: "identity_template missing context (with space)",
			in: `
				trust_domain = "domain.test"
				server_socket_path = "SOCKETPATH"
				cluster = "CLUSTER"
				mode = "crd"
				identity_template = "region/{{ .Context.region}}"
			`,
			err: "identity_template references non-existing context",
		},
		{
			name: "identity_template missing context (without space)",
			in: `
				trust_domain = "domain.test"
				server_socket_path = "SOCKETPATH"
				cluster = "CLUSTER"
				mode = "crd"
				identity_template = "region/{{.Context.region}}"
			`,
			err: "identity_template references non-existing context",
		},
		{
			name: "dns_name_templates",
			in: testMinimalCRDConfig + `
				dns_name_templates = ["{{.Pod.ServiceAccount}}.{{.Pod.Namespace}}.svc", "{{.Pod.Name}}.svc"]
			`,
			out: &CRDMode{
				CommonMode: CommonMode{
					LogLevel:           "info",
					ServerSocketPath:   "SOCKETPATH",
					ServerAddress:      "unix://SOCKETPATH",
					TrustDomain:        "domain.test",
					Cluster:            "CLUSTER",
					Mode:               "crd",
					DisabledNamespaces: []string{"kube-system", "kube-public"},
					trustDomain:        spiffeid.RequireTrustDomainFromString("domain.test"),
				},
				AddSvcDNSName:              true,
				LeaderElectionResourceLock: defaultLeaderElectionResourceLock,
				MetricsBindAddr:            ":8080",
				PodController:              true,
				WebhookCertDir:             defaultWebhookCertDir,
				WebhookPort:                defaultWebhookPort,
				WebhookServiceName:         defaultWebhookServiceName,
				DNSNameTemplates:           &[]string{"{{.Pod.ServiceAccount}}.{{.Pod.Namespace}}.svc", "{{.Pod.Name}}.svc"},
			},
		},
		{
			name: "dns_name_templates empty",
			in: testMinimalCRDConfig + `
				dns_name_templates = []
			`,
			out: &CRDMode{
				CommonMode: CommonMode{
					LogLevel:           "info",
					ServerSocketPath:   "SOCKETPATH",
					ServerAddress:      "unix://SOCKETPATH",
					TrustDomain:        "domain.test",
					Cluster:            "CLUSTER",
					Mode:               "crd",
					DisabledNamespaces: []string{"kube-system", "kube-public"},
					trustDomain:        spiffeid.RequireTrustDomainFromString("domain.test"),
				},
				AddSvcDNSName:              true,
				LeaderElectionResourceLock: defaultLeaderElectionResourceLock,
				MetricsBindAddr:            ":8080",
				PodController:              true,
				WebhookCertDir:             defaultWebhookCertDir,
				WebhookPort:                defaultWebhookPort,
				WebhookServiceName:         defaultWebhookServiceName,
				DNSNameTemplates:           &[]string{},
			},
		},
		{
			name: "dns_name_templates missing context (with space)",
			in: `
				trust_domain = "domain.test"
				server_socket_path = "SOCKETPATH"
				cluster = "CLUSTER"
				mode = "crd"
				dns_name_templates = ["{{ .Context.namespace}}"]
			`,
			err: "dns_name_template references non-existing context",
		},
		{
			name: "dns_name_templates missing context (without space)",
			in: `
				trust_domain = "domain.test"
				server_socket_path = "SOCKETPATH"
				cluster = "CLUSTER"
				mode = "crd"
				dns_name_templates = ["{{.Context.namespace}}"]
			`,
			err: "dns_name_template references non-existing context",
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
