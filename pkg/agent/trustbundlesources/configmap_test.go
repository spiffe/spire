package trustbundlesources

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetBundleFromConfigMap(t *testing.T) {
	testTrustBundlePEM, err := os.ReadFile(path.Join(util.ProjectRoot(), "conf/agent/dummy_root_ca.crt"))
	require.NoError(t, err)

	const testTBSPIFFE = `{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-384",
            "x": "WjB-nSGSxIYiznb84xu5WGDZj80nL7W1c3zf48Why0ma7Y7mCBKzfQkrgDguI4j0",
            "y": "Z-0_tDH_r8gtOtLLrIpuMwWHoe4vbVBFte1vj6Xt6WeE8lXwcCvLs_mcmvPqVK9j",
            "x5c": [
                "MIIBzDCCAVOgAwIBAgIJAJM4DhRH0vmuMAoGCCqGSM49BAMEMB4xCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZTUElGRkUwHhcNMTgwNTEzMTkzMzQ3WhcNMjMwNTEyMTkzMzQ3WjAeMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGU1BJRkZFMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWjB+nSGSxIYiznb84xu5WGDZj80nL7W1c3zf48Why0ma7Y7mCBKzfQkrgDguI4j0Z+0/tDH/r8gtOtLLrIpuMwWHoe4vbVBFte1vj6Xt6WeE8lXwcCvLs/mcmvPqVK9jo10wWzAdBgNVHQ4EFgQUh6XzV6LwNazA+GTEVOdu07o5yOgwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwGQYDVR0RBBIwEIYOc3BpZmZlOi8vbG9jYWwwCgYIKoZIzj0EAwQDZwAwZAIwE4Me13qMC9i6Fkx0h26y09QZIbuRqA9puLg9AeeAAyo5tBzRl1YL0KNEp02VKSYJAjBdeJvqjJ9wW55OGj1JQwDFD7kWeEB6oMlwPbI/5hEY3azJi16I0uN1JSYTSWGSqWc="
            ]
        }
    ]
}`

	newConfigMap := func(namespace, name string, data map[string]string, binaryData map[string][]byte) *corev1.ConfigMap {
		return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Data:       data,
			BinaryData: binaryData,
		}
	}

	cases := []struct {
		msg            string
		configMap      *corev1.ConfigMap
		clientErr      error
		namespace      string
		name           string
		key            string
		format         string
		expectErr      string
		expectNumCerts int
	}{
		{
			msg:            "pem bundle",
			configMap:      newConfigMap("spire-server", "spire-bundle", map[string]string{"bundle.crt": string(testTrustBundlePEM)}, nil),
			namespace:      "spire-server",
			name:           "spire-bundle",
			key:            "bundle.crt",
			format:         BundleFormatPEM,
			expectNumCerts: 1,
		},
		{
			msg:            "spiffe bundle",
			configMap:      newConfigMap("spire-server", "spire-bundle", map[string]string{"bundle.spiffe": testTBSPIFFE}, nil),
			namespace:      "spire-server",
			name:           "spire-bundle",
			key:            "bundle.spiffe",
			format:         BundleFormatSPIFFE,
			expectNumCerts: 1,
		},
		{
			msg:            "bundle in binary data",
			configMap:      newConfigMap("spire-server", "spire-bundle", nil, map[string][]byte{"bundle.crt": testTrustBundlePEM}),
			namespace:      "spire-server",
			name:           "spire-bundle",
			key:            "bundle.crt",
			format:         BundleFormatPEM,
			expectNumCerts: 1,
		},
		{
			msg:       "wrong format",
			configMap: newConfigMap("spire-server", "spire-bundle", map[string]string{"bundle.crt": string(testTrustBundlePEM)}, nil),
			namespace: "spire-server",
			name:      "spire-bundle",
			key:       "bundle.crt",
			format:    BundleFormatSPIFFE,
			expectErr: "unable to parse SPIFFE trust bundle",
		},
		{
			msg:       "key not in config map",
			configMap: newConfigMap("spire-server", "spire-bundle", map[string]string{"bundle.crt": string(testTrustBundlePEM)}, nil),
			namespace: "spire-server",
			name:      "spire-bundle",
			key:       "other.crt",
			format:    BundleFormatPEM,
			expectErr: `ConfigMap spire-server/spire-bundle does not contain key "other.crt"`,
		},
		{
			msg:       "config map does not exist",
			configMap: newConfigMap("spire-server", "other-bundle", map[string]string{"bundle.crt": string(testTrustBundlePEM)}, nil),
			namespace: "spire-server",
			name:      "spire-bundle",
			key:       "bundle.crt",
			format:    BundleFormatPEM,
			expectErr: "unable to fetch trust bundle from ConfigMap spire-server/spire-bundle",
		},
		{
			msg:       "config map in another namespace",
			configMap: newConfigMap("other-namespace", "spire-bundle", map[string]string{"bundle.crt": string(testTrustBundlePEM)}, nil),
			namespace: "spire-server",
			name:      "spire-bundle",
			key:       "bundle.crt",
			format:    BundleFormatPEM,
			expectErr: "unable to fetch trust bundle from ConfigMap spire-server/spire-bundle",
		},
		{
			msg:       "empty bundle",
			configMap: newConfigMap("spire-server", "spire-bundle", map[string]string{"bundle.crt": ""}, nil),
			namespace: "spire-server",
			name:      "spire-bundle",
			key:       "bundle.crt",
			format:    BundleFormatPEM,
			expectErr: "no PEM blocks",
		},
		{
			msg:       "unable to build client",
			clientErr: errors.New("no kubeconfig available"),
			namespace: "spire-server",
			name:      "spire-bundle",
			key:       "bundle.crt",
			format:    BundleFormatPEM,
			expectErr: "no kubeconfig available",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.msg, func(t *testing.T) {
			c := Config{
				TrustBundleFormat: testCase.format,
				TrustBundleConfigMap: &ConfigMapConfig{
					Namespace:      testCase.namespace,
					Name:           testCase.name,
					Key:            testCase.key,
					KubeConfigPath: "/not/a/real/kubeconfig",
				},
			}

			log, _ := test.NewNullLogger()
			tbs := New(&c, log)

			var kubeConfigPath string
			tbs.newKubeClient = func(path string) (kubernetes.Interface, error) {
				kubeConfigPath = path
				if testCase.clientErr != nil {
					return nil, testCase.clientErr
				}
				return fake.NewClientset(testCase.configMap), nil
			}

			tbs.SetMetrics(&telemetry.Blackhole{})
			require.NoError(t, tbs.SetStorage(openStorage(t, spiretest.TempDir(t))))

			trustBundle, insecureBootstrap, err := tbs.GetBundle()
			require.Equal(t, "/not/a/real/kubeconfig", kubeConfigPath)
			if testCase.expectErr != "" {
				require.ErrorContains(t, err, testCase.expectErr)
				return
			}
			require.NoError(t, err)
			require.False(t, insecureBootstrap)
			require.Len(t, trustBundle, testCase.expectNumCerts)
		})
	}
}

func TestGetBundleFromConfigMapDefaultsToOwnNamespace(t *testing.T) {
	// The namespace is left unset in the config, so it has to be resolved from
	// the service account. Nothing has projected one here, so the fetch fails
	// with an actionable error rather than querying an arbitrary namespace.
	c := Config{
		TrustBundleFormat: BundleFormatPEM,
		TrustBundleConfigMap: &ConfigMapConfig{
			Name: DefaultConfigMapName,
			Key:  DefaultConfigMapKey,
		},
	}

	log, _ := test.NewNullLogger()
	tbs := New(&c, log)
	tbs.newKubeClient = func(string) (kubernetes.Interface, error) {
		t.Fatal("client should not be built before the namespace is resolved")
		return nil, nil
	}
	tbs.SetMetrics(&telemetry.Blackhole{})
	require.NoError(t, tbs.SetStorage(openStorage(t, spiretest.TempDir(t))))

	_, _, err := tbs.GetBundle()
	require.ErrorContains(t, err, "unable to determine the agent namespace")
}

func TestLoadServiceAccountNamespace(t *testing.T) {
	dir := spiretest.TempDir(t)

	t.Run("namespace file present", func(t *testing.T) {
		namespacePath := filepath.Join(dir, "namespace")
		require.NoError(t, os.WriteFile(namespacePath, []byte("spire-agents\n"), 0o600))

		namespace, err := loadServiceAccountNamespace(namespacePath)
		require.NoError(t, err)
		require.Equal(t, "spire-agents", namespace)
	})

	t.Run("namespace file empty", func(t *testing.T) {
		namespacePath := filepath.Join(dir, "empty-namespace")
		require.NoError(t, os.WriteFile(namespacePath, []byte("  \n"), 0o600))

		_, err := loadServiceAccountNamespace(namespacePath)
		require.ErrorContains(t, err, "is empty")
	})

	t.Run("namespace file missing", func(t *testing.T) {
		_, err := loadServiceAccountNamespace(filepath.Join(dir, "doesnotexist"))
		require.ErrorContains(t, err, "unable to determine the agent namespace")
	})
}

func TestGetServiceAccountNamespacePath(t *testing.T) {
	require.NotEmpty(t, getServiceAccountNamespacePath())
}
