package trustbundlesources

const (
	BundleFormatPEM    = "pem"
	BundleFormatSPIFFE = "spiffe"
	UseUnspecified     = 0
	UseBootstrap       = 1
	UseRebootstrap     = 2
)

type Config struct {
	InsecureBootstrap            bool
	TrustBundleFormat            string
	TrustBundlePath              string
	TrustBundleURL               string
	TrustBundleUnixSocket        string
	TrustBundleSpiffeWorkloadAPI string
	TrustBundleConfigMap         *ConfigMapConfig
	TrustDomain                  string
	ServerAddress                string
	ServerPort                   int
}

// ConfigMapConfig locates the Kubernetes ConfigMap holding the bootstrap trust
// bundle. Unlike a mounted ConfigMap volume, which is restricted to the pod's
// own namespace, reading over the API server allows the bundle to live in a
// single namespace and be shared with agents running elsewhere.
type ConfigMapConfig struct {
	// Namespace holding the ConfigMap. If empty, the agent's own namespace is
	// used, as reported by its service account.
	Namespace string

	// Name of the ConfigMap.
	Name string

	// Key within the ConfigMap holding the trust bundle.
	Key string

	// KubeConfigPath is the path to a kubeconfig file to connect to the API
	// server with. If empty, the connection is configured from the ambient
	// environment (in-cluster credentials, KUBECONFIG, or ~/.kube/config).
	KubeConfigPath string
}
