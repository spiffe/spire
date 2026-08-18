package trustbundlesources

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	// Add auth providers so that kubeconfig files relying on them can be used
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	// DefaultConfigMapName is the ConfigMap consulted for the bootstrap trust
	// bundle when no name is configured. It matches the default written by the
	// server's k8sbundle notifier.
	DefaultConfigMapName = "spire-bundle"

	// DefaultConfigMapKey is the ConfigMap key consulted for the bootstrap
	// trust bundle when no key is configured.
	DefaultConfigMapKey = "bundle.crt"

	// serviceAccountNamespacePath is where Kubernetes projects the namespace
	// of the pod's service account.
	serviceAccountNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

	// configMapFetchTimeout bounds each trust bundle fetch from the Kubernetes
	// API server. The agent retries with backoff on failure.
	configMapFetchTimeout = time.Minute
)

// newKubeClient connects to the Kubernetes API server using the given
// kubeconfig file, or, when no path is given, using the ambient environment
// (in-cluster credentials, KUBECONFIG, or ~/.kube/config).
func newKubeClient(kubeConfigPath string) (kubernetes.Interface, error) {
	var config *rest.Config
	var err error
	if kubeConfigPath != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	} else {
		config, err = ctrl.GetConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("unable to load Kubernetes client config: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create Kubernetes client: %w", err)
	}
	return client, nil
}

// fetchTrustBundleFromConfigMap reads the trust bundle out of a ConfigMap via
// the Kubernetes API server. The ConfigMap does not need to live in the
// agent's own namespace, provided the agent's service account is granted get
// access to it.
func (b *Bundle) fetchTrustBundleFromConfigMap(cfg *ConfigMapConfig) ([]byte, error) {
	namespace := cfg.Namespace
	if namespace == "" {
		var err error
		namespace, err = loadServiceAccountNamespace(getServiceAccountNamespacePath())
		if err != nil {
			return nil, err
		}
	}

	b.log.Debug(fmt.Sprintf("Fetching trust bundle from Kubernetes ConfigMap %s/%s key %q", namespace, cfg.Name, cfg.Key))

	client, err := b.newKubeClient(cfg.KubeConfigPath)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), configMapFetchTimeout)
	defer cancel()

	configMap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, cfg.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to fetch trust bundle from ConfigMap %s/%s: %w", namespace, cfg.Name, err)
	}

	if data, ok := configMap.Data[cfg.Key]; ok {
		return []byte(data), nil
	}
	if data, ok := configMap.BinaryData[cfg.Key]; ok {
		return data, nil
	}

	return nil, fmt.Errorf("ConfigMap %s/%s does not contain key %q", namespace, cfg.Name, cfg.Key)
}

// loadServiceAccountNamespace returns the namespace the agent is running in,
// as projected by Kubernetes into the pod's service account directory.
func loadServiceAccountNamespace(path string) (string, error) {
	namespaceBytes, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("unable to determine the agent namespace from %s (set the namespace explicitly if the agent is not running in a pod): %w", path, err)
	}

	namespace := strings.TrimSpace(string(namespaceBytes))
	if namespace == "" {
		return "", fmt.Errorf("unable to determine the agent namespace: %s is empty", path)
	}
	return namespace, nil
}
