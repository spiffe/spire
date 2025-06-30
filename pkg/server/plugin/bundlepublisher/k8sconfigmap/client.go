package k8sconfigmap

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// kubernetesClient defines the interface for Kubernetes operations.
type kubernetesClient interface {
	// ApplyConfigMap applies a ConfigMap, creating it if it does not exist or updating it if it does.
	// If the ConfigMap already exists, it will be updated with the provided data.
	// If it does not exist, it will be created with the provided data.
	// This function uses the Apply method to ensure idempotency.
	ApplyConfigMap(ctx context.Context, cluster *Cluster, data []byte) error
}

// k8sClient implements the kubernetesClient interface.
type k8sClient struct {
	clientset kubernetes.Interface
}

func (c *k8sClient) ApplyConfigMap(ctx context.Context, cluster *Cluster, data []byte) error {
	_, err := c.clientset.CoreV1().
		ConfigMaps(cluster.Namespace).
		Apply(ctx, v1.
			ConfigMap(cluster.ConfigMapName, cluster.Namespace).
			WithData(map[string]string{cluster.ConfigMapKey: string(data)}), metav1.ApplyOptions{
			FieldManager: fmt.Sprintf("spire-bundlepublisher-%s", pluginName),
		})
	return err
}

// newK8sClient creates a new Kubernetes client based on the provided configuration.
func newK8sClient(kubeConfigPath string) (kubernetesClient, error) {
	kubeConfig, err := getKubeConfig(kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("error getting kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating Kubernetes client: %w", err)
	}

	return &k8sClient{
		clientset: clientset,
	}, nil
}

// getKubeConfig returns a Kubernetes configuration based on the provided path.
// If the path is empty, it uses the in-cluster configuration.
func getKubeConfig(configPath string) (*rest.Config, error) {
	if configPath != "" {
		return clientcmd.BuildConfigFromFlags("", configPath)
	}

	return rest.InClusterConfig()
}
