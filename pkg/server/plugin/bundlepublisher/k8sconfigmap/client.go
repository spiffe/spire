package k8sconfigmap

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// kubernetesClient defines the interface for Kubernetes operations.
type kubernetesClient interface {
	// CreateConfigMap creates a new ConfigMap in the specified namespace.
	CreateConfigMap(ctx context.Context, configMap *corev1.ConfigMap) error

	// GetConfigMap retrieves a ConfigMap from the specified namespace.
	GetConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error)

	// UpdateConfigMap updates an existing ConfigMap.
	UpdateConfigMap(ctx context.Context, configMap *corev1.ConfigMap) error
}

// k8sClient implements the kubernetesClient interface.
type k8sClient struct {
	clientset kubernetes.Interface
}

// GetConfigMap retrieves a ConfigMap from the specified namespace.
func (c *k8sClient) GetConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error) {
	configMap, err := c.clientset.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Error(codes.NotFound, fmt.Sprintf("ConfigMap %s/%s not found", namespace, name))
		}
		return nil, err
	}
	return configMap, nil
}

// CreateConfigMap creates a new ConfigMap.
func (c *k8sClient) CreateConfigMap(ctx context.Context, configMap *corev1.ConfigMap) error {
	_, err := c.clientset.CoreV1().ConfigMaps(configMap.Namespace).Create(ctx, configMap, metav1.CreateOptions{})
	return err
}

// UpdateConfigMap updates an existing ConfigMap.
func (c *k8sClient) UpdateConfigMap(ctx context.Context, configMap *corev1.ConfigMap) error {
	_, err := c.clientset.CoreV1().ConfigMaps(configMap.Namespace).Update(ctx, configMap, metav1.UpdateOptions{})
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
