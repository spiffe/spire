package k8sclustertrustbundle

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certificatesv1 "k8s.io/client-go/applyconfigurations/certificates/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// kubernetesClient defines the interface for Kubernetes operations.
type kubernetesClient interface {
	// ApplyClusterTrustBundle applies a ClusterTrustBundle, creating it if it
	// does not exist or updating it with the provided trust bundle if it does.
	ApplyClusterTrustBundle(ctx context.Context, cluster *Cluster, trustBundle []byte) error
}

// k8sClient implements the kubernetesClient interface.
type k8sClient struct {
	clientset kubernetes.Interface
}

func (c *k8sClient) ApplyClusterTrustBundle(ctx context.Context, cluster *Cluster, trustBundle []byte) error {
	spec := certificatesv1.ClusterTrustBundleSpec().
		WithTrustBundle(string(trustBundle))
	if cluster.SignerName != "" {
		spec = spec.WithSignerName(cluster.SignerName)
	}

	_, err := c.clientset.CertificatesV1().
		ClusterTrustBundles().
		Apply(ctx, certificatesv1.
			ClusterTrustBundle(cluster.ClusterTrustBundleName).
			WithSpec(spec), metav1.ApplyOptions{
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
