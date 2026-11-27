package k8sclustertrustbundle

import (
	"context"
	"errors"
	"fmt"

	certificatesv1api "k8s.io/api/certificates/v1"
	certificatesv1beta1api "k8s.io/api/certificates/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certificatesv1 "k8s.io/client-go/applyconfigurations/certificates/v1"
	certificatesv1beta1 "k8s.io/client-go/applyconfigurations/certificates/v1beta1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const clusterTrustBundlesResource = "clustertrustbundles"

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
	// ClusterTrustBundle is served in certificates.k8s.io/v1 since Kubernetes
	// 1.37. Kubernetes 1.33 to 1.36 serve it in v1beta1 when it is enabled.
	servesV1, err := c.servesClusterTrustBundles(ctx, certificatesv1api.SchemeGroupVersion.String())
	if err != nil {
		return err
	}
	if servesV1 {
		return c.applyV1(ctx, cluster, trustBundle)
	}

	servesV1beta1, err := c.servesClusterTrustBundles(ctx, certificatesv1beta1api.SchemeGroupVersion.String())
	if err != nil {
		return err
	}
	if servesV1beta1 {
		return c.applyV1beta1(ctx, cluster, trustBundle)
	}

	return errors.New("the API server does not serve ClusterTrustBundle in certificates.k8s.io/v1 or certificates.k8s.io/v1beta1")
}

func (c *k8sClient) servesClusterTrustBundles(ctx context.Context, groupVersion string) (bool, error) {
	resources, err := c.clientset.Discovery().ServerResourcesForGroupVersionWithContext(ctx, groupVersion)
	switch {
	case apierrors.IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("failed to discover resources in %s: %w", groupVersion, err)
	}

	for _, resource := range resources.APIResources {
		if resource.Name == clusterTrustBundlesResource {
			return true, nil
		}
	}
	return false, nil
}

func (c *k8sClient) applyV1(ctx context.Context, cluster *Cluster, trustBundle []byte) error {
	spec := certificatesv1.ClusterTrustBundleSpec().
		WithTrustBundle(string(trustBundle))
	if cluster.SignerName != "" {
		spec = spec.WithSignerName(cluster.SignerName)
	}

	_, err := c.clientset.CertificatesV1().
		ClusterTrustBundles().
		Apply(ctx, certificatesv1.
			ClusterTrustBundle(cluster.ClusterTrustBundleName).
			WithSpec(spec), applyOptions())
	return err
}

func (c *k8sClient) applyV1beta1(ctx context.Context, cluster *Cluster, trustBundle []byte) error {
	spec := certificatesv1beta1.ClusterTrustBundleSpec().
		WithTrustBundle(string(trustBundle))
	if cluster.SignerName != "" {
		spec = spec.WithSignerName(cluster.SignerName)
	}

	_, err := c.clientset.CertificatesV1beta1().
		ClusterTrustBundles().
		Apply(ctx, certificatesv1beta1.
			ClusterTrustBundle(cluster.ClusterTrustBundleName).
			WithSpec(spec), applyOptions())
	return err
}

func applyOptions() metav1.ApplyOptions {
	return metav1.ApplyOptions{
		FieldManager: fmt.Sprintf("spire-bundlepublisher-%s", pluginName),
		Force:        true,
	}
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
