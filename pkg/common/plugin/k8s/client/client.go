package client

import (
	"sync"

	"github.com/kubernetes/client-go/kubernetes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// K8SClient is a client for querying k8s API server
type K8SClient interface {
	//GetNode returns the node name in which a given pod lives
	GetNode(namespace, podName string) (string, error)
}

type k8sClient struct {
	kubeConfigFilePath string
	clientset          *kubernetes.Clientset
	mu                 sync.RWMutex
}

// NewK8SClient creates a new K8SClient.
// There are two cases:
// - If a kubeConfigFilePath is provided, config is taken from that file -> use for clients running out of a k8s cluster
// - If not (empty kubeConfigFilePath), InClusterConfig is used          -> use for clients running in a k8s cluster
func NewK8SClient(kubeConfigFilePath string) K8SClient {
	return &k8sClient{
		kubeConfigFilePath: kubeConfigFilePath,
	}
}

func (c *k8sClient) GetNode(namespace, podName string) (string, error) {
	// Reload config
	err := c.reloadConfig()
	if err != nil {
		return "", err
	}

	// Get pod
	pod, err := c.clientset.CoreV1().Pods(namespace).Get(podName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	return pod.Spec.NodeName, nil
}

func (c *k8sClient) reloadConfig() error {
	var config *rest.Config
	var err error

	if c.kubeConfigFilePath == "" {
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", c.kubeConfigFilePath)
	}
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.clientset = clientset

	return nil
}
