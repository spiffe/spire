package apiserver

import (
	"context"
	"errors"
	"fmt"

	authv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client is a client for querying k8s API server
type Client interface {
	// GetNode returns the node object for the given node name
	GetNode(ctx context.Context, nodeName string) (*v1.Node, error)

	// GetPod returns the pod object for the given pod name and namespace
	GetPod(ctx context.Context, namespace, podName string) (*v1.Pod, error)

	// ValidateToken queries k8s token review API and returns information about the given token
	ValidateToken(ctx context.Context, token string, audiences []string) (*authv1.TokenReviewStatus, error)
}

type client struct {
	kubeConfigFilePath string

	// loadClientHook is used to inject a fake loadClient on tests
	loadClientHook func(string) (kubernetes.Interface, error)
}

// New creates a new Client.
// There are two cases:
// - If a kubeConfigFilePath is provided, config is taken from that file -> use for clients running out of a k8s cluster
// - If not (empty kubeConfigFilePath), InClusterConfig is used          -> use for clients running in a k8s cluster
func New(kubeConfigFilePath string) Client {
	return &client{
		kubeConfigFilePath: kubeConfigFilePath,
		loadClientHook:     loadClient,
	}
}

func (c *client) GetPod(ctx context.Context, namespace, podName string) (*v1.Pod, error) {
	// Validate inputs
	if namespace == "" {
		return nil, errors.New("empty namespace")
	}
	if podName == "" {
		return nil, errors.New("empty pod name")
	}

	// Reload config
	clientset, err := c.loadClientHook(c.kubeConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to get clientset: %v", err)
	}

	// Get pod
	pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to query pods API: %v", err)
	}

	if pod == nil {
		return nil, fmt.Errorf("got nil pod for pod name: %v", podName)
	}

	return pod, nil
}

func (c *client) GetNode(ctx context.Context, nodeName string) (*v1.Node, error) {
	// Validate inputs
	if nodeName == "" {
		return nil, errors.New("empty node name")
	}

	// Reload config
	clientset, err := c.loadClientHook(c.kubeConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to get clientset: %v", err)
	}

	// Get node
	node, err := clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to query nodes API: %v", err)
	}

	if node == nil {
		return nil, fmt.Errorf("got nil node for node name: %v", nodeName)
	}

	return node, nil
}

func (c *client) ValidateToken(ctx context.Context, token string, audiences []string) (*authv1.TokenReviewStatus, error) {
	// Reload config
	clientset, err := c.loadClientHook(c.kubeConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to get clientset: %v", err)
	}

	// Create token review request
	req := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     token,
			Audiences: audiences,
		},
	}

	// Do request
	resp, err := clientset.AuthenticationV1().TokenReviews().Create(ctx, req, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to query token review API: %v", err)
	}

	// Evaluate token review response (review server will populate TokenReview.Status field)
	if resp == nil {
		return nil, errors.New("token review API response is nil")
	}

	if resp.Status.Error != "" {
		return nil, fmt.Errorf("token review API response contains an error: %v", resp.Status.Error)
	}

	return &resp.Status, nil
}

func loadClient(kubeConfigFilePath string) (kubernetes.Interface, error) {
	var config *rest.Config
	var err error

	if kubeConfigFilePath == "" {
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeConfigFilePath)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to create client config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create clientset for the given config: %v", err)
	}

	return clientset, nil
}
