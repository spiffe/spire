package apiserver

import (
	"errors"

	k8s_auth "k8s.io/api/authentication/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client is a client for querying k8s API server
type Client interface {
	//GetNode returns the node name in which a given pod lives
	GetNode(namespace, podName string) (string, error)

	// ValidateToken queries k8s token review API and returns information about the given token
	ValidateToken(token string, audiences []string) (*k8s_auth.TokenReviewStatus, error)
}

type client struct {
	kubeConfigFilePath string
}

// New creates a new Client.
// There are two cases:
// - If a kubeConfigFilePath is provided, config is taken from that file -> use for clients running out of a k8s cluster
// - If not (empty kubeConfigFilePath), InClusterConfig is used          -> use for clients running in a k8s cluster
func New(kubeConfigFilePath string) Client {
	return &client{
		kubeConfigFilePath: kubeConfigFilePath,
	}
}

func (c *client) GetNode(namespace, podName string) (string, error) {
	// Reload config
	clientset, err := c.loadClient()
	if err != nil {
		return "", err
	}

	// Get pod
	pod, err := clientset.CoreV1().Pods(namespace).Get(podName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	if pod.Spec.NodeName == "" {
		return "", errors.New("empty node name")
	}

	return pod.Spec.NodeName, nil
}

func (c *client) ValidateToken(token string, audiences []string) (*k8s_auth.TokenReviewStatus, error) {
	// Reload config
	clientset, err := c.loadClient()
	if err != nil {
		return nil, err
	}

	// Create token review request
	req := &k8s_auth.TokenReview{
		Spec: k8s_auth.TokenReviewSpec{
			Token:     token,
			Audiences: audiences,
		},
	}

	// Do request
	resp, err := clientset.AuthenticationV1().TokenReviews().Create(req)
	if resp == nil {
		return nil, errors.New("token review API response is nil")
	}

	// Evaluate token review response (review server will populate TokenReview.Status field)
	if err != nil {
		return nil, err
	}

	if resp.Status.Error != "" {
		return nil, errors.New(resp.Status.Error)
	}

	return &resp.Status, nil
}

func (c *client) loadClient() (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error

	if c.kubeConfigFilePath == "" {
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", c.kubeConfigFilePath)
	}
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}
