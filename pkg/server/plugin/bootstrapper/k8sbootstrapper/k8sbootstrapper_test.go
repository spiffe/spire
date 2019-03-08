package k8sbootstrapper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/bootstrapper"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	testBundle = &common.Bundle{
		RootCas: []*common.Certificate{
			{DerBytes: []byte("FOO")},
			{DerBytes: []byte("BAR")},
		},
	}

	testDefaultConfigMap = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "spire",
			Name:      "spire-bootstrap",
		},
	}
)

const (
	// PEM encoding of the root CAs in testBundle
	testBundleData = "-----BEGIN CERTIFICATE-----\nRk9P\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nQkFS\n-----END CERTIFICATE-----\n"
)

func TestPublishBundleFailsIfNotConfigured(t *testing.T) {
	p := bootstrapper.NewBuiltIn(New())

	stream, err := p.PublishBundle(context.Background())
	require.NoError(t, err)
	require.NotNil(t, stream)

	resp, err := stream.Recv()
	require.EqualError(t, err, "k8s-bootstrapper: not configured")
	require.Nil(t, resp)
}

func TestPublishBundleWhenCannotCreateClient(t *testing.T) {
	stream := openPublishBundleStream(t, "", func(configPath string) (kubeClient, error) {
		return nil, errors.New("unable to create client")
	})

	resp, err := stream.Recv()
	require.EqualError(t, err, "unable to create client")
	require.Nil(t, resp)
}

func TestPublishBundleConfigMapGetFailure(t *testing.T) {
	stream := openPublishBundleStream(t, "", func(string) (kubeClient, error) {
		return newFakeClient(), nil
	})

	resp, err := stream.Recv()
	require.EqualError(t, err, "k8s-bootstrapper: unable to get config map spire/spire-bootstrap: not found")
	require.Nil(t, resp)
}

func TestPublishBundleFailsIfRequestMissingBundle(t *testing.T) {
	stream := openPublishBundleStream(t, "", func(string) (kubeClient, error) {
		return newFakeClient(testDefaultConfigMap), nil
	})

	// wait for the plugin to fetch the config map
	resp, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, &bootstrapper.PublishBundleResponse{}, resp)

	// send a request without the bundle
	require.NoError(t, stream.Send(&bootstrapper.PublishBundleRequest{}))

	// assert the plugin aborts if the bundle is missing
	resp, err = stream.Recv()
	require.EqualError(t, err, "k8s-bootstrapper: request missing bundle")
	require.Nil(t, resp)
}

func TestPublishBundleConfigMapUpdateFailure(t *testing.T) {
	stream := openPublishBundleStream(t, "", func(string) (kubeClient, error) {
		client := newFakeClient(testDefaultConfigMap)
		client.setUpdateErr(errors.New("some error"))
		return client, nil
	})

	// wait for the plugin to fetch the config map
	resp, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, &bootstrapper.PublishBundleResponse{}, resp)

	// send the bundle
	require.NoError(t, stream.Send(&bootstrapper.PublishBundleRequest{
		Bundle: testBundle,
	}))

	// assert an error is returned since the update operation failed
	resp, err = stream.Recv()
	require.EqualError(t, err, "k8s-bootstrapper: unable to update config map spire/spire-bootstrap: some error")
	require.Nil(t, resp)
}

func TestPublishBundleSuccessWithDefaults(t *testing.T) {
	client := newFakeClient(testDefaultConfigMap)
	stream := openPublishBundleStream(t, "", func(string) (kubeClient, error) {
		return client, nil
	})

	// wait for the plugin to fetch the config map
	resp, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, &bootstrapper.PublishBundleResponse{}, resp)

	// send the bundle
	require.NoError(t, stream.Send(&bootstrapper.PublishBundleRequest{
		Bundle: testBundle,
	}))

	// assert the plugin has succeeded and that the config map was updated
	resp, err = stream.Recv()
	require.Equal(t, io.EOF, err)
	require.Nil(t, resp)
	require.Equal(t, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: defaultNamespace,
			Name:      defaultConfigMap,
		},
		Data: map[string]string{
			defaultConfigMapKey: testBundleData,
		},
	}, client.getConfigMap(defaultNamespace, defaultConfigMap))
}

func TestPublishBundleSuccessWithOverrides(t *testing.T) {
	client := newFakeClient(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "NAMESPACE",
			Name:      "CONFIGMAP",
		},
	})

	stream := openPublishBundleStream(t, `
		namespace = "NAMESPACE"
		config_map = "CONFIGMAP"
		config_map_key = "CONFIGMAPKEY"
		kube_config_file_path = "/some/file/path"`, func(configPath string) (kubeClient, error) {
		if configPath != "/some/file/path" {
			return nil, fmt.Errorf("expected config path %q, got %q", "/some/file/path", configPath)
		}
		return client, nil
	})

	// wait for the plugin to fetch the config map
	resp, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, &bootstrapper.PublishBundleResponse{}, resp)

	// send the bundle
	require.NoError(t, stream.Send(&bootstrapper.PublishBundleRequest{
		Bundle: testBundle,
	}))

	// assert the plugin has succeeded and that the config map was updated
	resp, err = stream.Recv()
	require.Equal(t, io.EOF, err)
	require.Nil(t, resp)
	require.Equal(t, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "NAMESPACE",
			Name:      "CONFIGMAP",
		},
		Data: map[string]string{
			"CONFIGMAPKEY": testBundleData,
		},
	}, client.getConfigMap("NAMESPACE", "CONFIGMAP"))
}

func TestPublishBundleOnConflict(t *testing.T) {
	client := newFakeClient(testDefaultConfigMap)
	stream := openPublishBundleStream(t, "", func(string) (kubeClient, error) {
		return client, nil
	})

	// wait for the plugin to fetch the config map
	resp, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, &bootstrapper.PublishBundleResponse{}, resp)

	// prevent the update from succeeding and send the bundle
	client.setUpdateErr(&k8serrors.StatusError{
		ErrStatus: metav1.Status{
			Code:    http.StatusConflict,
			Message: "unexpected version",
		},
	})
	require.NoError(t, stream.Send(&bootstrapper.PublishBundleRequest{
		Bundle: testBundle,
	}))

	// assert that the config map was never updated and that the plugin wants to try again
	require.Equal(t, testDefaultConfigMap, client.getConfigMap(defaultNamespace, defaultConfigMap))

	resp, err = stream.Recv()
	require.NoError(t, err)
	require.Equal(t, &bootstrapper.PublishBundleResponse{}, resp)

	// allow the update to succeed and send the bundle again
	client.setUpdateErr(nil)
	require.NoError(t, stream.Send(&bootstrapper.PublishBundleRequest{
		Bundle: testBundle,
	}))

	// assert the plugin has succeeded and that the config map was updated
	resp, err = stream.Recv()
	require.Equal(t, io.EOF, err)
	require.Nil(t, resp)

	require.Equal(t, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: defaultNamespace,
			Name:      defaultConfigMap,
		},
		Data: map[string]string{
			defaultConfigMapKey: testBundleData,
		},
	}, client.getConfigMap(defaultNamespace, defaultConfigMap))
}

func TestConfigureWithMalformedConfiguration(t *testing.T) {
	p := New()
	_, err := p.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: "not valid HCL",
	})
	require.Error(t, err, "k8s-bootstrapper: unable to decode configuration")
	require.Contains(t, err.Error(), "k8s-bootstrapper: unable to decode configuration")
}

func TestGetPluginInfo(t *testing.T) {
	p := New()
	resp, err := p.GetPluginInfo(context.Background(), &spi.GetPluginInfoRequest{})
	require.NoError(t, err)
	require.Equal(t, &spi.GetPluginInfoResponse{}, resp)
}

func openPublishBundleStream(t *testing.T, configuration string, newClient func(string) (kubeClient, error)) bootstrapper.PublishBundle_Stream {
	p := New()
	p.hooks.newClient = newClient
	_, err := p.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: configuration,
	})
	require.NoError(t, err)

	stream, err := bootstrapper.NewBuiltIn(p).PublishBundle(context.Background())
	require.NoError(t, err)
	require.NotNil(t, stream)
	return stream
}

type fakeClient struct {
	mu         sync.Mutex
	configMaps map[string]*corev1.ConfigMap
	updateErr  error
}

func newFakeClient(configMaps ...*corev1.ConfigMap) *fakeClient {
	c := &fakeClient{
		configMaps: make(map[string]*corev1.ConfigMap),
	}
	for _, configMap := range configMaps {
		c.setConfigMap(configMap)
	}
	return c
}

func (c *fakeClient) GetConfigMap(ctx context.Context, namespace, configMap string) (*corev1.ConfigMap, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.configMaps[configMapKey(namespace, configMap)]
	if !ok {
		return nil, errors.New("not found")
	}
	return entry, nil
}

func (c *fakeClient) UpdateConfigMap(ctx context.Context, namespace string, configMap *corev1.ConfigMap) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.configMaps[configMapKey(namespace, configMap.Name)] = configMap
	return c.updateErr
}

func (c *fakeClient) getConfigMap(namespace, configMap string) *corev1.ConfigMap {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.configMaps[configMapKey(namespace, configMap)]
}

func (c *fakeClient) setConfigMap(configMap *corev1.ConfigMap) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.configMaps[configMapKey(configMap.Namespace, configMap.Name)] = configMap
	return c.updateErr
}

func (c *fakeClient) setUpdateErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateErr = err
}

func configMapKey(namespace, configMap string) string {
	return fmt.Sprintf("%s|%s", namespace, configMap)
}
