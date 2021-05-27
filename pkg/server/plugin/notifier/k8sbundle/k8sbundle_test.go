package k8sbundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"testing"

	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/proto/spire/common"
	identityproviderv0 "github.com/spiffe/spire/proto/spire/hostservice/server/identityprovider/v0"
	"github.com/spiffe/spire/test/fakes/fakeidentityprovider"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

var (
	testBundle = &common.Bundle{
		RootCas: []*common.Certificate{
			{DerBytes: []byte("FOO")},
			{DerBytes: []byte("BAR")},
		},
	}

	testBundle2 = &common.Bundle{
		RootCas: []*common.Certificate{
			{DerBytes: []byte("BAR")},
			{DerBytes: []byte("BAZ")},
		},
	}

	commonBundle = &common.Bundle{
		TrustDomainId: "spiffe://example.org",
		RootCas:       []*common.Certificate{{DerBytes: []byte("1")}},
	}
)

const (
	// PEM encoding of the root CAs in testBundle
	testBundleData  = "-----BEGIN CERTIFICATE-----\nRk9P\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nQkFS\n-----END CERTIFICATE-----\n"
	testBundle2Data = "-----BEGIN CERTIFICATE-----\nQkFS\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nQkFa\n-----END CERTIFICATE-----\n"
)

func TestNotifyFailsIfNotConfigured(t *testing.T) {
	test := setupTest()
	notifier := new(notifier.V1)
	plugintest.Load(t, BuiltIn(), notifier,
		plugintest.HostServices(identityproviderv0.IdentityProviderServiceServer(test.identityProvider)),
	)

	err := notifier.NotifyBundleUpdated(context.Background(), &common.Bundle{TrustDomainId: "spiffe://example.org"})
	spiretest.RequireGRPCStatus(t, err, codes.FailedPrecondition, "notifier(k8sbundle): not configured")
}

func TestNotifyAndAdviseFailsIfNotConfigured(t *testing.T) {
	test := setupTest()
	notifier := new(notifier.V1)
	plugintest.Load(t, BuiltIn(), notifier,
		plugintest.HostServices(identityproviderv0.IdentityProviderServiceServer(test.identityProvider)),
	)

	err := notifier.NotifyAndAdviseBundleLoaded(context.Background(), &common.Bundle{TrustDomainId: "spiffe://example.org"})
	spiretest.RequireGRPCStatus(t, err, codes.FailedPrecondition, "notifier(k8sbundle): not configured")
}

func TestBundleLoadedWhenCannotCreateClient(t *testing.T) {
	test := setupTest()
	test.kubeClient = nil
	notifier := test.loadPlugin(t, "")

	err := notifier.NotifyAndAdviseBundleLoaded(context.Background(), commonBundle)
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "notifier(k8sbundle): failed to create kube client: kube client not configured")
}

func TestBundleLoadedConfigMapGetFailure(t *testing.T) {
	test := setupTest()
	notifier := test.loadPlugin(t, "")

	err := notifier.NotifyAndAdviseBundleLoaded(context.Background(), &common.Bundle{TrustDomainId: "spiffe://example.org"})
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "notifier(k8sbundle): unable to update: unable to get list: not found")
}

func TestBundleLoadedConfigMapPatchFailure(t *testing.T) {
	test := setupTest()
	notifier := test.loadPlugin(t, "")

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, string(debug.Stack()))
		}
	}()
	test.kubeClient.setConfigMap(newConfigMap())
	test.kubeClient.setPatchErr(errors.New("some error"))
	test.identityProvider.AppendBundle(testBundle)

	err := notifier.NotifyAndAdviseBundleLoaded(context.Background(), commonBundle)
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "notifier(k8sbundle): unable to update: spire/spire-bundle: some error")
}

func TestBundleLoadedConfigMapUpdateConflict(t *testing.T) {
	test := setupTest()
	notifier := test.loadPlugin(t, "")

	test.kubeClient.setConfigMap(newConfigMap())
	test.kubeClient.setPatchErr(&k8serrors.StatusError{
		ErrStatus: metav1.Status{
			Code:    http.StatusConflict,
			Message: "unexpected version",
			Reason:  "Conflict",
		},
	})

	// return a different bundle when fetched the second time
	test.identityProvider.AppendBundle(testBundle)
	test.identityProvider.AppendBundle(testBundle2)

	err := notifier.NotifyAndAdviseBundleLoaded(context.Background(), commonBundle)
	require.NoError(t, err)

	// make sure the config map contains the second bundle data
	configMap := test.kubeClient.getConfigMap("spire", "spire-bundle")
	require.NotNil(t, configMap)
	require.NotNil(t, configMap.Data)
	require.Equal(t, testBundle2Data, configMap.Data["bundle.crt"])
}

func TestBundleLoadedWithDefaultConfiguration(t *testing.T) {
	test := setupTest()
	notifier := test.loadPlugin(t, "")

	test.kubeClient.setConfigMap(newConfigMap())
	test.identityProvider.AppendBundle(testBundle)

	err := notifier.NotifyAndAdviseBundleLoaded(context.Background(), commonBundle)
	require.NoError(t, err)

	require.Equal(t, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "spire",
			Name:            "spire-bundle",
			ResourceVersion: "2",
		},
		Data: map[string]string{
			"bundle.crt": testBundleData,
		},
	}, test.kubeClient.getConfigMap("spire", "spire-bundle"))
}

func TestBundleLoadedWithConfigurationOverrides(t *testing.T) {
	test := setupTest()
	test.expectConfigPath = "/some/file/path"
	notifier := test.loadPlugin(t, `
namespace = "NAMESPACE"
config_map = "CONFIGMAP"
config_map_key = "CONFIGMAPKEY"
kube_config_file_path = "/some/file/path"
`)

	test.kubeClient.setConfigMap(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "NAMESPACE",
			Name:            "CONFIGMAP",
			ResourceVersion: "2",
		},
	})
	test.identityProvider.AppendBundle(testBundle)

	err := notifier.NotifyAndAdviseBundleLoaded(context.Background(), commonBundle)
	require.NoError(t, err)

	require.Equal(t, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "NAMESPACE",
			Name:            "CONFIGMAP",
			ResourceVersion: "3",
		},
		Data: map[string]string{
			"CONFIGMAPKEY": testBundleData,
		},
	}, test.kubeClient.getConfigMap("NAMESPACE", "CONFIGMAP"))
}

func TestBundleUpdatedWhenCannotCreateClient(t *testing.T) {
	test := setupTest()
	test.kubeClient = nil
	notifier := test.loadPlugin(t, "")

	err := notifier.NotifyBundleUpdated(context.Background(), commonBundle)
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "notifier(k8sbundle): failed to create kube client: kube client not configured")
}

func TestBundleUpdatedConfigMapGetFailure(t *testing.T) {
	test := setupTest()
	notifier := test.loadPlugin(t, "")

	err := notifier.NotifyBundleUpdated(context.Background(), commonBundle)
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "notifier(k8sbundle): unable to update: unable to get list: not found")
}

func TestBundleUpdatedConfigMapPatchFailure(t *testing.T) {
	test := setupTest()
	notifier := test.loadPlugin(t, "")

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, string(debug.Stack()))
		}
	}()
	test.kubeClient.setConfigMap(newConfigMap())
	test.kubeClient.setPatchErr(errors.New("some error"))
	test.identityProvider.AppendBundle(testBundle)

	err := notifier.NotifyBundleUpdated(context.Background(), commonBundle)
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "notifier(k8sbundle): unable to update: spire/spire-bundle: some error")
}

func TestBundleUpdatedConfigMapUpdateConflict(t *testing.T) {
	test := setupTest()
	notifier := test.loadPlugin(t, "")

	test.kubeClient.setConfigMap(newConfigMap())
	test.kubeClient.setPatchErr(&k8serrors.StatusError{
		ErrStatus: metav1.Status{
			Code:    http.StatusConflict,
			Message: "unexpected version",
			Reason:  "Conflict",
		},
	})

	// return a different bundle when fetched the second time
	test.identityProvider.AppendBundle(testBundle)
	test.identityProvider.AppendBundle(testBundle2)

	err := notifier.NotifyBundleUpdated(context.Background(), commonBundle)
	require.NoError(t, err)

	// make sure the config map contains the second bundle data
	configMap := test.kubeClient.getConfigMap("spire", "spire-bundle")
	require.NotNil(t, configMap)
	require.NotNil(t, configMap.Data)
	require.Equal(t, testBundle2Data, configMap.Data["bundle.crt"])
}

func TestBundleUpdatedWithDefaultConfiguration(t *testing.T) {
	test := setupTest()
	notifier := test.loadPlugin(t, "")

	test.kubeClient.setConfigMap(newConfigMap())
	test.identityProvider.AppendBundle(testBundle)

	err := notifier.NotifyBundleUpdated(context.Background(), commonBundle)
	require.NoError(t, err)

	require.Equal(t, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "spire",
			Name:            "spire-bundle",
			ResourceVersion: "2",
		},
		Data: map[string]string{
			"bundle.crt": testBundleData,
		},
	}, test.kubeClient.getConfigMap("spire", "spire-bundle"))
}

func TestBundleUpdatedWithConfigurationOverrides(t *testing.T) {
	test := setupTest()
	test.expectConfigPath = "/some/file/path"
	notifier := test.loadPlugin(t, `
namespace = "NAMESPACE"
config_map = "CONFIGMAP"
config_map_key = "CONFIGMAPKEY"
kube_config_file_path = "/some/file/path"
`)

	test.kubeClient.setConfigMap(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "NAMESPACE",
			Name:            "CONFIGMAP",
			ResourceVersion: "2",
		},
	})
	test.identityProvider.AppendBundle(testBundle)

	err := notifier.NotifyBundleUpdated(context.Background(), commonBundle)
	require.NoError(t, err)

	require.Equal(t, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "NAMESPACE",
			Name:            "CONFIGMAP",
			ResourceVersion: "3",
		},
		Data: map[string]string{
			"CONFIGMAPKEY": testBundleData,
		},
	}, test.kubeClient.getConfigMap("NAMESPACE", "CONFIGMAP"))
}

func TestConfigureWithMalformedConfiguration(t *testing.T) {
	test := setupTest()
	doConfig := func(t *testing.T, configuration string) error {
		var err error
		notifier := new(notifier.V1)
		plugintest.Load(t, BuiltIn(), notifier,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(identityproviderv0.IdentityProviderServiceServer(test.identityProvider)),
			plugintest.Configure(configuration),
		)

		return err
	}

	err := doConfig(t, "blah")
	spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "unable to decode configuration")
}

func TestBundleFailsToLoadIfHostServicesUnavailabler(t *testing.T) {
	var err error
	plugintest.Load(t, BuiltIn(), nil,
		plugintest.CaptureLoadError(&err))
	spiretest.AssertGRPCStatusContains(t, err, codes.FailedPrecondition, "IdentityProvider host service is required")
}

type fakeKubeClient struct {
	mu         sync.RWMutex
	configMaps map[string]*corev1.ConfigMap
	patchErr   error
}

func newFakeKubeClient(configMaps ...*corev1.ConfigMap) *fakeKubeClient {
	c := &fakeKubeClient{
		configMaps: make(map[string]*corev1.ConfigMap),
	}
	for _, configMap := range configMaps {
		c.setConfigMap(configMap)
	}
	return c
}

func (c *fakeKubeClient) Get(ctx context.Context, namespace, configMap string) (runtime.Object, error) {
	entry := c.getConfigMap(namespace, configMap)
	if entry == nil {
		return nil, errors.New("not found")
	}
	return entry, nil
}
func (c *fakeKubeClient) GetList(ctx context.Context, config *pluginConfig) (runtime.Object, error) {
	list := c.getConfigMapList()
	if list.Items == nil {
		return nil, errors.New("not found")
	}
	return list, nil
}

func (c *fakeKubeClient) CreatePatch(ctx context.Context, config *pluginConfig, obj runtime.Object, resp *identityproviderv0.FetchX509IdentityResponse) (runtime.Object, error) {
	configMap, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "wrong type, expecting config map")
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: configMap.ResourceVersion,
		},
		Data: map[string]string{
			config.ConfigMapKey: bundleData(resp.Bundle),
		},
	}, nil
}

func (c *fakeKubeClient) Patch(ctx context.Context, namespace, configMap string, patchBytes []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.configMaps[configMapKey(namespace, configMap)]
	if !ok {
		return errors.New("not found")
	}

	// if there is a patch error configured, return it and clear the patchErr state.
	patchErr := c.patchErr
	c.patchErr = nil
	if patchErr != nil {
		return patchErr
	}

	patchedMap := new(corev1.ConfigMap)
	if err := json.Unmarshal(patchBytes, patchedMap); err != nil {
		return err
	}
	resourceVersion, err := strconv.Atoi(patchedMap.ResourceVersion)
	if err != nil {
		return errors.New("patch does not have resource version")
	}
	entry.ResourceVersion = fmt.Sprint(resourceVersion + 1)
	if entry.Data == nil {
		entry.Data = map[string]string{}
	}
	for key, data := range patchedMap.Data {
		entry.Data[key] = data
	}
	return nil
}

func (c *fakeKubeClient) Watch(ctx context.Context, config *pluginConfig) (watch.Interface, error) {
	return nil, nil
}

func (c *fakeKubeClient) getConfigMap(namespace, configMap string) *corev1.ConfigMap {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.configMaps[configMapKey(namespace, configMap)]
}

func (c *fakeKubeClient) getConfigMapList() *corev1.ConfigMapList {
	c.mu.RLock()
	defer c.mu.RUnlock()
	configMapList := &corev1.ConfigMapList{}
	for _, configMap := range c.configMaps {
		configMapList.Items = append(configMapList.Items, *configMap)
	}
	return configMapList
}

func (c *fakeKubeClient) setConfigMap(configMap *corev1.ConfigMap) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.configMaps[configMapKey(configMap.Namespace, configMap.Name)] = configMap
}

func (c *fakeKubeClient) setPatchErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.patchErr = err
}

func configMapKey(namespace, configMap string) string {
	return fmt.Sprintf("%s|%s", namespace, configMap)
}

func newConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "spire",
			Name:            "spire-bundle",
			ResourceVersion: "1",
		},
	}
}

type test struct {
	identityProvider *fakeidentityprovider.IdentityProvider
	kubeClient       *fakeKubeClient
	expectConfigPath string
}

func setupTest() *test {
	return &test{
		identityProvider: fakeidentityprovider.New(),
		kubeClient:       newFakeKubeClient(),
		expectConfigPath: "",
	}
}

func (s *test) loadPlugin(t *testing.T, configuration string) *notifier.V1 {
	notifier := new(notifier.V1)
	raw := New()
	plugintest.Load(t, builtIn(raw), notifier,
		plugintest.HostServices(identityproviderv0.IdentityProviderServiceServer(s.identityProvider)),
		plugintest.Configure(configuration),
	)

	raw.hooks.newKubeClient = func(c *pluginConfig) ([]kubeClient, error) {
		require.Equal(t, s.expectConfigPath, c.KubeConfigFilePath)
		if s.kubeClient == nil {
			return nil, errors.New("kube client not configured")
		}
		return []kubeClient{s.kubeClient}, nil
	}

	return notifier
}
