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

	"github.com/hashicorp/hcl"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/proto/spire/common"
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
	testBundle = &plugintypes.Bundle{
		X509Authorities: []*plugintypes.X509Certificate{
			{Asn1: []byte("FOO")},
			{Asn1: []byte("BAR")},
		},
	}

	testBundle2 = &plugintypes.Bundle{
		X509Authorities: []*plugintypes.X509Certificate{
			{Asn1: []byte("BAR")},
			{Asn1: []byte("BAZ")},
		},
	}

	commonBundle = &common.Bundle{
		TrustDomainId: "spiffe://example.org",
		RootCas:       []*common.Certificate{{DerBytes: []byte("1")}},
	}

	coreConfig = &configv1.CoreConfiguration{TrustDomain: "test.example.org"}
)

const (
	// PEM encoding of the root CAs in testBundle
	testBundleData  = "-----BEGIN CERTIFICATE-----\nRk9P\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nQkFS\n-----END CERTIFICATE-----\n"
	testBundle2Data = "-----BEGIN CERTIFICATE-----\nQkFS\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nQkFa\n-----END CERTIFICATE-----\n"
)

func TestNotifyFailsIfNotConfigured(t *testing.T) {
	test := setupTest(t)
	notifier := new(notifier.V1)
	plugintest.Load(t, BuiltIn(), notifier,
		plugintest.HostServices(identityproviderv1.IdentityProviderServiceServer(test.identityProvider)),
	)

	err := notifier.NotifyBundleUpdated(context.Background(), &common.Bundle{TrustDomainId: "spiffe://example.org"})
	spiretest.RequireGRPCStatus(t, err, codes.FailedPrecondition, "notifier(k8sbundle): not configured")
}

func TestNotifyAndAdviseFailsIfNotConfigured(t *testing.T) {
	test := setupTest(t)
	notifier := new(notifier.V1)
	plugintest.Load(t, BuiltIn(), notifier,
		plugintest.HostServices(identityproviderv1.IdentityProviderServiceServer(test.identityProvider)),
	)

	err := notifier.NotifyAndAdviseBundleLoaded(context.Background(), &common.Bundle{TrustDomainId: "spiffe://example.org"})
	spiretest.RequireGRPCStatus(t, err, codes.FailedPrecondition, "notifier(k8sbundle): not configured")
}

func TestBundleLoadedWhenCannotCreateClient(t *testing.T) {
	test := setupTest(t, withKubeClientError())
	err := test.notifier.NotifyAndAdviseBundleLoaded(context.Background(), commonBundle)
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "notifier(k8sbundle): failed to create kube clients: kube client not configured")
}

func TestBundleLoadedConfigMapGetFailure(t *testing.T) {
	test := setupTest(t)

	err := test.notifier.NotifyAndAdviseBundleLoaded(context.Background(), &common.Bundle{TrustDomainId: "spiffe://example.org"})
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "notifier(k8sbundle): unable to update: unable to get list: not found")
}

func TestBundleLoadedConfigMapPatchFailure(t *testing.T) {
	test := setupTest(t)

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, string(debug.Stack()))
		}
	}()
	test.kubeClient.setConfigMap(newConfigMap())
	test.kubeClient.setPatchErr(errors.New("some error"))
	test.identityProvider.AppendBundle(testBundle)

	err := test.notifier.NotifyAndAdviseBundleLoaded(context.Background(), commonBundle)
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "notifier(k8sbundle): unable to update: spire/spire-bundle: some error")
}

func TestBundleLoadedConfigMapUpdateConflict(t *testing.T) {
	test := setupTest(t)

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

	err := test.notifier.NotifyAndAdviseBundleLoaded(context.Background(), commonBundle)
	require.NoError(t, err)

	// make sure the config map contains the second bundle data
	configMap := test.kubeClient.getConfigMap("spire", "spire-bundle")
	require.NotNil(t, configMap)
	require.NotNil(t, configMap.Data)
	require.Equal(t, testBundle2Data, configMap.Data["bundle.crt"])
}

func TestBundleLoadedWithDefaultConfiguration(t *testing.T) {
	test := setupTest(t)

	test.kubeClient.setConfigMap(newConfigMap())
	test.identityProvider.AppendBundle(testBundle)

	err := test.notifier.NotifyAndAdviseBundleLoaded(context.Background(), commonBundle)
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
	config := `
namespace = "NAMESPACE"
config_map = "CONFIGMAP"
config_map_key = "CONFIGMAPKEY"
clusters  = [
	{
		namespace = "NAMESPACE2"
		config_map = "CONFIGMAP2"
		config_map_key = "CONFIGMAPKEY2"
		kube_config_file_path = "KUBECONFIGFILEPATH2"
	}
]
`
	test := setupTest(t, withPlainConfig(config))

	test.kubeClient.setConfigMap(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "NAMESPACE",
			Name:            "CONFIGMAP",
			ResourceVersion: "2",
		},
	})
	test.kubeClient.setConfigMap(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "NAMESPACE2",
			Name:            "CONFIGMAP2",
			ResourceVersion: "22",
		},
	})
	test.identityProvider.AppendBundle(testBundle)
	test.identityProvider.AppendBundle(testBundle)

	err := test.notifier.NotifyAndAdviseBundleLoaded(context.Background(), commonBundle)
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

	require.Equal(t, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "NAMESPACE2",
			Name:            "CONFIGMAP2",
			ResourceVersion: "23",
		},
		Data: map[string]string{
			"CONFIGMAPKEY": testBundleData,
		},
	}, test.kubeClient.getConfigMap("NAMESPACE2", "CONFIGMAP2"))
}

func TestBundleUpdatedWhenCannotCreateClient(t *testing.T) {
	test := setupTest(t, withKubeClientError())
	err := test.notifier.NotifyBundleUpdated(context.Background(), commonBundle)
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "notifier(k8sbundle): failed to create kube clients: kube client not configured")
}

func TestBundleUpdatedConfigMapGetFailure(t *testing.T) {
	test := setupTest(t)

	err := test.notifier.NotifyBundleUpdated(context.Background(), commonBundle)
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "notifier(k8sbundle): unable to update: unable to get list: not found")
}

func TestBundleUpdatedConfigMapPatchFailure(t *testing.T) {
	test := setupTest(t)

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, string(debug.Stack()))
		}
	}()
	test.kubeClient.setConfigMap(newConfigMap())
	test.kubeClient.setPatchErr(errors.New("some error"))
	test.identityProvider.AppendBundle(testBundle)

	err := test.notifier.NotifyBundleUpdated(context.Background(), commonBundle)
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "notifier(k8sbundle): unable to update: spire/spire-bundle: some error")
}

func TestBundleUpdatedConfigMapUpdateConflict(t *testing.T) {
	test := setupTest(t)

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

	err := test.notifier.NotifyBundleUpdated(context.Background(), commonBundle)
	require.NoError(t, err)

	// make sure the config map contains the second bundle data
	configMap := test.kubeClient.getConfigMap("spire", "spire-bundle")
	require.NotNil(t, configMap)
	require.NotNil(t, configMap.Data)
	require.Equal(t, testBundle2Data, configMap.Data["bundle.crt"])
}

func TestBundleUpdatedWithDefaultConfiguration(t *testing.T) {
	test := setupTest(t)

	test.kubeClient.setConfigMap(newConfigMap())
	test.identityProvider.AppendBundle(testBundle)

	err := test.notifier.NotifyBundleUpdated(context.Background(), commonBundle)
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
	plainConfig := `
namespace = "NAMESPACE"
config_map = "CONFIGMAP"
config_map_key = "CONFIGMAPKEY"
kube_config_file_path = "/some/file/path"
clusters  = [
	{
		namespace = "NAMESPACE2"
		config_map = "CONFIGMAP2"
		config_map_key = "CONFIGMAPKEY2"
		kube_config_file_path = "KUBECONFIGFILEPATH2"
	}
]
`
	test := setupTest(t, withPlainConfig(plainConfig))

	test.kubeClient.setConfigMap(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "NAMESPACE",
			Name:            "CONFIGMAP",
			ResourceVersion: "2",
		},
	})
	test.kubeClient.setConfigMap(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "NAMESPACE2",
			Name:            "CONFIGMAP2",
			ResourceVersion: "22",
		},
	})
	test.identityProvider.AppendBundle(testBundle)
	test.identityProvider.AppendBundle(testBundle)

	err := test.notifier.NotifyBundleUpdated(context.Background(), commonBundle)
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

	require.Equal(t, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "NAMESPACE2",
			Name:            "CONFIGMAP2",
			ResourceVersion: "23",
		},
		Data: map[string]string{
			"CONFIGMAPKEY": testBundleData,
		},
	}, test.kubeClient.getConfigMap("NAMESPACE2", "CONFIGMAP2"))
}

func TestConfigureWithMalformedConfiguration(t *testing.T) {
	configuration := "blah"
	test := setupTest(t, withNoConfigure())

	_, err := test.rawPlugin.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration:  configuration,
		CoreConfiguration: coreConfig,
	})

	spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "unable to decode configuration")
}

func TestBundleFailsToLoadIfHostServicesUnavailabler(t *testing.T) {
	var err error
	plugintest.Load(t, BuiltIn(), nil,
		plugintest.CaptureLoadError(&err))
	spiretest.RequireGRPCStatusContains(t, err, codes.FailedPrecondition, "IdentityProvider host service is required")
}

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name           string
		configuration  string
		expectedErr    string
		expectedCode   codes.Code
		expectedConfig *pluginConfig
	}{
		{
			name: "empty configuration",
			expectedConfig: &pluginConfig{
				cluster: cluster{
					Namespace:    "spire",
					ConfigMap:    "spire-bundle",
					ConfigMapKey: "bundle.crt",
				},
			},
		},
		{
			name: "full configuration",
			configuration: `
			namespace = "root"
			config_map = "root_config_map"
			config_map_key = "root.pem"
			kube_config_file_path = "/some/file/path"
			webhook_label = "root_webhook_label"
			api_service_label = "root_api_label"
			clusters  = [
			{
				namespace = "cluster1"
				config_map = "cluster1_config_map"
				config_map_key = "cluster1.pem"
				kube_config_file_path = "/cluster1/file/path"
				webhook_label = "cluster1_webhook_label"
				api_service_label = "cluster1_api_label"
			},
			{
				namespace = "cluster2"
				config_map = "cluster2_config_map"
				config_map_key = "cluster2.pem"
				kube_config_file_path = "/cluster2/file/path"
				webhook_label = "cluster2_webhook_label"
				api_service_label = "cluster2_api_label"
			},
			]
			`,
			expectedConfig: &pluginConfig{
				cluster: cluster{
					Namespace:          "root",
					ConfigMap:          "root_config_map",
					ConfigMapKey:       "root.pem",
					KubeConfigFilePath: "/some/file/path",
					WebhookLabel:       "root_webhook_label",
					APIServiceLabel:    "root_api_label",
				},
				Clusters: []cluster{
					{
						Namespace:          "cluster1",
						ConfigMap:          "cluster1_config_map",
						ConfigMapKey:       "cluster1.pem",
						KubeConfigFilePath: "/cluster1/file/path",
						WebhookLabel:       "cluster1_webhook_label",
						APIServiceLabel:    "cluster1_api_label",
					},
					{
						Namespace:          "cluster2",
						ConfigMap:          "cluster2_config_map",
						ConfigMapKey:       "cluster2.pem",
						KubeConfigFilePath: "/cluster2/file/path",
						WebhookLabel:       "cluster2_webhook_label",
						APIServiceLabel:    "cluster2_api_label",
					},
				},
			},
		},
		{
			name: "root only with partial configuration",
			configuration: `			
			api_service_label = "root_api_label"			
			`,
			expectedConfig: &pluginConfig{
				cluster: cluster{
					Namespace:          "spire",
					ConfigMap:          "spire-bundle",
					ConfigMapKey:       "bundle.crt",
					KubeConfigFilePath: "",
					APIServiceLabel:    "root_api_label",
				},
			},
		},
		{
			name: "clusters only with partial configuration",
			configuration: `
			clusters  = [
			{
				kube_config_file_path = "/cluster1/file/path"														
			},
			{
				namespace = "cluster2"
				config_map = "cluster2_config_map"				
				kube_config_file_path = "/cluster2/file/path"				
			},
			]
			`,
			expectedConfig: &pluginConfig{
				Clusters: []cluster{
					{
						Namespace:          "spire",
						ConfigMap:          "spire-bundle",
						ConfigMapKey:       "bundle.crt",
						KubeConfigFilePath: "/cluster1/file/path",
					},
					{
						Namespace:          "cluster2",
						ConfigMap:          "cluster2_config_map",
						ConfigMapKey:       "bundle.crt",
						KubeConfigFilePath: "/cluster2/file/path",
					},
				},
			},
		},
		{
			name:         "clusters only missing kube_config_file_path",
			expectedErr:  "cluster configuration is missing kube_config_file_path",
			expectedCode: codes.InvalidArgument,
			configuration: `
			clusters  = [
			{
				namespace = "cluster1"
				config_map = "cluster1_config_map"														
			},
			{
				namespace = "cluster2"
				config_map = "cluster2_config_map"				
				kube_config_file_path = "/cluster2/file/path"				
			},
			]
			`,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, withNoConfigure())
			_, err := test.rawPlugin.Configure(context.Background(), &configv1.ConfigureRequest{
				HclConfiguration:  tt.configuration,
				CoreConfiguration: coreConfig,
			})

			if tt.expectedErr != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectedCode, tt.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedConfig, test.rawPlugin.config)
		})
	}
}

type fakeKubeClient struct {
	mu           sync.RWMutex
	configMaps   map[string]*corev1.ConfigMap
	patchErr     error
	namespace    string
	configMapKey string
}

func newFakeKubeClient(config *pluginConfig, configMaps ...*corev1.ConfigMap) *fakeKubeClient {
	fake := &fakeKubeClient{
		configMaps:   make(map[string]*corev1.ConfigMap),
		namespace:    config.Namespace,
		configMapKey: config.ConfigMapKey,
	}
	for _, configMap := range configMaps {
		fake.setConfigMap(configMap)
	}
	return fake
}

func (c *fakeKubeClient) Get(ctx context.Context, namespace, configMap string) (runtime.Object, error) {
	entry := c.getConfigMap(namespace, configMap)
	if entry == nil {
		return nil, errors.New("not found")
	}
	return entry, nil
}
func (c *fakeKubeClient) GetList(ctx context.Context) (runtime.Object, error) {
	list := c.getConfigMapList()
	if list.Items == nil {
		return nil, errors.New("not found")
	}
	return list, nil
}

func (c *fakeKubeClient) CreatePatch(ctx context.Context, obj runtime.Object, resp *identityproviderv1.FetchX509IdentityResponse) (runtime.Object, error) {
	configMap, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "wrong type, expecting config map")
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: configMap.ResourceVersion,
		},
		Data: map[string]string{
			c.configMapKey: bundleData(resp.Bundle),
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

func (c *fakeKubeClient) Watch(ctx context.Context) (watch.Interface, error) {
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
	rawPlugin        *Plugin
	notifier         *notifier.V1
	clients          []kubeClient
	kubeClient       *fakeKubeClient
	webhookClient    *fakeWebhook
	apiServiceClient *fakeAPIService
}

type testOptions struct {
	plainConfig     string
	kubeClientError bool
	doConfigure     bool
}

type testOption func(*testOptions)

func withPlainConfig(plainConfig string) testOption {
	return func(args *testOptions) {
		args.plainConfig = plainConfig
	}
}

func withKubeClientError() testOption {
	return func(args *testOptions) {
		args.kubeClientError = true
	}
}

func withNoConfigure() testOption {
	return func(args *testOptions) {
		args.doConfigure = false
	}
}

func setupTest(t *testing.T, options ...testOption) *test {
	args := &testOptions{
		doConfigure: true,
		plainConfig: fmt.Sprintf(`
		namespace = "%s"
		config_map = "%s"
		config_map_key = "%s"
		`, defaultNamespace, defaultConfigMap, defaultConfigMapKey),
	}

	for _, opt := range options {
		opt(args)
	}

	config := new(pluginConfig)
	err := hcl.Decode(&config, args.plainConfig)
	require.Nil(t, err)

	raw := New()
	notifier := new(notifier.V1)
	identityProvider := fakeidentityprovider.New()

	test := &test{
		identityProvider: identityProvider,
		rawPlugin:        raw,
		notifier:         notifier,
	}

	test.kubeClient = newFakeKubeClient(config)
	raw.hooks.newKubeClients = func(c *pluginConfig) ([]kubeClient, error) {
		if args.kubeClientError {
			return nil, errors.New("kube client not configured")
		}

		test.clients = append([]kubeClient{}, test.kubeClient)

		if c.WebhookLabel != "" {
			test.webhookClient = newFakeWebhook(c)
			test.clients = append(test.clients, test.webhookClient)
		}
		if c.APIServiceLabel != "" {
			test.apiServiceClient = newFakeAPIService(c)
			test.clients = append(test.clients, test.apiServiceClient)
		}

		return test.clients, nil
	}

	if args.doConfigure {
		plugintest.Load(
			t,
			builtIn(raw),
			notifier,
			plugintest.HostServices(identityproviderv1.IdentityProviderServiceServer(identityProvider)),
			plugintest.Configure(args.plainConfig),
		)
	} else {
		plugintest.Load(
			t,
			builtIn(raw),
			notifier,
			plugintest.HostServices(identityproviderv1.IdentityProviderServiceServer(identityProvider)),
		)
	}

	return test
}
