package k8sbundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeidentityprovider"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregator "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	fakeaggregator "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
	aggregatorinformers "k8s.io/kube-aggregator/pkg/client/informers/externalversions"
)

var (
	td      = spiffeid.RequireTrustDomainFromString("example.org")
	rootPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIBRzCB76ADAgECAgEBMAoGCCqGSM49BAMCMBMxETAPBgNVBAMTCEFnZW50IENB
MCAYDzAwMDEwMTAxMDAwMDAwWhcNMjEwNTI2MjE1MDA5WjATMREwDwYDVQQDEwhB
Z2VudCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNRTee0Z/+omKGAVU3Ns
NkOrpvcU4gZ3C6ilHSfYUiF2o+YCdsuLZb8UFbEVB4VR1H7Ez629IPEASK1k0KW+
KHajMjAwMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFAXjxsTxL8UIBZl5lheq
qaDOcBhNMAoGCCqGSM49BAMCA0cAMEQCIGTDiqcBaFomiRIfRNtLNTl5wFIQMlcB
MWnIPs59/JF8AiBeKSM/rkL2igQchDTvlJJWsyk9YL8UZI/XfZO7907TWA==
-----END CERTIFICATE-----`)
	root, _ = pemutil.ParseCertificate(rootPEM)

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
		TrustDomainId: td.IDString(),
		RootCas:       []*common.Certificate{{DerBytes: root.Raw}},
	}

	coreConfig = &configv1.CoreConfiguration{TrustDomain: "test.example.org"}
)

const (
	// PEM encoding of the root CAs in testBundle
	testBundleData   = "-----BEGIN CERTIFICATE-----\nRk9P\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nQkFS\n-----END CERTIFICATE-----\n"
	testBundle2Data  = "-----BEGIN CERTIFICATE-----\nQkFS\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nQkFa\n-----END CERTIFICATE-----\n"
	testTimeout      = time.Minute
	testPollInterval = 50 * time.Millisecond
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

func TestBundleInformerAddWebhookEvent(t *testing.T) {
	plainConfig := `
webhook_label = "WEBHOOK_LABEL"
kube_config_file_path = "/some/file/path"
`

	test := setupTest(t, withPlainConfig(plainConfig))
	require.NotNil(t, test.rawPlugin.stopCh)
	test.identityProvider.AppendBundle(testBundle)

	waitForInformerWatcher(t, test.webhookClient.watcherStarted)
	webhook := newMutatingWebhook(t, test.webhookClient.Interface, "spire-webhook", "")

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		actualWebhook, err := test.webhookClient.Get(context.Background(), webhook.Namespace, webhook.Name)
		require.NoError(collect, err)

		expected := &admissionv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:            webhook.Name,
				ResourceVersion: "1",
			},
			Webhooks: []admissionv1.MutatingWebhook{
				{
					ClientConfig: admissionv1.WebhookClientConfig{
						CABundle: []byte(testBundleData),
					},
				},
			},
		}

		// Ignore TypeMeta and ManagedFields which are populated by NewClientset's field management
		assert.Empty(collect, cmp.Diff(expected, actualWebhook,
			cmpopts.IgnoreFields(metav1.ObjectMeta{}, "ManagedFields"),
			cmpopts.IgnoreFields(metav1.TypeMeta{}, "Kind", "APIVersion")))
	}, testTimeout, testPollInterval)
}

func TestBundleInformerAddAPIServiceEvent(t *testing.T) {
	plainConfig := `
api_service_label = "API_SERVICE_LABEL"
kube_config_file_path = "/some/file/path"
`

	test := setupTest(t, withPlainConfig(plainConfig))
	require.NotNil(t, test.rawPlugin.stopCh)
	test.identityProvider.AppendBundle(testBundle)

	waitForInformerWatcher(t, test.apiServiceClient.watcherStarted)
	apiService := newAPIService(t, test.apiServiceClient.Interface, "spire-apiservice", "")

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		actualAPIService, err := test.apiServiceClient.Get(context.Background(), apiService.Namespace, apiService.Name)
		require.NoError(collect, err)

		expected := &apiregistrationv1.APIService{
			ObjectMeta: metav1.ObjectMeta{
				Name:            apiService.Name,
				ResourceVersion: "1",
			},
			Spec: apiregistrationv1.APIServiceSpec{
				CABundle: []byte(testBundleData),
			},
		}

		// Ignore TypeMeta and ManagedFields which are populated by NewClientset's field management
		assert.Empty(collect, cmp.Diff(expected, actualAPIService,
			cmpopts.IgnoreFields(metav1.ObjectMeta{}, "ManagedFields"),
			cmpopts.IgnoreFields(metav1.TypeMeta{}, "Kind", "APIVersion")))
	}, testTimeout, testPollInterval)
}

func TestBundleInformerWebhookAlreadyUpToDate(t *testing.T) {
	plainConfig := `
webhook_label = "WEBHOOK_LABEL"
kube_config_file_path = "/some/file/path"
`
	var test *test
	updateDone := make(chan struct{})
	test = setupTest(t, withPlainConfig(plainConfig), withInformerCallback(func(client kubeClient, obj runtime.Object) {
		objectMeta, err := meta.Accessor(obj)
		require.NoError(t, err)

		err = test.rawPlugin.updateBundle(context.Background(), client, objectMeta.GetNamespace(), objectMeta.GetName())
		require.Equal(t, status.Code(err), codes.AlreadyExists)
		updateDone <- struct{}{}
	}))
	require.NotNil(t, test.rawPlugin.stopCh)
	test.identityProvider.AppendBundle(testBundle)

	waitForInformerWatcher(t, test.webhookClient.watcherStarted)
	newMutatingWebhook(t, test.webhookClient.Interface, "spire-webhook", testBundleData)

	select {
	case <-updateDone:
	case <-time.After(testTimeout):
		require.FailNow(t, "timed out waiting for bundle update")
	}
}

func TestBundleInformerAPIServiceAlreadyUpToDate(t *testing.T) {
	plainConfig := `
api_service_label = "API_SERVICE_LABEL"
kube_config_file_path = "/some/file/path"
`
	var test *test
	updateDone := make(chan struct{})
	test = setupTest(t, withPlainConfig(plainConfig), withInformerCallback(func(client kubeClient, obj runtime.Object) {
		objectMeta, err := meta.Accessor(obj)
		require.NoError(t, err)

		err = test.rawPlugin.updateBundle(context.Background(), client, objectMeta.GetNamespace(), objectMeta.GetName())
		require.Equal(t, status.Code(err), codes.AlreadyExists)
		updateDone <- struct{}{}
	}))
	require.NotNil(t, test.rawPlugin.stopCh)
	test.identityProvider.AppendBundle(testBundle)

	waitForInformerWatcher(t, test.apiServiceClient.watcherStarted)
	newAPIService(t, test.apiServiceClient.Interface, "spire-apiservice", testBundleData)

	select {
	case <-updateDone:
	case <-time.After(testTimeout):
		require.FailNow(t, "timed out waiting for bundle update")
	}
}

func TestBundleInformerUpdateConfig(t *testing.T) {
	initialConfig := `
namespace = "NAMESPACE"
config_map = "CONFIGMAP"
config_map_key = "CONFIGMAPKEY"
webhook_label = "WEBHOOK_LABEL"
api_service_label = "API_SERVICE_LABEL"
`
	test := setupTest(t, withPlainConfig(initialConfig))
	require.NotNil(t, test.rawPlugin.stopCh)
	require.Eventually(t, func() bool {
		return test.webhookClient.webhookLabel == "WEBHOOK_LABEL"
	}, testTimeout, testPollInterval)
	require.Eventually(t, func() bool {
		return test.apiServiceClient.apiServiceLabel == "API_SERVICE_LABEL"
	}, testTimeout, testPollInterval)

	finalConfig := `
namespace = "NAMESPACE"
config_map = "CONFIGMAP"
config_map_key = "CONFIGMAPKEY"
webhook_label = "WEBHOOK_LABEL2"
api_service_label = "API_SERVICE_LABEL2"
kube_config_file_path = "/some/file/path"
`
	_, err := test.rawPlugin.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: "example.org",
		},
		HclConfiguration: finalConfig,
	})
	require.NoError(t, err)
	require.NotNil(t, test.rawPlugin.stopCh)
	require.Eventually(t, func() bool {
		return test.webhookClient.webhookLabel == "WEBHOOK_LABEL2"
	}, testTimeout, testPollInterval)
	require.Eventually(t, func() bool {
		return test.apiServiceClient.apiServiceLabel == "API_SERVICE_LABEL2"
	}, testTimeout, testPollInterval)
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

	spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "plugin configuration is malformed")
}

func TestBundleFailsToLoadIfHostServicesUnavailable(t *testing.T) {
	var err error
	plugintest.Load(t, BuiltIn(), nil,
		plugintest.CaptureLoadError(&err))
	spiretest.RequireGRPCStatusContains(t, err, codes.FailedPrecondition, "IdentityProvider host service is required")
}

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name           string
		trustDomain    string
		configuration  string
		expectedErr    string
		expectedCode   codes.Code
		expectedConfig *Configuration
	}{
		{
			name:        "empty configuration",
			trustDomain: "example.org",
			expectedConfig: &Configuration{
				cluster: cluster{
					Namespace:    "spire",
					ConfigMap:    "spire-bundle",
					ConfigMapKey: "bundle.crt",
				},
			},
		},
		{
			name:        "full configuration",
			trustDomain: "example.org",
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
			expectedConfig: &Configuration{
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
			name:        "root only with partial configuration",
			trustDomain: "example.org",
			configuration: `			
			api_service_label = "root_api_label"			
			`,
			expectedConfig: &Configuration{
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
			name:        "clusters only with partial configuration",
			trustDomain: "example.org",
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
			expectedConfig: &Configuration{
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
			trustDomain:  "example.org",
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

func newFakeKubeClient(config *Configuration, configMaps ...*corev1.ConfigMap) *fakeKubeClient {
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

func (c *fakeKubeClient) Get(_ context.Context, namespace, configMap string) (runtime.Object, error) {
	entry := c.getConfigMap(namespace, configMap)
	if entry == nil {
		return nil, errors.New("not found")
	}
	return entry, nil
}

func (c *fakeKubeClient) GetList(context.Context) (runtime.Object, error) {
	list := c.getConfigMapList()
	if list.Items == nil {
		return nil, errors.New("not found")
	}
	return list, nil
}

func (c *fakeKubeClient) CreatePatch(_ context.Context, obj runtime.Object, resp *identityproviderv1.FetchX509IdentityResponse) (runtime.Object, error) {
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

func (c *fakeKubeClient) Patch(_ context.Context, namespace, configMap string, patchBytes []byte) error {
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
	maps.Copy(entry.Data, patchedMap.Data)
	return nil
}

func (c *fakeKubeClient) Informer(informerCallback) (cache.SharedIndexInformer, error) {
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

type fakeWebhookClient struct {
	mutatingWebhookClient
	watcherStarted chan struct{}
}

func newFakeWebhookClient(config *Configuration) *fakeWebhookClient {
	client := fake.NewClientset()
	w := &fakeWebhookClient{
		mutatingWebhookClient: mutatingWebhookClient{
			Interface:    client,
			webhookLabel: config.WebhookLabel,
			factory: informers.NewSharedInformerFactoryWithOptions(
				client,
				0,
				informers.WithTweakListOptions(func(options *metav1.ListOptions) {
					options.LabelSelector = fmt.Sprintf("%s=true", config.WebhookLabel)
				}),
			),
		},
		watcherStarted: make(chan struct{}),
	}

	// A catch-all watch reactor that allows us to inject the watcherStarted channel. We will later wait on this channel before
	// using the fake client. See waitForInformerWatcher().
	client.PrependWatchReactor("*", func(action clienttesting.Action) (handled bool, ret watch.Interface, err error) {
		gvr := action.GetResource()
		ns := action.GetNamespace()
		watch, err := client.Tracker().Watch(gvr, ns)
		if err != nil {
			return false, nil, err
		}
		close(w.watcherStarted)
		return true, watch, nil
	})
	return w
}

func newMutatingWebhook(t *testing.T, client kubernetes.Interface, name, bundle string) *admissionv1.MutatingWebhookConfiguration {
	webhook := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			ResourceVersion: "1",
		},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				ClientConfig: admissionv1.WebhookClientConfig{
					CABundle: []byte(bundle),
				},
			},
		},
	}
	_, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(context.Background(), webhook, metav1.CreateOptions{})
	require.NoError(t, err)
	return webhook
}

type fakeAPIServiceClient struct {
	apiServiceClient
	watcherStarted chan struct{}
}

func newFakeAPIServiceClient(config *Configuration) *fakeAPIServiceClient {
	// NewSimpleClientset is deprecated, but the aggregator package doesn't provide
	// NewClientset yet (only available when apply configurations are generated).
	client := fakeaggregator.NewSimpleClientset() //nolint:staticcheck // https://github.com/spiffe/spire/issues/6530: NewSimpleClientset is deprecated, but no alternative exists for aggregator.
	a := &fakeAPIServiceClient{
		apiServiceClient: apiServiceClient{
			Interface:       client,
			apiServiceLabel: config.APIServiceLabel,
			factory: aggregatorinformers.NewSharedInformerFactoryWithOptions(
				client,
				0,
				aggregatorinformers.WithTweakListOptions(func(options *metav1.ListOptions) {
					options.LabelSelector = fmt.Sprintf("%s=true", config.APIServiceLabel)
				}),
			),
		},
		watcherStarted: make(chan struct{}),
	}

	// A catch-all watch reactor that allows us to inject the watcherStarted channel. We will later wait on this channel before
	// using the fake client. See waitForInformerWatcher().
	client.PrependWatchReactor("*", func(action clienttesting.Action) (handled bool, ret watch.Interface, err error) {
		gvr := action.GetResource()
		ns := action.GetNamespace()
		watch, err := client.Tracker().Watch(gvr, ns)
		if err != nil {
			return false, nil, err
		}
		close(a.watcherStarted)
		return true, watch, nil
	})
	return a
}

func newAPIService(t *testing.T, client aggregator.Interface, name, bundle string) *apiregistrationv1.APIService {
	apiService := &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			ResourceVersion: "1",
		},
		Spec: apiregistrationv1.APIServiceSpec{
			CABundle: []byte(bundle),
		},
	}
	_, err := client.ApiregistrationV1().APIServices().Create(context.Background(), apiService, metav1.CreateOptions{})
	require.NoError(t, err)
	return apiService
}

type test struct {
	identityProvider *fakeidentityprovider.IdentityProvider
	rawPlugin        *Plugin
	notifier         *notifier.V1
	clients          []kubeClient
	kubeClient       *fakeKubeClient
	webhookClient    *fakeWebhookClient
	apiServiceClient *fakeAPIServiceClient
}

type testOptions struct {
	trustDomain      spiffeid.TrustDomain
	plainConfig      string
	kubeClientError  bool
	doConfigure      bool
	informerCallback informerCallback
}

type testOption func(*testOptions)

func withPlainConfig(plainConfig string) testOption {
	return func(args *testOptions) {
		args.plainConfig = plainConfig
	}
}

func withNoConfigure() testOption {
	return func(args *testOptions) {
		args.doConfigure = false
	}
}

func withInformerCallback(callback informerCallback) testOption {
	return func(args *testOptions) {
		args.informerCallback = callback
	}
}

func setupTest(t *testing.T, options ...testOption) *test {
	args := &testOptions{
		doConfigure: true,
		trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		plainConfig: fmt.Sprintf(`
		namespace = "%s"
		config_map = "%s"
		config_map_key = "%s"
		`, defaultNamespace, defaultConfigMap, defaultConfigMapKey),
	}

	for _, opt := range options {
		opt(args)
	}

	config := new(Configuration)
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
	raw.hooks.newKubeClients = func(c *Configuration) ([]kubeClient, error) {
		if args.kubeClientError {
			return nil, errors.New("kube client not configured")
		}

		test.clients = append([]kubeClient{}, test.kubeClient)

		if c.WebhookLabel != "" {
			test.webhookClient = newFakeWebhookClient(c)
			test.clients = append(test.clients, test.webhookClient)
		}
		if c.APIServiceLabel != "" {
			test.apiServiceClient = newFakeAPIServiceClient(c)
			test.clients = append(test.clients, test.apiServiceClient)
		}

		return test.clients, nil
	}

	if args.informerCallback != nil {
		raw.hooks.informerCallback = args.informerCallback
	}

	if args.doConfigure {
		plugintest.Load(
			t,
			builtIn(raw),
			notifier,
			plugintest.HostServices(identityproviderv1.IdentityProviderServiceServer(identityProvider)),
			plugintest.CoreConfig(catalog.CoreConfig{
				TrustDomain: args.trustDomain,
			}),
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

// waitForInformerWatcher wait until the watcher embedded in the informer starts up. The fake client doesn't support
// resource versions, so any writes to the fake client after the informer's initial LIST and before the informer
// establishing the watcher will be missed by the informer.
func waitForInformerWatcher(t *testing.T, watcher chan struct{}) {
	select {
	case <-watcher:
	case <-time.After(testTimeout):
		require.FailNow(t, "timed out waiting for watcher to start")
	}
}
