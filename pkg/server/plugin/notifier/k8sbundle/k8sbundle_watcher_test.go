package k8sbundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	identityproviderv0 "github.com/spiffe/spire/proto/spire/hostservice/server/identityprovider/v0"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
)

const (
	testTimeout = time.Minute
)

func (s *Suite) TestBundleWatcherErrorsWhenCannotCreateClient() {
	s.withKubeClient(nil, "")

	s.configure("")

	_, err := newBundleWatcher(context.TODO(), s.raw, s.raw.config)
	s.Require().Equal(err.Error(), "kube client not configured")
}

func (s *Suite) TestBundleWatchersStartsAndStops() {
	s.configure("")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error)
	watcherStarted := make(chan struct{})
	watcher, err := newBundleWatcher(ctx, s.raw, s.raw.config)
	s.Require().NoError(err)

	watcher.hooks.watch = func(ctx context.Context) error {
		watcherStarted <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}
	go func() {
		errCh <- watcher.Watch(ctx)
	}()

	timer := time.NewTimer(testTimeout)
	defer timer.Stop()

	select {
	case <-watcherStarted:
	case err := <-errCh:
		if err != nil {
			s.Require().FailNow(fmt.Sprintf("watcher.Watch() unexpected exit: %v", err))
		} else {
			s.Require().FailNow("watcher.Watch() unexpected exit")
		}
	case <-timer.C:
		s.Require().FailNow("timed out waiting for watcher to start")
	}

	cancel()

	select {
	case err := <-errCh:
		s.Require().Equal(err.Error(), "context canceled")
	case <-timer.C:
		s.Require().FailNow("timed out waiting for watcher.Watch() to return")
	}
}

func (s *Suite) TestBundleWatcherUpdateConfig() {
	w := newFakeWebhook()
	a := newFakeAPIService()
	client := []kubeClient{w, a}
	s.withKubeClient(client, "/some/file/path")

	s.configure(`
webhook_label = "WEBHOOK_LABEL"
api_service_label = "API_SERVICE_LABEL"
kube_config_file_path = "/some/file/path"
`)
	s.Require().Eventually(func() bool {
		return w.getWatchLabel() == "WEBHOOK_LABEL"
	}, testTimeout, time.Second)

	s.Require().Eventually(func() bool {
		return a.getWatchLabel() == "API_SERVICE_LABEL"
	}, testTimeout, time.Second)

	s.configure(`
webhook_label = "WEBHOOK_LABEL2"
api_service_label = "API_SERVICE_LABEL2"
kube_config_file_path = "/some/file/path"
`)
	s.Require().Eventually(func() bool {
		return w.getWatchLabel() == "WEBHOOK_LABEL2"
	}, testTimeout, time.Second)

	s.Require().Eventually(func() bool {
		return a.getWatchLabel() == "API_SERVICE_LABEL2"
	}, testTimeout, time.Second)
}

func (s *Suite) TestBundleWatcherAddWebhookEvent() {
	w := newFakeWebhook()
	s.withKubeClient([]kubeClient{w}, "/some/file/path")

	s.configure(`
webhook_label = "WEBHOOK_LABEL"
kube_config_file_path = "/some/file/path"
`)

	webhook := newWebhook()
	s.r.AppendBundle(testBundle)
	w.setWebhook(webhook)
	w.addWatchEvent(webhook)
	s.Require().Eventually(func() bool {
		return s.Equal(&admissionv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:            webhook.Name,
				ResourceVersion: "2",
			},
			Webhooks: []admissionv1.MutatingWebhook{
				{
					ClientConfig: admissionv1.WebhookClientConfig{
						CABundle: []byte(testBundleData),
					},
				},
			},
		}, w.getWebhook(webhook.Name))
	}, testTimeout, time.Second)
}

func (s *Suite) TestBundleWatcherAddAPIServiceEvent() {
	a := newFakeAPIService()
	s.withKubeClient([]kubeClient{a}, "/some/file/path")

	s.configure(`
api_service_label = "API_SERVICE_LABEL"
kube_config_file_path = "/some/file/path"
`)
	s.r.AppendBundle(testBundle)

	apiService := newAPIService()
	a.setAPIService(apiService)
	a.addWatchEvent(apiService)
	s.Require().Eventually(func() bool {
		return s.Equal(&apiregistrationv1.APIService{
			ObjectMeta: metav1.ObjectMeta{
				Name:            apiService.Name,
				ResourceVersion: "2",
			},
			Spec: apiregistrationv1.APIServiceSpec{
				CABundle: []byte(testBundleData),
			},
		}, a.getAPIService(apiService.Name))
	}, testTimeout, time.Second)
}

type fakeWebhook struct {
	mu         sync.RWMutex
	fakeWatch  *watch.FakeWatcher
	webhooks   map[string]*admissionv1.MutatingWebhookConfiguration
	watchLabel string
}

func newFakeWebhook() *fakeWebhook {
	w := &fakeWebhook{
		fakeWatch: watch.NewFake(),
		webhooks:  make(map[string]*admissionv1.MutatingWebhookConfiguration),
	}
	return w
}

func (w *fakeWebhook) Get(ctx context.Context, namespace, name string) (runtime.Object, error) {
	entry := w.getWebhook(name)
	if entry == nil {
		return nil, errors.New("not found")
	}
	return entry, nil
}

func (w *fakeWebhook) GetList(ctx context.Context, config *pluginConfig) (runtime.Object, error) {
	list := w.getWebhookList()
	if list.Items == nil {
		return nil, errors.New("not found")
	}
	return list, nil
}

func (w *fakeWebhook) CreatePatch(ctx context.Context, config *pluginConfig, obj runtime.Object, resp *identityproviderv0.FetchX509IdentityResponse) (runtime.Object, error) {
	webhook, ok := obj.(*admissionv1.MutatingWebhookConfiguration)
	if !ok {
		return nil, k8sErr.New("wrong type, expecting mutating webhook")
	}
	return &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: webhook.ResourceVersion,
		},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				ClientConfig: admissionv1.WebhookClientConfig{
					CABundle: []byte(bundleData(resp.Bundle)),
				},
			},
		},
	}, nil
}

func (w *fakeWebhook) Patch(ctx context.Context, namespace, name string, patchBytes []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	entry, ok := w.webhooks[name]
	if !ok {
		return errors.New("not found")
	}

	patchedWebhook := new(admissionv1.MutatingWebhookConfiguration)
	if err := json.Unmarshal(patchBytes, patchedWebhook); err != nil {
		return err
	}
	resourceVersion, err := strconv.Atoi(patchedWebhook.ResourceVersion)
	if err != nil {
		return errors.New("patch does not have resource version")
	}
	entry.ResourceVersion = fmt.Sprint(resourceVersion + 1)
	for i := range entry.Webhooks {
		entry.Webhooks[i].ClientConfig.CABundle = patchedWebhook.Webhooks[i].ClientConfig.CABundle
	}
	return nil
}

func (w *fakeWebhook) Watch(ctx context.Context, config *pluginConfig) (watch.Interface, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.watchLabel = config.WebhookLabel
	return w.fakeWatch, nil
}

func (w *fakeWebhook) getWebhook(name string) *admissionv1.MutatingWebhookConfiguration {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.webhooks[name]
}

func (w *fakeWebhook) getWebhookList() *admissionv1.MutatingWebhookConfigurationList {
	w.mu.RLock()
	defer w.mu.RUnlock()
	webhookList := &admissionv1.MutatingWebhookConfigurationList{}
	for _, webhook := range w.webhooks {
		webhookList.Items = append(webhookList.Items, *webhook)
	}
	return webhookList
}

func (w *fakeWebhook) setWebhook(webhook *admissionv1.MutatingWebhookConfiguration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.webhooks[webhook.Name] = webhook
}

func (w *fakeWebhook) addWatchEvent(obj runtime.Object) {
	w.fakeWatch.Add(obj)
}

func (w *fakeWebhook) getWatchLabel() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.watchLabel
}

func newWebhook() *admissionv1.MutatingWebhookConfiguration {
	return &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "spire-webhook",
			ResourceVersion: "1",
		},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				ClientConfig: admissionv1.WebhookClientConfig{},
			},
		},
	}
}

type fakeAPIService struct {
	mu          sync.RWMutex
	fakeWatch   *watch.FakeWatcher
	apiServices map[string]*apiregistrationv1.APIService
	watchLabel  string
}

func newFakeAPIService() *fakeAPIService {
	return &fakeAPIService{
		fakeWatch:   watch.NewFake(),
		apiServices: make(map[string]*apiregistrationv1.APIService),
	}
}

func (a *fakeAPIService) Get(ctx context.Context, namespace, name string) (runtime.Object, error) {
	entry := a.getAPIService(name)
	if entry == nil {
		return nil, errors.New("not found")
	}
	return entry, nil
}

func (a *fakeAPIService) GetList(ctx context.Context, config *pluginConfig) (runtime.Object, error) {
	list := a.getAPIServiceList()
	if list.Items == nil {
		return nil, errors.New("not found")
	}
	return list, nil
}

func (a *fakeAPIService) CreatePatch(ctx context.Context, config *pluginConfig, obj runtime.Object, resp *identityproviderv0.FetchX509IdentityResponse) (runtime.Object, error) {
	webhook, ok := obj.(*apiregistrationv1.APIService)
	if !ok {
		return nil, k8sErr.New("wrong type, expecting API service")
	}
	return &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: webhook.ResourceVersion,
		},
		Spec: apiregistrationv1.APIServiceSpec{
			CABundle: []byte(bundleData(resp.Bundle)),
		},
	}, nil
}

func (a *fakeAPIService) Patch(ctx context.Context, namespace, name string, patchBytes []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry, ok := a.apiServices[name]
	if !ok {
		return errors.New("not found")
	}

	patchedAPIService := new(apiregistrationv1.APIService)
	if err := json.Unmarshal(patchBytes, patchedAPIService); err != nil {
		return err
	}
	resourceVersion, err := strconv.Atoi(patchedAPIService.ResourceVersion)
	if err != nil {
		return errors.New("patch does not have resource version")
	}
	entry.ResourceVersion = fmt.Sprint(resourceVersion + 1)
	entry.Spec.CABundle = patchedAPIService.Spec.CABundle
	return nil
}

func (a *fakeAPIService) Watch(ctx context.Context, config *pluginConfig) (watch.Interface, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.watchLabel = config.APIServiceLabel
	return a.fakeWatch, nil
}

func (a *fakeAPIService) getAPIService(name string) *apiregistrationv1.APIService {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.apiServices[name]
}

func (a *fakeAPIService) getAPIServiceList() *apiregistrationv1.APIServiceList {
	a.mu.RLock()
	defer a.mu.RUnlock()
	apiServiceList := &apiregistrationv1.APIServiceList{}
	for _, apiService := range a.apiServices {
		apiServiceList.Items = append(apiServiceList.Items, *apiService)
	}
	return apiServiceList
}

func (a *fakeAPIService) setAPIService(apiService *apiregistrationv1.APIService) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.apiServices[apiService.Name] = apiService
}

func (a *fakeAPIService) addWatchEvent(obj runtime.Object) {
	a.fakeWatch.Add(obj)
}

func (a *fakeAPIService) getWatchLabel() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.watchLabel
}

func newAPIService() *apiregistrationv1.APIService {
	return &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "spire-api-service",
			ResourceVersion: "1",
		},
		Spec: apiregistrationv1.APIServiceSpec{},
	}
}
