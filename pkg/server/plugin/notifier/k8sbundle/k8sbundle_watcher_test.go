package k8sbundle

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	testTimeout = time.Minute
)

func (s *Suite) TestBundleWatcherErrorsWhenCannotCreateClient() {
	s.withKubeClient(nil, "")

	s.configure("")

	watcher := newBundleWatcher(s.raw)
	err := watcher.Start()

	s.Require().Equal(err.Error(), "kube client not configured")
}

func (s *Suite) TestBundleWatchersStartsAndStops() {
	s.configure("")

	errCh := make(chan error)
	watcherStarted := make(chan struct{})
	watcher := newBundleWatcher(s.raw)
	watcher.hooks.watcherEvents = func(ctx context.Context, c *pluginConfig, clients []kubeClient, watchers []watch.Interface) error {
		watcherStarted <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}
	go func() {
		errCh <- watcher.Start()
	}()

	timer := time.NewTimer(testTimeout)
	defer timer.Stop()

	select {
	case <-watcherStarted:
	case err := <-errCh:
		if err != nil {
			s.Require().FailNow(fmt.Sprintf("watcher.Start() unexpected exit: %v", err))
		} else {
			s.Require().FailNow("watcher.Start() unexpected exit")
		}
	case <-timer.C:
		s.Require().FailNow("timed out waiting for watcher to start")
	}

	watcher.Stop()

	select {
	case err := <-errCh:
		s.Require().NoError(err)
	case <-timer.C:
		s.Require().FailNow("timed out waiting for watcher.Start() to return")
	}
}

func (s *Suite) TestBundleWatcherStartFailsIfAlreadyStarted() {
	s.configure("")

	watcher := newBundleWatcher(s.raw)
	watcher.hooks.watcherEvents = func(ctx context.Context, c *pluginConfig, clients []kubeClient, watchers []watch.Interface) error {
		<-ctx.Done()
		return ctx.Err()
	}
	defer watcher.Stop()

	errs := make(chan error, 2)
	go func() {
		errs <- watcher.Start()
	}()
	go func() {
		errs <- watcher.Start()
	}()

	timer := time.NewTimer(testTimeout)
	defer timer.Stop()

	// First call should fail because the client has already started
	select {
	case err := <-errs:
		s.Require().EqualError(err, "already started")
	case <-timer.C:
		s.Require().FailNow("timed out waiting for watcher.Start() to return")
	}

	watcher.Stop()

	// Second call should return normally
	select {
	case err := <-errs:
		s.Require().NoError(err)
	case <-timer.C:
		s.Require().FailNow("timed out waiting for watcher.Start() to return")
	}
}

func (s *Suite) TestBundleWatcherUpdateConfig() {
	s.withKubeClient(s.k, "/some/file/path")

	s.configure(`
webhook_label = "LABEL"
kube_config_file_path = "/some/file/path"
`)
	watchLabel := s.k.getWatchLabel()
	s.Require().Equal("LABEL", watchLabel)

	s.configure(`
webhook_label = "LABEL2"
kube_config_file_path = "/some/file/path"
`)
	watchLabel = s.k.getWatchLabel()
	s.Require().Equal("LABEL2", watchLabel)
}

func (s *Suite) TestBundleWatcherAddEvent() {
	s.withKubeClient(s.k, "/some/file/path")
	s.configure(`
webhook_label = "LABEL"
kube_config_file_path = "/some/file/path"
`)

	configMap := newConfigMap()
	s.r.AppendBundle(testBundle)
	s.k.setConfigMap(configMap)
	s.k.addWatchEvent(configMap)

	s.Require().Eventually(func() bool {
		return s.Equal(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "spire",
				Name:            "spire-bundle",
				ResourceVersion: "2",
			},
			Data: map[string]string{
				"bundle.crt": testBundleData,
			},
		}, s.k.getConfigMap("spire", "spire-bundle"))
	}, testTimeout, time.Millisecond)
}
