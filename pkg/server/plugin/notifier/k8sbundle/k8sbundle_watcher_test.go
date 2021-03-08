package k8sbundle

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testTimeout = time.Second * 2
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
	s.withKubeClient(s.k, "/some/file/path")

	s.configure(`
webhook_label = "LABEL"
kube_config_file_path = "/some/file/path"
`)
	s.Require().Eventually(func() bool {
		return s.k.getWatchLabel() == "LABEL"
	}, testTimeout, time.Second)

	s.configure(`
webhook_label = "LABEL2"
kube_config_file_path = "/some/file/path"
`)
	s.Require().Eventually(func() bool {
		return s.k.getWatchLabel() == "LABEL2"
	}, testTimeout, time.Second)
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
	}, testTimeout, time.Second)
}
