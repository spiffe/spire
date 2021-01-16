package k8sbundle

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/watch"
)

const (
	testTimeout = time.Second
)

func (s *Suite) TestBundleWatchersStartsAndStops() {
	watcher := newBundleWatcher(s.raw)
	watcherDone := false
	go func() {
		watcher.Start()
		watcherDone = true
	}()

	s.Require().Eventually(func() bool {
		watcher.Stop()
		return watcherDone == true
	}, time.Second, time.Millisecond)

}

func (s *Suite) TestBundleWatcherStartFailsIfAlreadyStarted() {
	s.configure("")

	watcher := newBundleWatcher(s.raw)
	watcher.hooks.watcherFunc = func(ctx context.Context, c *pluginConfig, clients []kubeClient, watchers []watch.Interface) error {
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
