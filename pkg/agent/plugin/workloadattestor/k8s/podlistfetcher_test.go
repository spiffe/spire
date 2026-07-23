package k8s

import (
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fastjson"
)

const testPodListFetchRetryInterval = time.Second

func TestPodListFetcherCachesAndSpacesRequestsFromStart(t *testing.T) {
	fetcher, mockClock := newTestPodListFetcher(t)

	var requestCount atomic.Int32
	configureTestFetcher(t, fetcher, func(context.Context) (map[string]*fastjson.Value, error) {
		requestCount.Add(1)
		return map[string]*fastjson.Value{}, nil
	})

	first, err := fetcher.fetchNext(t.Context(), 0)
	require.NoError(t, err)
	require.EqualValues(t, 1, first.version)

	cached, err := fetcher.fetchNext(t.Context(), 0)
	require.NoError(t, err)
	require.Equal(t, first.version, cached.version)
	require.EqualValues(t, 1, requestCount.Load())

	nextResult := make(chan podListFetchResult, 1)
	go func() {
		podList, err := fetcher.fetchNext(t.Context(), first.version)
		nextResult <- podListFetchResult{versionedPodList: podList, err: err}
	}()

	mockClock.WaitForTimer(time.Minute, "waiting for pod list retry timer")
	mockClock.Add(testPodListFetchRetryInterval - time.Nanosecond)
	require.Never(t, func() bool {
		return requestCount.Load() > 1
	}, 10*time.Millisecond, time.Millisecond)

	mockClock.Add(time.Nanosecond)
	next := <-nextResult
	require.NoError(t, next.err)
	require.EqualValues(t, 2, next.version)
	require.EqualValues(t, 2, requestCount.Load())
}

func TestPodListFetcherSharesFetchAcrossConcurrentCallers(t *testing.T) {
	fetcher, _ := newTestPodListFetcher(t)

	started := make(chan struct{})
	release := make(chan struct{})
	var requestCount atomic.Int32
	configureTestFetcher(t, fetcher, func(context.Context) (map[string]*fastjson.Value, error) {
		requestCount.Add(1)
		close(started)
		<-release
		return map[string]*fastjson.Value{}, nil
	})

	const callerCount = 16
	var ready sync.WaitGroup
	ready.Add(callerCount)
	start := make(chan struct{})
	results := make(chan podListFetchResult, callerCount)
	for range callerCount {
		go func() {
			ready.Done()
			<-start
			podList, err := fetcher.fetchNext(t.Context(), 0)
			results <- podListFetchResult{versionedPodList: podList, err: err}
		}()
	}
	ready.Wait()
	close(start)
	<-started
	close(release)

	for range callerCount {
		result := <-results
		require.NoError(t, result.err)
		require.EqualValues(t, 1, result.version)
	}
	require.EqualValues(t, 1, requestCount.Load())
}

func TestPodListFetcherStartsOverdueRequestAfterSlowRequest(t *testing.T) {
	fetcher, mockClock := newTestPodListFetcher(t)

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var requestCount atomic.Int32
	configureTestFetcher(t, fetcher, func(context.Context) (map[string]*fastjson.Value, error) {
		if requestCount.Add(1) == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		return map[string]*fastjson.Value{}, nil
	})

	firstResult := make(chan podListFetchResult, 1)
	go func() {
		podList, err := fetcher.fetchNext(t.Context(), 0)
		firstResult <- podListFetchResult{versionedPodList: podList, err: err}
	}()

	<-firstStarted
	mockClock.Add(2 * testPodListFetchRetryInterval)
	close(releaseFirst)
	first := <-firstResult
	require.NoError(t, first.err)

	second, err := fetcher.fetchNext(t.Context(), first.version)
	require.NoError(t, err)
	require.EqualValues(t, 2, second.version)
	require.EqualValues(t, 2, requestCount.Load())
}

func TestPodListFetcherDoesNotCacheFailures(t *testing.T) {
	fetcher, mockClock := newTestPodListFetcher(t)

	fetchErr := errors.New("fetch failed")
	var requestCount atomic.Int32
	configureTestFetcher(t, fetcher, func(context.Context) (map[string]*fastjson.Value, error) {
		if requestCount.Add(1) == 1 {
			return nil, fetchErr
		}
		return map[string]*fastjson.Value{}, nil
	})

	_, err := fetcher.fetchNext(t.Context(), 0)
	require.ErrorIs(t, err, fetchErr)

	secondResult := make(chan podListFetchResult, 1)
	go func() {
		podList, err := fetcher.fetchNext(t.Context(), 0)
		secondResult <- podListFetchResult{versionedPodList: podList, err: err}
	}()

	mockClock.WaitForTimer(time.Minute, "waiting for retry after failed pod list request")
	select {
	case result := <-secondResult:
		t.Fatalf("request returned before retry interval elapsed: %v", result.err)
	default:
	}

	mockClock.Add(testPodListFetchRetryInterval)
	second := <-secondResult
	require.NoError(t, second.err)
	require.EqualValues(t, 1, second.version)
	require.EqualValues(t, 2, requestCount.Load())
}

func TestPodListFetcherDoesNotRevalidateStaleCacheAfterFailure(t *testing.T) {
	fetcher, mockClock := newTestPodListFetcher(t)

	fetchErr := errors.New("fetch failed")
	var requestCount atomic.Int32
	configureTestFetcher(t, fetcher, func(context.Context) (map[string]*fastjson.Value, error) {
		if requestCount.Add(1) == 2 {
			return nil, fetchErr
		}
		return map[string]*fastjson.Value{}, nil
	})

	first, err := fetcher.fetchNext(t.Context(), 0)
	require.NoError(t, err)
	require.EqualValues(t, 1, first.version)

	mockClock.Add(testPodListFetchRetryInterval)
	_, err = fetcher.fetchNext(t.Context(), 0)
	require.ErrorIs(t, err, fetchErr)

	nextResult := make(chan podListFetchResult, 1)
	go func() {
		podList, err := fetcher.fetchNext(t.Context(), 0)
		nextResult <- podListFetchResult{versionedPodList: podList, err: err}
	}()

	mockClock.WaitForTimer(time.Minute, "waiting for retry after failed cache refresh")
	select {
	case result := <-nextResult:
		t.Fatalf("request returned stale cached result after failed refresh: %v", result.err)
	default:
	}

	mockClock.Add(testPodListFetchRetryInterval)
	next := <-nextResult
	require.NoError(t, next.err)
	require.EqualValues(t, 2, next.version)
	require.EqualValues(t, 3, requestCount.Load())
}

func TestPodListFetcherDoesNotPollWithoutWaiters(t *testing.T) {
	fetcher, mockClock := newTestPodListFetcher(t)

	var requestCount atomic.Int32
	configureTestFetcher(t, fetcher, func(context.Context) (map[string]*fastjson.Value, error) {
		requestCount.Add(1)
		return map[string]*fastjson.Value{}, nil
	})

	_, err := fetcher.fetchNext(t.Context(), 0)
	require.NoError(t, err)

	mockClock.Add(10 * testPodListFetchRetryInterval)
	require.EqualValues(t, 1, requestCount.Load())

	_, err = fetcher.fetchNext(t.Context(), 0)
	require.NoError(t, err)
	require.EqualValues(t, 2, requestCount.Load())
}

func TestPodListFetcherLateWaiterDoesNotInheritPreviousCallerCancellation(t *testing.T) {
	fetcher, _ := newTestPodListFetcher(t)

	started := make(chan struct{})
	release := make(chan struct{})
	var requestCount atomic.Int32
	configureTestFetcher(t, fetcher, func(ctx context.Context) (map[string]*fastjson.Value, error) {
		requestCount.Add(1)
		close(started)
		<-release
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return map[string]*fastjson.Value{}, nil
	})

	ctx, cancel := context.WithCancel(t.Context())
	firstResult := make(chan podListFetchResult, 1)
	go func() {
		podList, err := fetcher.fetchNext(ctx, 0)
		firstResult <- podListFetchResult{versionedPodList: podList, err: err}
	}()

	<-started

	// Cancel the only waiter, leaving the kubelet request temporarily without
	// any callers. The request must remain in flight so that a waiter arriving
	// during this window does not receive a context cancellation it did not
	// cause.
	cancel()
	require.ErrorIs(t, (<-firstResult).err, context.Canceled)

	// Submit directly to ensure the new waiter is registered before the
	// kubelet request completes.
	secondResult := make(chan podListFetchResult, 1)
	fetcher.actionCh <- func() { fetcher.registerFetchRequest(0, secondResult) }

	close(release)
	require.NoError(t, (<-secondResult).err)
	require.EqualValues(t, 1, requestCount.Load())
}

func TestPodListFetcherCallerCancellationDoesNotCancelSharedFetch(t *testing.T) {
	fetcher, _ := newTestPodListFetcher(t)

	started := make(chan struct{})
	release := make(chan struct{})
	var requestCount atomic.Int32
	configureTestFetcher(t, fetcher, func(context.Context) (map[string]*fastjson.Value, error) {
		requestCount.Add(1)
		close(started)
		<-release
		return map[string]*fastjson.Value{}, nil
	})

	ctx, cancel := context.WithCancel(t.Context())
	firstResult := make(chan podListFetchResult, 1)
	go func() {
		podList, err := fetcher.fetchNext(ctx, 0)
		firstResult <- podListFetchResult{versionedPodList: podList, err: err}
	}()

	<-started

	// Submit directly so the test knows the fetcher registered the second
	// waiter before the first one is canceled.
	secondResult := make(chan podListFetchResult, 1)
	fetcher.actionCh <- func() { fetcher.registerFetchRequest(0, secondResult) }

	cancel()
	require.ErrorIs(t, (<-firstResult).err, context.Canceled)
	close(release)
	require.NoError(t, (<-secondResult).err)
	require.EqualValues(t, 1, requestCount.Load())
}

func TestPodListFetcherCloseWaitsForFetch(t *testing.T) {
	mockClock := clock.NewMock(t)
	fetcher := newPodListFetcher(mockClock, "")

	started := make(chan struct{})
	fetchDone := make(chan struct{})
	configureTestFetcher(t, fetcher, func(ctx context.Context) (map[string]*fastjson.Value, error) {
		close(started)
		<-ctx.Done()
		close(fetchDone)
		return nil, ctx.Err()
	})

	result := make(chan podListFetchResult, 1)
	go func() {
		podList, err := fetcher.fetchNext(t.Context(), 0)
		result <- podListFetchResult{versionedPodList: podList, err: err}
	}()
	<-started

	fetcher.close()
	<-fetchDone
	require.ErrorIs(t, (<-result).err, errPodListFetcherClosed)
}

func TestPodListFetcherCloseWaitsForKubeletClientBuild(t *testing.T) {
	fetcher := newPodListFetcher(clock.NewMock(t), "")

	started := make(chan struct{})
	release := make(chan struct{})
	buildDone := make(chan struct{})
	fetcher.buildClient = func(podListFetcherConfig, *kubeletClient) (*kubeletClient, error) {
		close(started)
		<-release
		close(buildDone)
		return nil, errors.New("build failed")
	}

	configureResult := make(chan error, 1)
	go func() {
		configureResult <- fetcher.configure(t.Context(), podListFetcherConfig{})
	}()
	<-started

	closeResult := make(chan struct{})
	go func() {
		fetcher.close()
		close(closeResult)
	}()
	require.Never(t, func() bool {
		select {
		case <-closeResult:
			return true
		default:
			return false
		}
	}, 10*time.Millisecond, time.Millisecond)

	close(release)
	<-closeResult
	<-buildDone
	require.Error(t, <-configureResult)
}

func TestPodListFetcherConfigureAfterClose(t *testing.T) {
	fetcher := newPodListFetcher(clock.NewMock(t), "")
	fetcher.close()

	err := fetcher.configure(t.Context(), podListFetcherConfig{})
	require.ErrorIs(t, err, errPodListFetcherClosed)
}

func TestPodListFetcherConfigureWaitsForAcceptedRequestAfterContextCancellation(t *testing.T) {
	fetcher, _ := newTestPodListFetcher(t)

	started := make(chan struct{})
	release := make(chan struct{})
	fetcher.buildClient = func(config podListFetcherConfig, previousClient *kubeletClient) (*kubeletClient, error) {
		close(started)
		<-release
		return fetcher.buildKubeletClient(config, previousClient)
	}

	ctx, cancel := context.WithCancel(t.Context())
	configResult := make(chan error, 1)
	go func() {
		configResult <- fetcher.configure(ctx, podListFetcherConfig{
			port: 1,
		})
	}()
	<-started

	cancel()
	select {
	case err := <-configResult:
		t.Fatalf("configure returned before the accepted request completed: %v", err)
	default:
	}

	close(release)
	require.NoError(t, <-configResult)
	require.Equal(t, 1, fetcher.config.port)
}

func TestPodListFetcherFailedConfigurePreservesClient(t *testing.T) {
	fetcher, _ := newTestPodListFetcher(t)
	require.NoError(t, fetcher.configure(t.Context(), podListFetcherConfig{port: 1}))

	buildErr := errors.New("build failed")
	fetcher.buildClient = func(podListFetcherConfig, *kubeletClient) (*kubeletClient, error) {
		return nil, buildErr
	}
	require.ErrorIs(t, fetcher.configure(t.Context(), podListFetcherConfig{port: 2}), buildErr)
	require.Equal(t, 1, fetcher.config.port)
	require.Equal(t, "http://127.0.0.1:1", fetcher.client.endpoint.String())
}

func TestPodListFetcherRunProcessesRequestsWhileConfiguringKubeletClient(t *testing.T) {
	fetcher, _ := newTestPodListFetcher(t)

	require.NoError(t, fetcher.configure(t.Context(), podListFetcherConfig{
		pollRetryInterval: time.Second,
		port:              1,
		reloadInterval:    time.Hour,
	}))

	started := make(chan struct{})
	release := make(chan struct{})
	fetcher.buildClient = func(config podListFetcherConfig, previousClient *kubeletClient) (*kubeletClient, error) {
		close(started)
		<-release
		return fetcher.buildKubeletClient(config, previousClient)
	}
	fetcher.fetch = func(ctx context.Context, _ *kubeletClient) (map[string]*fastjson.Value, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	configResult := make(chan error, 1)
	go func() {
		configResult <- fetcher.configure(t.Context(), podListFetcherConfig{
			pollRetryInterval: time.Second,
			port:              2,
			reloadInterval:    time.Hour,
		})
	}()
	<-started

	resultCh := make(chan podListFetchResult, 1)
	requestReceived := make(chan struct{})
	go func() {
		fetcher.actionCh <- func() { fetcher.registerFetchRequest(0, resultCh) }
		close(requestReceived)
	}()
	require.Eventually(t, func() bool {
		select {
		case <-requestReceived:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)

	cancellationReceived := make(chan struct{})
	go func() {
		fetcher.actionCh <- func() { fetcher.cancelFetchRequest(resultCh) }
		close(cancellationReceived)
	}()
	require.Eventually(t, func() bool {
		select {
		case <-cancellationReceived:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)

	close(release)
	require.NoError(t, <-configResult)
}

func TestPodListFetcherDoesNotInstallClientFromStaleFetchResult(t *testing.T) {
	transportConfig := kubeletTransportConfig{
		secure:                  true,
		skipKubeletVerification: true,
		port:                    2,
	}
	newClient := func(token string) *kubeletClient {
		client, err := newKubeletClient(transportConfig, token)
		require.NoError(t, err)
		return client
	}

	fetcher := podListFetcher{
		clock:  clock.NewMock(t),
		client: newClient("new-token"),
	}

	fetcher.completeFetch(podListFetchResult{
		versionedPodList: versionedPodList{pods: map[string]*fastjson.Value{}, version: 1},
	}, newClient("old-token"), newClient("old-token"))
	require.Equal(t, "https://127.0.0.1:2", fetcher.client.endpoint.String())
	require.Equal(t, "new-token", fetcher.client.token)
	require.EqualValues(t, 1, fetcher.cachedPodList.version)

	fetcher.completeFetch(podListFetchResult{
		versionedPodList: versionedPodList{pods: map[string]*fastjson.Value{}, version: 2},
	}, fetcher.client, newClient("newest-token"))
	require.Equal(t, "newest-token", fetcher.client.token)
	require.EqualValues(t, 2, fetcher.cachedPodList.version)
}

func TestPodListFetcherReconfigurePreservesCache(t *testing.T) {
	fetcher, mockClock := newTestPodListFetcher(t)

	var oldRequestCount atomic.Int32
	var newRequestCount atomic.Int32
	fetcher.fetch = func(_ context.Context, client *kubeletClient) (map[string]*fastjson.Value, error) {
		if client.endpoint.Port() == "1" {
			oldRequestCount.Add(1)
		} else {
			newRequestCount.Add(1)
		}
		return map[string]*fastjson.Value{}, nil
	}
	require.NoError(t, fetcher.configure(t.Context(), podListFetcherConfig{
		pollRetryInterval: testPodListFetchRetryInterval,
		port:              1,
	}))

	first, err := fetcher.fetchNext(t.Context(), 0)
	require.NoError(t, err)

	require.NoError(t, fetcher.configure(t.Context(), podListFetcherConfig{
		pollRetryInterval: testPodListFetchRetryInterval,
		port:              2,
	}))

	cached, err := fetcher.fetchNext(t.Context(), 0)
	require.NoError(t, err)
	require.Equal(t, first.version, cached.version)
	require.EqualValues(t, 1, oldRequestCount.Load())
	require.EqualValues(t, 0, newRequestCount.Load())

	nextResult := make(chan podListFetchResult, 1)
	go func() {
		podList, err := fetcher.fetchNext(t.Context(), first.version)
		nextResult <- podListFetchResult{versionedPodList: podList, err: err}
	}()

	mockClock.WaitForTimer(time.Minute, "waiting for reconfigured pod list request")
	require.EqualValues(t, 0, newRequestCount.Load())
	mockClock.Add(testPodListFetchRetryInterval)

	next := <-nextResult
	require.NoError(t, next.err)
	require.Greater(t, next.version, first.version)
	require.EqualValues(t, 1, oldRequestCount.Load())
	require.EqualValues(t, 1, newRequestCount.Load())
}

func TestPodListFetcherReconfigureUpdatesCacheLifetime(t *testing.T) {
	t.Run("Extend", func(t *testing.T) {
		fetcher, mockClock := newTestPodListFetcher(t)

		var requestCount atomic.Int32
		fetcher.fetch = func(context.Context, *kubeletClient) (map[string]*fastjson.Value, error) {
			requestCount.Add(1)
			return map[string]*fastjson.Value{}, nil
		}
		require.NoError(t, fetcher.configure(t.Context(), podListFetcherConfig{
			pollRetryInterval: time.Second,
		}))

		first, err := fetcher.fetchNext(t.Context(), 0)
		require.NoError(t, err)
		mockClock.Add(1500 * time.Millisecond)

		require.NoError(t, fetcher.configure(t.Context(), podListFetcherConfig{
			pollRetryInterval: 2 * time.Second,
		}))
		cached, err := fetcher.fetchNext(t.Context(), 0)
		require.NoError(t, err)
		require.Equal(t, first.version, cached.version)
		require.EqualValues(t, 1, requestCount.Load())
	})

	t.Run("Shorten", func(t *testing.T) {
		fetcher, mockClock := newTestPodListFetcher(t)

		var requestCount atomic.Int32
		fetcher.fetch = func(context.Context, *kubeletClient) (map[string]*fastjson.Value, error) {
			requestCount.Add(1)
			return map[string]*fastjson.Value{}, nil
		}
		require.NoError(t, fetcher.configure(t.Context(), podListFetcherConfig{
			pollRetryInterval: 2 * time.Second,
		}))

		first, err := fetcher.fetchNext(t.Context(), 0)
		require.NoError(t, err)
		mockClock.Add(time.Second)

		require.NoError(t, fetcher.configure(t.Context(), podListFetcherConfig{
			pollRetryInterval: 500 * time.Millisecond,
		}))
		refreshed, err := fetcher.fetchNext(t.Context(), 0)
		require.NoError(t, err)
		require.Greater(t, refreshed.version, first.version)
		require.EqualValues(t, 2, requestCount.Load())
	})
}

func TestPodListFetcherReloadsKubeletClient(t *testing.T) {
	mockClock := clock.NewMock(t)
	firstConfig := podListFetcherConfig{
		port:           1,
		reloadInterval: time.Second,
	}
	fetcher := &podListFetcher{
		clock:    mockClock,
		config:   &firstConfig,
		actionCh: make(chan func(), 1),
		fetch: func(context.Context, *kubeletClient) (map[string]*fastjson.Value, error) {
			return map[string]*fastjson.Value{}, nil
		},
	}
	fetcher.buildClient = fetcher.buildKubeletClient
	runFetch := func() {
		fetcher.startFetch()
		(<-fetcher.actionCh)()
	}

	runFetch()
	firstClient := fetcher.client

	secondConfig := podListFetcherConfig{
		port:           2,
		reloadInterval: time.Second,
	}
	fetcher.config = &secondConfig
	runFetch()
	require.Same(t, firstClient, fetcher.client)

	mockClock.Add(firstConfig.reloadInterval)
	runFetch()
	require.NotSame(t, firstClient, fetcher.client)
}

func TestPodListFetcherBuildKubeletClientReusesTransportWhenOnlyTokenChanges(t *testing.T) {
	mockClock := clock.NewMock(t)
	rootDir := t.TempDir()
	fetcher := newPodListFetcher(mockClock, rootDir)
	t.Cleanup(fetcher.close)

	const tokenPath = "token"
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, tokenPath), []byte("old-token"), 0o600))

	config := podListFetcherConfig{
		secure:                  true,
		skipKubeletVerification: true,
		tokenPath:               tokenPath,
		reloadInterval:          time.Second,
	}
	client, err := fetcher.buildKubeletClient(config, fetcher.client)
	require.NoError(t, err)
	fetcher.installKubeletClient(client)
	firstClient := fetcher.client
	firstTransport := fetcher.client.transport

	require.NoError(t, os.WriteFile(filepath.Join(rootDir, tokenPath), []byte("new-token"), 0o600))
	client, err = fetcher.buildKubeletClient(config, fetcher.client)
	require.NoError(t, err)
	fetcher.installKubeletClient(client)

	require.NotSame(t, firstClient, fetcher.client)
	require.Same(t, firstTransport, fetcher.client.transport)
	require.Equal(t, "old-token", firstClient.token)
	require.Equal(t, "new-token", fetcher.client.token)
}

func TestPodListFetcherBuildKubeletClientReplacesTransportWhenCAChanges(t *testing.T) {
	mockClock := clock.NewMock(t)
	rootDir := t.TempDir()
	fetcher := newPodListFetcher(mockClock, rootDir)
	t.Cleanup(fetcher.close)

	const caPath = "ca.pem"
	writeTestCA(t, filepath.Join(rootDir, caPath), 1)

	config := podListFetcherConfig{
		secure:                     true,
		kubeletCAPath:              caPath,
		nodeName:                   "localhost",
		useAnonymousAuthentication: true,
		reloadInterval:             time.Second,
	}
	client, err := fetcher.buildKubeletClient(config, fetcher.client)
	require.NoError(t, err)
	fetcher.installKubeletClient(client)
	firstTransport := fetcher.client.transport

	writeTestCA(t, filepath.Join(rootDir, caPath), 2)
	client, err = fetcher.buildKubeletClient(config, fetcher.client)
	require.NoError(t, err)
	fetcher.installKubeletClient(client)

	require.NotSame(t, firstTransport, fetcher.client.transport)
}

func TestPodListFetcherCreatesAndInstallsConfiguredKubeletClient(t *testing.T) {
	fetcher, _ := newTestPodListFetcher(t)

	config := podListFetcherConfig{
		pollRetryInterval: time.Second,
		port:              1,
	}
	usedClient := make(chan *kubeletClient, 1)
	fetcher.fetch = func(_ context.Context, client *kubeletClient) (map[string]*fastjson.Value, error) {
		usedClient <- client
		return map[string]*fastjson.Value{}, nil
	}

	require.NoError(t, fetcher.configure(t.Context(), config))
	_, err := fetcher.fetchNext(t.Context(), 0)
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:1", (<-usedClient).endpoint.String())
}

func TestPodListFetcherConfiguresKubeletClientDuringFetch(t *testing.T) {
	fetcher := podListFetcher{
		clock:       clock.NewMock(t),
		actionCh:    make(chan func(), 1),
		fetchCancel: func() {},
	}
	fetcher.buildClient = fetcher.buildKubeletClient
	config := podListFetcherConfig{port: 1}
	resultCh := make(chan error, 1)

	fetcher.startConfigure(config, resultCh)
	(<-fetcher.actionCh)()
	require.NoError(t, <-resultCh)
	require.Equal(t, "http://127.0.0.1:1", fetcher.client.endpoint.String())
}

func TestPodListFetcherParsePodList(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		response string
		wantUIDs []string
		wantErr  string
	}{
		{
			name: "indexes pods by UID",
			response: `{"items":[
				{"metadata":{"uid":"pod-1"}},
				{"metadata":{"uid":"pod-2"}}
			]}`,
			wantUIDs: []string{"pod-1", "pod-2"},
		},
		{
			name:     "accepts null items as an empty list",
			response: `{"items":null}`,
		},
		{
			name: "ignores pods without a UID",
			response: `{"items":[
				{"metadata":{}},
				{"metadata":{"uid":"pod-1"}}
			]}`,
			wantUIDs: []string{"pod-1"},
		},
		{
			name:     "rejects malformed response",
			response: `{"items":`,
			wantErr:  "unable to parse kubelet response",
		},
		{
			name:     "rejects non-object response",
			response: `[]`,
			wantErr:  "invalid kubelet response: expected an object",
		},
		{
			name:     "rejects response without items",
			response: `{}`,
			wantErr:  "invalid kubelet response: expected an items array",
		},
		{
			name:     "rejects response with non-array items",
			response: `{"items":{}}`,
			wantErr:  "invalid kubelet response: expected an items array",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fetcher := podListFetcher{log: hclog.NewNullLogger()}
			pods, err := fetcher.parsePodList([]byte(testCase.response))
			if testCase.wantErr != "" {
				require.ErrorContains(t, err, testCase.wantErr)
				return
			}

			require.NoError(t, err)
			require.Len(t, pods, len(testCase.wantUIDs))
			for _, uid := range testCase.wantUIDs {
				require.Contains(t, pods, uid)
			}
		})
	}
}

func newTestPodListFetcher(t *testing.T) (*podListFetcher, *clock.Mock) {
	t.Helper()

	mockClock := clock.NewMock(t)
	fetcher := newPodListFetcher(mockClock, "")
	t.Cleanup(fetcher.close)
	return fetcher, mockClock
}

func configureTestFetcher(t *testing.T, fetcher *podListFetcher, fetch func(context.Context) (map[string]*fastjson.Value, error)) {
	t.Helper()

	fetcher.fetch = func(ctx context.Context, _ *kubeletClient) (map[string]*fastjson.Value, error) {
		return fetch(ctx)
	}
	require.NoError(t, fetcher.configure(t.Context(), podListFetcherConfig{
		pollRetryInterval: testPodListFetchRetryInterval,
	}))
}

func writeTestCA(t *testing.T, path string, serial int64) {
	cert, _ := spiretest.SelfSignCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	})
	require.NoError(t, os.WriteFile(path, pemutil.EncodeCertificate(cert), 0o600))
}
