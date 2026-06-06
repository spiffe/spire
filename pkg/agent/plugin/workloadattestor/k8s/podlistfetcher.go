package k8s

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	"github.com/valyala/fastjson"
)

const kubeletRequestTimeout = 10 * time.Second

var errPodListFetcherClosed = errors.New("pod list fetcher is closed")

type podListFetcherConfig struct {
	pollRetryInterval          time.Duration
	secure                     bool
	port                       int
	skipKubeletVerification    bool
	tokenPath                  string
	certificatePath            string
	privateKeyPath             string
	useAnonymousAuthentication bool
	kubeletCAPath              string
	nodeName                   string
	reloadInterval             time.Duration
}

// podListFetcher coordinates access to the kubelet pod list. Concurrent callers
// share at most one kubelet request, with request starts separated by at least
// the configured poll interval. Successful results are cached until another
// request is eligible to start and assigned monotonically increasing versions
// so callers can wait for a pod list newer than one they have already examined.
//
// The run goroutine exclusively owns the mutable state identified below.
// Public methods and background operations communicate with it through
// channels.
type podListFetcher struct {
	clock   clock.Clock
	log     hclog.Logger
	rootDir string

	actionCh chan func()
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// The fields below are owned by the run goroutine.
	config           *podListFetcherConfig
	client           *kubeletClient
	clientLoadedAt   time.Time
	lastFetchStart   time.Time
	fetchTimer       *clock.Timer
	fetchWaiters     map[chan<- podListFetchResult]struct{}
	fetchCancel      context.CancelFunc
	cachedPodList    versionedPodList
	cachedFetchStart time.Time

	// These are callbacks purely to facilitate testing.
	fetch       func(context.Context, *kubeletClient) (map[string]*fastjson.Value, error)
	buildClient func(podListFetcherConfig, *kubeletClient) (*kubeletClient, error)
}

type versionedPodList struct {
	pods    map[string]*fastjson.Value
	version uint64
}

type podListFetchResult struct {
	versionedPodList
	err error
}

// newPodListFetcher constructs a pod list fetcher and starts its run goroutine.
// The caller must eventually call close exactly once.
func newPodListFetcher(clock clock.Clock, rootDir string) *podListFetcher {
	f := podListFetcher{
		clock:        clock,
		log:          hclog.NewNullLogger(),
		rootDir:      rootDir,
		actionCh:     make(chan func()),
		stopCh:       make(chan struct{}),
		fetchWaiters: make(map[chan<- podListFetchResult]struct{}),
	}
	f.fetch = f.fetchPodList
	f.buildClient = f.buildKubeletClient
	f.wg.Go(f.run)
	return &f
}

// setLogger replaces the logger used while processing kubelet responses. It
// must be called before the fetcher is otherwise used.
func (f *podListFetcher) setLogger(log hclog.Logger) {
	f.log = log
}

// configure recreates the internal kubelet client based on config. A failure
// leaves the current configuration unchanged. Calls to configure must not
// overlap.
func (f *podListFetcher) configure(ctx context.Context, config podListFetcherConfig) error {
	resultCh := make(chan error, 1)
	select {
	case f.actionCh <- func() { f.startConfigure(config, resultCh) }:
	case <-ctx.Done():
		return ctx.Err()
	case <-f.stopCh:
		return errPodListFetcherClosed
	}

	// Once accepted, wait for the definitive result so configuration cannot
	// be installed after the caller observes a context cancellation.
	select {
	case err := <-resultCh:
		return err
	case <-f.stopCh:
		return errPodListFetcherClosed
	}
}

// validate validates the given config.
func (f *podListFetcher) validate(config podListFetcherConfig) error {
	_, err := f.buildClient(config, nil)
	return err
}

// fetchNext returns a cached result newer than afterVersion while that result is
// fresh, or waits for the next shared kubelet request.
func (f *podListFetcher) fetchNext(ctx context.Context, afterVersion uint64) (versionedPodList, error) {
	resultCh := make(chan podListFetchResult, 1)

	select {
	case f.actionCh <- func() { f.registerFetchRequest(afterVersion, resultCh) }:
	case <-ctx.Done():
		return versionedPodList{}, ctx.Err()
	case <-f.stopCh:
		return versionedPodList{}, errPodListFetcherClosed
	}

	select {
	case result := <-resultCh:
		return result.versionedPodList, result.err
	case <-ctx.Done():
		f.dispatch(func() { f.cancelFetchRequest(resultCh) })
		return versionedPodList{}, ctx.Err()
	case <-f.stopCh:
		return versionedPodList{}, errPodListFetcherClosed
	}
}

// close stops the run goroutine, cancels any in-flight kubelet request, and
// waits for all background operations to finish. It must be called exactly once.
func (f *podListFetcher) close() {
	close(f.stopCh)
	f.wg.Wait()
}

func (f *podListFetcher) run() {
	for {
		select {
		case action := <-f.actionCh:
			action()
		case <-f.timerChan():
			f.fetchTimerFired()
		case <-f.stopCh:
			f.stop()
			return
		}
	}
}

func (f *podListFetcher) dispatch(action func()) {
	select {
	case f.actionCh <- action:
	case <-f.stopCh:
	}
}

func (f *podListFetcher) registerFetchRequest(afterVersion uint64, resultCh chan<- podListFetchResult) {
	if f.cachedPodList.pods != nil && afterVersion < f.cachedPodList.version &&
		f.clock.Now().Before(f.cachedFetchStart.Add(f.config.pollRetryInterval)) {
		resultCh <- podListFetchResult{versionedPodList: f.cachedPodList}
		return
	}

	f.fetchWaiters[resultCh] = struct{}{}
	f.scheduleFetch()
}

func (f *podListFetcher) cancelFetchRequest(resultCh chan<- podListFetchResult) {
	delete(f.fetchWaiters, resultCh)
	if len(f.fetchWaiters) == 0 {
		f.stopTimer()
		// Could also call fetchCancel here, but another request
		// might still come in and then see the cancellation.
		// Also, future requests may benefit from having a cached result.
	}
}

func (f *podListFetcher) completeFetch(result podListFetchResult, originalClient, reloadedClient *kubeletClient) {
	f.fetchCancel = nil

	if reloadedClient != nil && f.client == originalClient {
		// Only install the new kubelet client if the client from which it was
		// built is still installed. This prevents a reload started before a
		// configure call from overwriting the newly configured client.
		f.installKubeletClient(reloadedClient)
	}

	if result.err == nil {
		f.cachedPodList = result.versionedPodList
		f.cachedFetchStart = f.lastFetchStart
	}

	for resultCh := range f.fetchWaiters {
		resultCh <- result
	}
	clear(f.fetchWaiters)
}

func (f *podListFetcher) startConfigure(config podListFetcherConfig, resultCh chan<- error) {
	previousClient := f.client
	buildClient := f.buildClient

	f.wg.Go(func() {
		client, err := buildClient(config, previousClient)
		if err != nil {
			resultCh <- err
			return
		}

		f.dispatch(func() { f.completeConfigure(config, client, resultCh) })
	})
}

func (f *podListFetcher) completeConfigure(config podListFetcherConfig, client *kubeletClient, resultCh chan<- error) {
	f.config = &config
	f.installKubeletClient(client)
	// Reset any pending timer because pollRetryInterval may have changed, then
	// schedule a fetch if there are waiters. In particular, waiters may have
	// arrived before the initial configuration completed, when no timer could
	// be scheduled.
	f.stopTimer()
	f.scheduleFetch()
	resultCh <- nil
}

func (f *podListFetcher) fetchTimerFired() {
	f.stopTimer()
	if len(f.fetchWaiters) > 0 {
		f.startFetch()
	}
}

func (f *podListFetcher) stop() {
	f.stopTimer()
	if f.fetchInFlight() {
		f.fetchCancel()
	}
}

func (f *podListFetcher) scheduleFetch() {
	if f.config == nil || f.fetchInFlight() || f.fetchTimer != nil || len(f.fetchWaiters) == 0 {
		return
	}

	if f.lastFetchStart.IsZero() {
		f.startFetch()
		return
	}

	delay := f.config.pollRetryInterval - f.clock.Now().Sub(f.lastFetchStart)
	if delay <= 0 {
		f.startFetch()
		return
	}

	f.fetchTimer = f.clock.Timer(delay)
}

func (f *podListFetcher) startFetch() {
	f.lastFetchStart = f.clock.Now()
	fetchCtx, cancel := context.WithTimeout(context.Background(), kubeletRequestTimeout)
	f.fetchCancel = cancel

	config := *f.config
	version := f.cachedPodList.version + 1
	originalClient := f.client
	shouldReloadClient := originalClient == nil || f.clock.Now().Sub(f.clientLoadedAt) >= config.reloadInterval
	buildClient, fetch := f.buildClient, f.fetch

	f.wg.Go(func() {
		defer cancel()
		clientForFetch := originalClient
		var reloadedClient *kubeletClient
		if shouldReloadClient {
			var err error
			reloadedClient, err = buildClient(config, originalClient)
			if err != nil {
				f.dispatch(func() { f.completeFetch(podListFetchResult{err: err}, originalClient, nil) })
				return
			}
			clientForFetch = reloadedClient
		}

		pods, err := fetch(fetchCtx, clientForFetch)
		result := podListFetchResult{
			versionedPodList: versionedPodList{pods: pods, version: version},
			err:              err,
		}
		f.dispatch(func() { f.completeFetch(result, originalClient, reloadedClient) })
	})
}

func (f *podListFetcher) stopTimer() {
	if f.fetchTimer == nil {
		return
	}

	f.fetchTimer.Stop()
	f.fetchTimer = nil
}

func (f *podListFetcher) timerChan() <-chan time.Time {
	if f.fetchTimer == nil {
		return nil
	}
	return f.fetchTimer.C
}

func (f *podListFetcher) fetchInFlight() bool {
	return f.fetchCancel != nil
}

func (f *podListFetcher) fetchPodList(ctx context.Context, client *kubeletClient) (map[string]*fastjson.Value, error) {
	podListBytes, err := client.getPodList(ctx)
	if err != nil {
		return nil, err
	}
	return f.parsePodList(podListBytes)
}

func (f *podListFetcher) parsePodList(podListBytes []byte) (map[string]*fastjson.Value, error) {
	var parser fastjson.Parser
	podList, err := parser.ParseBytes(podListBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse kubelet response: %w", err)
	}

	if podList.Type() != fastjson.TypeObject {
		return nil, errors.New("invalid kubelet response: expected an object")
	}
	itemsValue := podList.Get("items")
	if itemsValue == nil {
		return nil, errors.New("invalid kubelet response: expected an items array")
	}
	var items []*fastjson.Value
	switch itemsValue.Type() {
	case fastjson.TypeArray:
		items = itemsValue.GetArray()
	case fastjson.TypeNull:
		// encoding/json marshals a nil PodList.Items slice as null.
	default:
		return nil, errors.New("invalid kubelet response: expected an items array")
	}
	result := make(map[string]*fastjson.Value, len(items))

	for _, podValue := range items {
		uid := string(podValue.Get("metadata", "uid").GetStringBytes())
		if uid == "" {
			f.log.Warn("Pod has no UID", "pod", podValue)
			continue
		}
		result[uid] = podValue
	}

	return result, nil
}

func (f *podListFetcher) buildKubeletClient(config podListFetcherConfig, previousClient *kubeletClient) (*kubeletClient, error) {
	transportConfig, token, err := f.loadKubeletTransportConfig(config)
	if err != nil {
		return nil, err
	}

	if previousClient != nil && previousClient.transportConfig == transportConfig {
		// An in-flight fetch may still reference the existing client. Copy it to
		// update the token without a data race while reusing the transport.
		client := *previousClient
		client.token = token
		return &client, nil
	}

	return newKubeletClient(transportConfig, token)
}

func (f *podListFetcher) installKubeletClient(client *kubeletClient) {
	f.client = client
	f.clientLoadedAt = f.clock.Now()
}

func (f *podListFetcher) loadKubeletTransportConfig(config podListFetcherConfig) (kubeletTransportConfig, string, error) {
	transportConfig := kubeletTransportConfig{
		secure:                  config.secure,
		skipKubeletVerification: config.skipKubeletVerification,
		nodeName:                config.nodeName,
		port:                    config.port,
	}
	if !config.secure {
		return transportConfig, "", nil
	}

	if !config.skipKubeletVerification {
		caPEM, err := f.readFile(config.kubeletCAPath)
		if err != nil {
			return kubeletTransportConfig{}, "", fmt.Errorf("unable to load kubelet CA: %w", err)
		}
		transportConfig.caPEM = string(caPEM)
	}

	var token string
	switch {
	case config.useAnonymousAuthentication:
	case config.certificatePath != "" && config.privateKeyPath != "":
		certPEM, err := f.readFile(config.certificatePath)
		if err != nil {
			return kubeletTransportConfig{}, "", fmt.Errorf("unable to load certificate: %w", err)
		}
		keyPEM, err := f.readFile(config.privateKeyPath)
		if err != nil {
			return kubeletTransportConfig{}, "", fmt.Errorf("unable to load private key: %w", err)
		}
		transportConfig.certificatePEM = string(certPEM)
		transportConfig.privateKeyPEM = string(keyPEM)
	case config.certificatePath != "":
		return kubeletTransportConfig{}, "", errors.New("the private key path is required with the certificate path")
	case config.privateKeyPath != "":
		return kubeletTransportConfig{}, "", errors.New("the certificate path is required with the private key path")
	default:
		tokenBytes, err := f.readFile(config.tokenPath)
		if err != nil {
			return kubeletTransportConfig{}, "", fmt.Errorf("unable to load token: %w", err)
		}
		token = strings.TrimSpace(string(tokenBytes))
	}

	return transportConfig, token, nil
}

func (f *podListFetcher) readFile(path string) ([]byte, error) {
	return os.ReadFile(filepath.Join(f.rootDir, path))
}
