package k8sbundle

import (
	"context"
	"reflect"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/watch"
)

type bundleWatcher struct {
	p      *Plugin
	cancel func()
}

func newBundleWatcher(p *Plugin) *bundleWatcher {
	return &bundleWatcher{p: p}
}

// startOrUpdateWatcher starts the webhook watcher or sends a signal to update configuration
func (b *bundleWatcher) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.cancel = cancel

	config, err := b.p.getConfig()
	if err != nil {
		return err
	}
	clients, err := b.p.hooks.newKubeClient(config)
	if err != nil {
		return err
	}
	watchers, validWatcherPresent, err := newWatchers(ctx, config, clients)
	if err != nil {
		return err
	}
	if !validWatcherPresent {
		return nil
	}

	err = b.watcherFunc(ctx, config, clients, watchers)
	switch err {
	case nil, context.Canceled:
		return nil
	default:
		return err
	}
}

func (b *bundleWatcher) Stop() {
	b.cancel()
}

// watcherFunc watches for new webhooks that are created with the configured label and updates the CA Bundle
func (b *bundleWatcher) watcherFunc(ctx context.Context, c *pluginConfig, clients []kubeClient, watchers []watch.Interface) (err error) {
	selectCase := newSelectCase(ctx, watchers)
	for {
		chosen, recv, _ := reflect.Select(selectCase)
		if chosen < len(clients) {
			if err = b.watchEvent(ctx, c, clients[chosen], recv.Interface().(watch.Event)); err != nil {
				return k8sErr.New("handling watch event: %v", err)
			}
		} else {
			return ctx.Err()
		}
	}
}

// watchEvent triggers the read-modify-write for a newly created webhook
func (b *bundleWatcher) watchEvent(ctx context.Context, c *pluginConfig, client kubeClient, event watch.Event) (err error) {
	if event.Type == watch.Added {
		webhookMeta, err := meta.Accessor(event.Object)
		if err != nil {
			return err
		}

		b.p.log.Debug("Setting bundle for new object", "name", webhookMeta.GetName())
		if err = b.p.updateBundle(ctx, c, client, webhookMeta.GetNamespace(), webhookMeta.GetName()); err != nil {
			return err
		}
	}
	return nil
}

func newSelectCase(ctx context.Context, watchers []watch.Interface) []reflect.SelectCase {
	selectCase := []reflect.SelectCase{}
	for _, watcher := range watchers {
		if watcher != nil {
			selectCase = append(selectCase, reflect.SelectCase{
				Dir:  reflect.SelectRecv,
				Chan: reflect.ValueOf(watcher.ResultChan()),
			})
		} else {
			selectCase = append(selectCase, reflect.SelectCase{
				Dir: reflect.SelectRecv,
			})
		}
	}
	selectCase = append(selectCase, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(ctx.Done()),
	})
	return selectCase
}

func newWatchers(ctx context.Context, c *pluginConfig, clients []kubeClient) ([]watch.Interface, bool, error) {
	watchers := []watch.Interface{}
	validWatcherPresent := false
	for _, client := range clients {
		watcher, err := client.Watch(ctx, c.WebhookLabel)
		if err != nil {
			return nil, false, err
		}
		if watcher != nil {
			validWatcherPresent = true
		}
		watchers = append(watchers, watcher)
	}
	return watchers, validWatcherPresent, nil
}
