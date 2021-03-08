package k8sbundle

import (
	"context"
	"reflect"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/watch"
)

type bundleWatcher struct {
	p        *Plugin
	clients  []kubeClient
	watchers []watch.Interface
	config   *pluginConfig

	hooks struct {
		watch func(ctx context.Context) error
	}
}

// newBundleWatcher creates a new watcher for newly created objects
func newBundleWatcher(ctx context.Context, p *Plugin, config *pluginConfig) (*bundleWatcher, error) {
	clients, err := p.hooks.newKubeClient(config)
	if err != nil {
		return nil, err
	}
	watchers, clients, err := newWatchers(ctx, clients, config)
	if err != nil {
		return nil, err
	}

	watcher := &bundleWatcher{
		p:        p,
		clients:  clients,
		config:   config,
		watchers: watchers,
	}
	watcher.hooks.watch = watcher.watch
	return watcher, nil
}

// Watch calls the hook to watch for new objects
func (b *bundleWatcher) Watch(ctx context.Context) error {
	return b.hooks.watch(ctx)
}

// watch watches for new objects that are created with the proper selector and updates the CA Bundle
func (b *bundleWatcher) watch(ctx context.Context) error {
	selectCase := newSelectCase(ctx, b.watchers)
	for {
		chosen, recv, _ := reflect.Select(selectCase)
		if chosen < len(b.clients) {
			if err := b.watchEvent(ctx, b.clients[chosen], recv.Interface().(watch.Event)); err != nil {
				return k8sErr.New("handling watch event: %v", err)
			}
		} else {
			// The context is the last element in the array
			return ctx.Err()
		}
	}
}

// watchEvent triggers the read-modify-write for a newly created object
func (b *bundleWatcher) watchEvent(ctx context.Context, client kubeClient, event watch.Event) (err error) {
	if event.Type == watch.Added {
		objectMeta, err := meta.Accessor(event.Object)
		if err != nil {
			return err
		}

		b.p.log.Debug("Setting bundle for new object", "name", objectMeta.GetName())
		if err = b.p.updateBundle(ctx, b.config, client, objectMeta.GetNamespace(), objectMeta.GetName()); err != nil {
			return err
		}
	}
	return nil
}

// newWatchers creates a watcher array for all of the clients
func newWatchers(ctx context.Context, clients []kubeClient, config *pluginConfig) ([]watch.Interface, []kubeClient, error) {
	watchers := []watch.Interface{}
	validClients := []kubeClient{}
	for _, client := range clients {
		watcher, err := client.Watch(ctx, config)
		if err != nil {
			return nil, nil, err
		}
		if watcher != nil {
			watchers = append(watchers, watcher)
			validClients = append(validClients, client)
		}
	}
	return watchers, validClients, nil
}

// newSelectCase creates the SelectCase array used by reflect.Select
func newSelectCase(ctx context.Context, watchers []watch.Interface) []reflect.SelectCase {
	selectCase := []reflect.SelectCase{}
	for _, watcher := range watchers {
		selectCase = append(selectCase, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(watcher.ResultChan()),
		})
	}
	// Add the context as the last element in the array
	selectCase = append(selectCase, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(ctx.Done()),
	})
	return selectCase
}
