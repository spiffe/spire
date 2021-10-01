package k8sbundle

import (
	"context"
	"reflect"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	clients, err := p.hooks.newKubeClients(config)
	if err != nil {
		return nil, err
	}
	watchers, clients, err := newWatchers(ctx, clients)
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
				b.p.log.Error("Handling watch event", "error", err)
			}
		} else {
			// The context is the last element in the array
			return ctx.Err()
		}
	}
}

// watchEvent triggers the read-modify-write for a newly created object
func (b *bundleWatcher) watchEvent(ctx context.Context, client kubeClient, event watch.Event) error {
	if event.Type == watch.Added || event.Type == watch.Modified {
		objectMeta, err := meta.Accessor(event.Object)
		if err != nil {
			return err
		}

		err = b.p.updateBundle(ctx, client, objectMeta.GetNamespace(), objectMeta.GetName())
		switch {
		case err == nil:
			b.p.log.Debug("Set bundle for object", "name", objectMeta.GetName(), "event", event.Type)
		case status.Code(err) == codes.FailedPrecondition:
			// Ignore FailPrecondition errors for when SPIRE is booting and we receive an event prior to
			// IdentityProvider being initialized. In this case the BundleLoaded event will come
			// to populate the caBundle, so its safe to ignore this error.
		case status.Code(err) == codes.AlreadyExists:
			// Updating the bundle from an ADD event triggers a subsequent MODIFIED event. updateBundle will
			// return AlreadyExists since nothing needs to be updated.
		default:
			return err
		}
	}
	return nil
}

// newWatchers creates a watcher array for all of the clients
func newWatchers(ctx context.Context, clients []kubeClient) ([]watch.Interface, []kubeClient, error) {
	watchers := []watch.Interface{}
	validClients := []kubeClient{}
	for _, client := range clients {
		watcher, err := client.Watch(ctx)
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
