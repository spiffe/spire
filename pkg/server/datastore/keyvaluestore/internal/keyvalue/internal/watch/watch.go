package watch

import (
	"context"
	"errors"
	"sync"

	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
)

type ReportFunc = func(changed []keyvalue.Key, current bool) error

type Watcher interface {
	Watch(ctx context.Context, report ReportFunc) error
}

type Watchers[W Watcher] struct {
	mtx     sync.Mutex
	wg      sync.WaitGroup
	watches map[*watch[W]]struct{}
	closed  bool
}

func (ws *Watchers[W]) Close() {
	ws.mtx.Lock()
	ws.closed = true
	for watch := range ws.watches {
		watch.cancel()
	}
	ws.mtx.Unlock()
	ws.wg.Wait()
}

func (ws *Watchers[W]) New(ctx context.Context, watcher W) keyvalue.WatchChan {
	out := make(chan keyvalue.WatchResult, 1)
	ctx, cancel := context.WithCancel(ctx)

	w := &watch[W]{
		out:     out,
		cancel:  cancel,
		watcher: watcher,
	}

	ws.mtx.Lock()
	defer ws.mtx.Unlock()

	if ws.closed {
		out <- keyvalue.WatchResult{Err: errors.New("closed")}
		close(out)
		return out
	}
	if ws.watches == nil {
		ws.watches = make(map[*watch[W]]struct{})
	}
	ws.watches[w] = struct{}{}
	ws.wg.Add(1)
	go func() {
		defer ws.wg.Done()
		ws.watch(ctx, w)
	}()
	return out
}

func (ws *Watchers[W]) watch(ctx context.Context, w *watch[W]) {
	defer func() {
		close(w.out)
		ws.mtx.Lock()
		delete(ws.watches, w)
		ws.mtx.Unlock()
		w.cancel()
	}()

	send := func(r keyvalue.WatchResult) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case w.out <- r:
			return nil
		}
	}

	// Send the initial empty result to signify that the watch has started.
	if err := send(keyvalue.WatchResult{}); err != nil {
		return
	}

	err := w.watcher.Watch(ctx, func(changed []keyvalue.Key, current bool) error {
		return send(keyvalue.WatchResult{
			Current: current,
			Changed: changed,
		})
	})

	_ = send(keyvalue.WatchResult{Err: err})
}

type watch[W Watcher] struct {
	out     chan<- keyvalue.WatchResult
	cancel  context.CancelFunc
	watcher W
}
