package workload

import (
	"reflect"
	"sync"

	"github.com/spiffe/spire/proto/api/workload"
)

// x509Handler implements logic to 1) dedupe X509-SVID updates, and 2) decouple
// internal state changes from client consumption.
type x509Handler struct {
	mtx *sync.RWMutex

	changes  chan struct{}
	latest   *workload.X509SVIDResponse
	stopChan chan struct{}
	updChan  chan *workload.X509SVIDResponse
}

// newX509Handler initializes a new x509Handler struct.
func newX509Handler() *x509Handler {
	return &x509Handler{
		mtx:      new(sync.RWMutex),
		changes:  make(chan struct{}, 1),
		stopChan: make(chan struct{}),
		updChan:  make(chan *workload.X509SVIDResponse),
	}
}

// start fires the handler logic in a dedicated goroutine, which waits for
// updates and transmits them to the update channel as necessary.
func (x *x509Handler) start() {
	go x.handleUpdates()
}

// stop stops the handler.
func (x *x509Handler) stop() {
	close(x.stopChan)
}

// update sets a new X509-SVID response as the latest.
func (x *x509Handler) update(u *workload.X509SVIDResponse) {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	if reflect.DeepEqual(u, x.latest) {
		return
	}

	x.latest = u

	// Don't block if the channel is full
	select {
	case x.changes <- struct{}{}:
		break
	default:
		break
	}
}

// updateChan returns a channel on which a client will receive X509-SVID updates
func (x *x509Handler) updateChan() <-chan *workload.X509SVIDResponse {
	return x.updChan
}

// handleUpdates waits for changes to occur, and attempts to send them to the client.
func (x *x509Handler) handleUpdates() {
	for {
		select {
		case <-x.changes:
			break
		case <-x.stopChan:
			return
		}

	SendUpdate:
		x.mtx.RLock()
		latest := x.latest
		x.mtx.RUnlock()

		select {
		case x.updChan <- latest:
			continue
		case <-x.changes:
			goto SendUpdate
		case <-x.stopChan:
			return
		}
	}
}
