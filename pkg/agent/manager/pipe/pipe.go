package pipe

import (
	"crypto"
	"crypto/x509"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/proto/spire/common"
)

// Holds an storable SVID, with relevant information
type SVIDUpdate struct {
	Entry      *common.RegistrationEntry
	SVID       []*x509.Certificate
	PrivateKey crypto.Signer

	Bundle           *bundleutil.Bundle
	FederatedBundles map[spiffeid.TrustDomain]*bundleutil.Bundle
}

type In interface {
	Push(*SVIDUpdate)
	Close()
}

type Out interface {
	GetUpdate() <-chan *SVIDUpdate
}

func BufferedPipe(bufferSize int) (In, Out) {
	inCh := make(chan *SVIDUpdate)
	outCh := make(chan *SVIDUpdate, bufferSize)

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(outCh)
		for svidUpdate := range inCh {
			if svidUpdate == nil {
				continue
			}

			select {
			case outCh <- svidUpdate:
			default:
				<-outCh
				outCh <- svidUpdate
			}
		}
	}()

	return newPipeIn(wg, inCh), newPipeOut(outCh)
}

type pipeIn struct {
	mu   sync.RWMutex
	wg   *sync.WaitGroup
	in   chan *SVIDUpdate
	done chan struct{}
}

func newPipeIn(wg *sync.WaitGroup, in chan *SVIDUpdate) *pipeIn {
	return &pipeIn{
		in:   in,
		done: make(chan struct{}),
		wg:   wg,
	}
}

func (p *pipeIn) Push(update *SVIDUpdate) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	select {
	case p.in <- update:
	case <-p.done:
	}
}

func (p *pipeIn) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.in != nil {
		close(p.in)
		close(p.done)
		p.in = nil
		p.wg.Wait()
	}
}

type pipeOut struct {
	out chan *SVIDUpdate
}

func newPipeOut(out chan *SVIDUpdate) *pipeOut {
	return &pipeOut{
		out: out,
	}
}

func (p *pipeOut) GetUpdate() <-chan *SVIDUpdate {
	return p.out
}
