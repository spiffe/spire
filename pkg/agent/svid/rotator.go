package svid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"github.com/imkira/go-observer"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/api/node"
)

type Rotator interface {
	Start()
	Stop()

	State() State
	Subscribe() observer.Stream
}

type rotator struct {
	c      *RotatorConfig
	stop   chan struct{}
	done   chan struct{}
	client client.Client

	state observer.Property

	m       sync.RWMutex
	running bool
	// Mutex used to protect access to c.BundleStream.
	bsm *sync.RWMutex
}

type State struct {
	SVID *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Start starts the rotator.
func (r *rotator) Start() {
	go r.run()
}

func (r *rotator) Stop() {
	close(r.stop)
	if r.isRunning() {
		<-r.done
		r.setRunning(false)
	}
}

func (r *rotator) State() State {
	return r.state.Value().(State)
}

func (r *rotator) Subscribe() observer.Stream {
	return r.state.Observe()
}

// run
// - Starts a ticker which monitors the server SVID for expiration and invokes
// rotateSVID() as necessary.
// - Reads the next trust bundle received on BundleStream.
func (r *rotator) run() {
	r.setRunning(true)
	t := time.NewTicker(r.c.Interval)
	defer t.Stop()

	for {
		select {
		case <-r.stop:
			r.c.Log.Debug("Stopping SVID rotator")
			r.client.Release()
			close(r.done)
			return
		case <-t.C:
			if r.shouldRotate() {
				if err := r.rotateSVID(); err != nil {
					r.c.Log.Errorf("Could not rotate agent SVID: %v", err)
				}
			}
		case <-r.c.BundleStream.Changes():
			r.bsm.Lock()
			r.c.BundleStream.Next()
			r.bsm.Unlock()
		}
	}
}

// shouldRotate returns a boolean informing the caller of whether or not the
// SVID should be rotated.
func (r *rotator) shouldRotate() bool {
	s := r.state.Value().(State)

	ttl := time.Until(s.SVID.NotAfter)
	watermark := s.SVID.NotAfter.Sub(s.SVID.NotBefore) / 2

	return ttl < watermark
}

// rotateSVID asks SPIRE's server for a new agent's SVID.
func (r *rotator) rotateSVID() error {
	r.c.Log.Debug("Rotating agent SVID")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	csr, err := util.MakeCSR(key, r.c.SpiffeID)
	if err != nil {
		return err
	}

	update, err := r.client.FetchUpdates(&node.FetchSVIDRequest{Csrs: [][]byte{csr}})
	if err != nil {
		return err
	}

	if len(update.SVIDs) == 0 {
		return errors.New("no SVID received when rotating agent SVID")
	}

	svid, ok := update.SVIDs[r.c.SpiffeID]
	if !ok {
		return errors.New("it was not possible to get agent SVID from FetchSVID response")
	}
	cert, err := x509.ParseCertificate(svid.SvidCert)
	if err != nil {
		return err
	}

	// We must release the client because its underlaying connection is tied to an
	// expired SVID, so next time the client is used, it will get a new connection with
	// the most up-to-date SVID.
	r.client.Release()

	s := State{
		SVID: cert,
		Key:  key,
	}

	r.state.Update(s)
	return nil
}

func (r *rotator) isRunning() bool {
	r.m.RLock()
	defer r.m.RUnlock()
	return r.running
}

func (r *rotator) setRunning(value bool) {
	r.m.Lock()
	defer r.m.Unlock()
	r.running = value
}
