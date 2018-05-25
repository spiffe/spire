package svid

import (
	"context"
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
	Run(ctx context.Context) error

	State() State
	Subscribe() observer.Stream
}

type rotator struct {
	c      *RotatorConfig
	client client.Client

	state observer.Property

	m sync.RWMutex
	// Mutex used to protect access to c.BundleStream.
	bsm *sync.RWMutex
}

type State struct {
	SVID *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Run runs the rotator. It monitors the server SVID for expiration and rotates
// as necessary. It also watches for changes to the trust bundle.
func (r *rotator) Run(ctx context.Context) error {
	t := time.NewTicker(r.c.Interval)
	defer t.Stop()

	done := ctx.Done()
	for {
		select {
		case <-done:
			r.c.Log.Debug("Stopping SVID rotator")
			r.client.Release()
			return nil
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

func (r *rotator) State() State {
	return r.state.Value().(State)
}

func (r *rotator) Subscribe() observer.Stream {
	return r.state.Observe()
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
