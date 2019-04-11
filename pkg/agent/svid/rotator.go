package svid

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/andres-erbsen/clock"
	observer "github.com/imkira/go-observer"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/agent/keymanager"
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
	clk   clock.Clock

	// Mutex used to protect access to c.BundleStream.
	bsm *sync.RWMutex
}

type State struct {
	SVID []*x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Run runs the rotator. It monitors the server SVID for expiration and rotates
// as necessary. It also watches for changes to the trust bundle.
func (r *rotator) Run(ctx context.Context) error {
	t := r.clk.Ticker(r.c.Interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			r.c.Log.Debug("Stopping SVID rotator")
			r.client.Release()
			return nil
		case <-t.C:
			if r.shouldRotate() {
				if err := r.rotateSVID(ctx); err != nil {
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

	ttl := s.SVID[0].NotAfter.Sub(r.clk.Now())
	watermark := s.SVID[0].NotAfter.Sub(s.SVID[0].NotBefore) / 2

	return ttl <= watermark
}

// rotateSVID asks SPIRE's server for a new agent's SVID.
func (r *rotator) rotateSVID(ctx context.Context) (err error) {
	counter := telemetry.StartCall(r.c.Metrics, "agent_svid", "rotate")
	defer counter.Done(&err)

	counter.AddLabel("spiffe_id", r.c.SpiffeID)
	r.c.Log.Debug("Rotating agent SVID")

	key, err := r.newKey(ctx)
	if err != nil {
		return err
	}

	csr, err := util.MakeCSR(key, r.c.SpiffeID)
	if err != nil {
		return err
	}

	update, err := r.client.FetchUpdates(ctx, &node.FetchX509SVIDRequest{Csrs: [][]byte{csr}})
	if err != nil {
		return err
	}

	if len(update.SVIDs) == 0 {
		return errors.New("no SVID received when rotating agent SVID")
	}

	svid, ok := update.SVIDs[r.c.SpiffeID]
	if !ok {
		return errors.New("it was not possible to get agent SVID from FetchX509SVID response")
	}
	certs, err := x509.ParseCertificates(svid.CertChain)
	if err != nil {
		return err
	}

	if err := r.storeKey(ctx, key); err != nil {
		return err
	}

	// We must release the client because its underlaying connection is tied to an
	// expired SVID, so next time the client is used, it will get a new connection with
	// the most up-to-date SVID.
	r.client.Release()

	s := State{
		SVID: certs,
		Key:  key,
	}

	r.state.Update(s)
	return nil
}

func (r *rotator) newKey(ctx context.Context) (*ecdsa.PrivateKey, error) {
	km := r.c.Catalog.GetKeyManager()
	resp, err := km.GenerateKeyPair(ctx, &keymanager.GenerateKeyPairRequest{})
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %v", err)
	}

	return x509.ParseECPrivateKey(resp.PrivateKey)
}

func (r *rotator) storeKey(ctx context.Context, key *ecdsa.PrivateKey) error {
	km := r.c.Catalog.GetKeyManager()

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	if _, err := km.StorePrivateKey(ctx, &keymanager.StorePrivateKeyRequest{PrivateKey: keyBytes}); err != nil {
		r.c.Log.Errorf("could not store new agent key pair: %v", err)
		r.c.Log.Warn("Error encountered while storing new agent key pair. Is your KeyManager plugin is up-to-date?")

		// This error is not returned, to preserve backwards-compability with KeyManagers that were built against the old interface.
		// If the StorePrivateKey() method isn't avaiable on the plugin, we get a "not implemented" error, which we
		// should ignore for now, but log an error and warning.
		// return fmt.Errorf("store key pair: %v", err)
	}

	return nil
}
