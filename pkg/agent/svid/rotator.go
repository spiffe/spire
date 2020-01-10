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
	"github.com/spiffe/spire/pkg/agent/common/backoff"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	telemetry_agent "github.com/spiffe/spire/pkg/common/telemetry/agent"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/api/node"
)

type Rotator interface {
	Run(ctx context.Context) error

	State() State
	Subscribe() observer.Stream
	GetRotationMtx() *sync.RWMutex
	SetRotationFinishedHook(func())
}

type rotator struct {
	c      *RotatorConfig
	client client.Client

	state observer.Property
	clk   clock.Clock

	// backoff calculator for rotation check interval, backing off if error is returned on
	// rotation attempt
	backoff backoff.BackOff

	// Mutex used to protect access to c.BundleStream.
	bsm *sync.RWMutex

	// Mutex used to prevent rotations when a new connection is being created
	rotMtx *sync.RWMutex

	// Hook that will be called when the SVID rotation finishes
	rotationFinishedHook func()
}

type State struct {
	SVID []*x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Run runs the rotator. It monitors the server SVID for expiration and rotates
// as necessary. It also watches for changes to the trust bundle.
func (r *rotator) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			r.c.Log.Debug("Stopping SVID rotator")
			r.client.Release()
			return nil
		case <-r.clk.After(r.backoff.NextBackOff()):
			if err := r.rotateSVID(ctx); err != nil {
				r.c.Log.WithError(err).Error("Could not rotate agent SVID")
			} else {
				r.backoff.Reset()
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

func (r *rotator) GetRotationMtx() *sync.RWMutex {
	return r.rotMtx
}

func (r *rotator) SetRotationFinishedHook(f func()) {
	r.rotationFinishedHook = f
}

// rotateSVID asks SPIRE's server for a new agent's SVID.
func (r *rotator) rotateSVID(ctx context.Context) (err error) {
	if !rotationutil.ShouldRotateX509(r.clk.Now(), r.state.Value().(State).SVID[0]) {
		return nil
	}

	counter := telemetry_agent.StartRotateAgentSVIDCall(r.c.Metrics)
	defer counter.Done(&err)

	// Get the mtx before starting the rotation
	// In this way, the client do not create new connections until the new SVID is received
	r.rotMtx.Lock()
	defer r.rotMtx.Unlock()
	r.c.Log.Debug("Rotating agent SVID")

	key, err := r.newKey(ctx)
	if err != nil {
		return err
	}

	csr, err := util.MakeCSR(key, r.c.SpiffeID)
	if err != nil {
		return err
	}

	update, err := r.client.FetchUpdates(ctx,
		&node.FetchX509SVIDRequest{
			// CSRS are expected to be keyed by entryID. Since it does not
			// exist an entry ID for the agent spiffeID, the `r.c.SpiffeID`
			// is used as a key in this particular case
			Csrs: map[string][]byte{
				r.c.SpiffeID: csr,
			},
		}, true)
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

	s := State{
		SVID: certs,
		Key:  key,
	}

	r.state.Update(s)

	// We must release the client because its underlaying connection is tied to an
	// expired SVID, so next time the client is used, it will get a new connection with
	// the most up-to-date SVID.
	r.client.Release()

	if r.rotationFinishedHook != nil {
		r.rotationFinishedHook()
	}

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
