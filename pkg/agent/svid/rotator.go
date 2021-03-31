package svid

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/andres-erbsen/clock"
	observer "github.com/imkira/go-observer"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/common/backoff"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	telemetry_agent "github.com/spiffe/spire/pkg/common/telemetry/agent"
	"github.com/spiffe/spire/pkg/common/util"
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
	err := util.RunTasks(ctx, r.runRotation, r.processBundleUpdates)
	r.c.Log.Debug("Stopping SVID rotator")
	r.client.Release()
	return err
}

func (r *rotator) runRotation(ctx context.Context) error {
	for {
		err := r.rotateSVID(ctx)

		switch {
		case err != nil && rotationutil.X509Expired(r.clk.Now(), r.state.Value().(State).SVID[0]):
			r.c.Log.WithError(err).Error("Could not rotate agent SVID")
			// Since our X509 cert has expired, and we weren't able to carry out a rotation request, we're probably unrecoverable without re-attesting.
			return fmt.Errorf("current SVID has already expired and rotation failed: %v", err)
		case err != nil && nodeutil.ShouldAgentReattest(err):
			r.c.Log.WithError(err).Error("Could not rotate agent SVID")
			return err
		case err != nil:
			// Just log the error and wait for next rotation
			r.c.Log.WithError(err).Error("Could not rotate agent SVID")
		default:
			r.backoff.Reset()
		}

		select {
		case <-ctx.Done():
			return nil
		case <-r.clk.After(r.backoff.NextBackOff()):
		}
	}
}

func (r *rotator) processBundleUpdates(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
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

	csr, err := util.MakeCSRWithoutURISAN(key)
	if err != nil {
		return err
	}

	svid, err := r.client.RenewSVID(ctx, csr)
	if err != nil {
		return err
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
