package svid

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/andres-erbsen/clock"
	observer "github.com/imkira/go-observer"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	node_attestor "github.com/spiffe/spire/pkg/agent/attestor/node"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/common/backoff"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/fflag"
	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_agent "github.com/spiffe/spire/pkg/common/telemetry/agent"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc"
)

type Rotator interface {
	Run(ctx context.Context) error

	State() State
	Subscribe() observer.Stream
	GetRotationMtx() *sync.RWMutex
	SetRotationFinishedHook(func())
}

type Client interface {
	RenewSVID(ctx context.Context, csr []byte) (*client.X509SVID, error)
	Release()
}

type rotator struct {
	c      *RotatorConfig
	client Client

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
	SVID         []*x509.Certificate
	Key          crypto.Signer
	Reattestable bool
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
		err := r.rotateSVIDIfNeeded(ctx)
		state, ok := r.state.Value().(State)
		if !ok {
			return fmt.Errorf("unexpected value type: %T", r.state.Value())
		}

		switch {
		case err != nil && rotationutil.X509Expired(r.clk.Now(), state.SVID[0]):
			r.c.Log.WithError(err).Errorf("Could not %s", rotationError(state))
			// Since our X509 cert has expired, and we weren't able to carry out a rotation request, we're probably unrecoverable without re-attesting.
			return fmt.Errorf("current SVID has already expired and %s failed: %w", rotationError(state), err)
		case err != nil && nodeutil.ShouldAgentReattest(err):
			r.c.Log.WithError(err).Errorf("Could not %s", rotationError(state))
			return err
		case err != nil && nodeutil.ShouldAgentShutdown(err):
			r.c.Log.WithError(err).Errorf("Could not %s", rotationError(state))
			return err
		case err != nil:
			// Just log the error and wait for next rotation
			r.c.Log.WithError(err).Errorf("Could not %s", rotationError(state))
		default:
			r.backoff.Reset()
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.clk.After(r.backoff.NextBackOff()):
		}
	}
}

func (r *rotator) processBundleUpdates(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
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

func (r *rotator) rotateSVIDIfNeeded(ctx context.Context) (err error) {
	state, ok := r.state.Value().(State)
	if !ok {
		return fmt.Errorf("unexpected value type: %T", r.state.Value())
	}

	if rotationutil.ShouldRotateX509(r.clk.Now(), state.SVID[0]) {
		if state.Reattestable && fflag.IsSet(fflag.FlagReattestToRenew) {
			err = r.reattest(ctx)
		} else {
			err = r.rotateSVID(ctx)
		}

		if err == nil && r.rotationFinishedHook != nil {
			r.rotationFinishedHook()
		}
	}

	return err
}

// reattest goes through the full attestation process with the server and gets a new SVID.
func (r *rotator) reattest(ctx context.Context) (err error) {
	counter := telemetry_agent.StartReattestAgentCall(r.c.Metrics)
	defer counter.Done(&err)

	// Get the mtx before starting the reattestation
	// In this way, the client do not create new connections until the new SVID is received
	r.rotMtx.Lock()
	defer r.rotMtx.Unlock()
	r.c.Log.Debug("Reattesting node")

	bundle, err := r.getBundle()
	if err != nil {
		return err
	}

	key, err := r.generateKey(ctx)
	if err != nil {
		return err
	}

	csr, err := util.MakeCSRWithoutURISAN(key)
	if err != nil {
		return err
	}

	conn, err := r.serverConn(ctx, bundle)
	if err != nil {
		return err
	}
	defer conn.Close()

	stream := &node_attestor.ServerStream{Client: agentv1.NewAgentClient(conn), Csr: csr, Log: r.c.Log}
	if err := r.c.NodeAttestor.Attest(ctx, stream); err != nil {
		return err
	}
	r.c.Log.WithField(telemetry.SPIFFEID, stream.SVID[0].URIs[0].String()).Info("Successfully reattested node")

	s := State{
		SVID:         stream.SVID,
		Key:          key,
		Reattestable: stream.Reattestable,
	}

	r.state.Update(s)

	// We must release the client because its underlaying connection is tied to an
	// expired SVID, so next time the client is used, it will get a new connection with
	// the most up-to-date SVID.
	r.client.Release()

	return nil
}

// rotateSVID asks SPIRE's server for a new agent's SVID.
func (r *rotator) rotateSVID(ctx context.Context) (err error) {
	counter := telemetry_agent.StartRotateAgentSVIDCall(r.c.Metrics)
	defer counter.Done(&err)

	// Get the mtx before starting the rotation
	// In this way, the client do not create new connections until the new SVID is received
	r.rotMtx.Lock()
	defer r.rotMtx.Unlock()
	r.c.Log.Debug("Rotating agent SVID")

	key, err := r.generateKey(ctx)
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
	r.c.Log.WithField(telemetry.SPIFFEID, certs[0].URIs[0].String()).Info("Successfully rotated agent SVID")

	s := State{
		SVID: certs,
		Key:  key,
	}

	r.state.Update(s)

	// We must release the client because its underlaying connection is tied to an
	// expired SVID, so next time the client is used, it will get a new connection with
	// the most up-to-date SVID.
	r.client.Release()

	return nil
}

func (r *rotator) getBundle() (*bundleutil.Bundle, error) {
	r.bsm.RLock()
	bundles := r.c.BundleStream.Value()
	r.bsm.RUnlock()

	bundle := bundles[r.c.TrustDomain]
	if bundle == nil {
		return nil, errors.New("bundle not found")
	}

	return bundle, nil
}

func (r *rotator) generateKey(ctx context.Context) (keymanager.Key, error) {
	state, ok := r.state.Value().(State)
	if !ok {
		return nil, fmt.Errorf("unexpected value type: %T", r.state.Value())
	}

	var existingKey keymanager.Key
	if state.Key != nil {
		existingKey, ok = state.Key.(keymanager.Key)
		if !ok {
			return nil, fmt.Errorf("unexpected value type: %T", state.Key)
		}
	}

	return r.c.SVIDKeyManager.GenerateKey(ctx, existingKey)
}

func (r *rotator) serverConn(ctx context.Context, bundle *bundleutil.Bundle) (*grpc.ClientConn, error) {
	return client.DialServer(ctx, client.DialServerConfig{
		Address:     r.c.ServerAddr,
		TrustDomain: r.c.TrustDomain,
		GetBundle:   bundle.RootCAs,
	})
}

func rotationError(state State) string {
	if state.Reattestable {
		return "reattest agent"
	}

	return "rotate agent SVID"
}
