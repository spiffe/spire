package svid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"time"

	"github.com/imkira/go-observer"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/ca"
)

// Rotator is an interface for a SVID rotator
type Rotator interface {
	Initialize(ctx context.Context) error
	Run(ctx context.Context) error

	State() State
	Subscribe() observer.Stream
}

type rotator struct {
	c *RotatorConfig

	state observer.Property
}

// State is the current SVID and key
type State struct {
	SVID []*x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Start generates a new SVID and then starts the rotator.
func (r *rotator) Initialize(ctx context.Context) error {
	return r.rotateSVID(ctx)
}

func (r *rotator) State() State {
	return r.state.Value().(State)
}

func (r *rotator) Subscribe() observer.Stream {
	return r.state.Observe()
}

// Run starts a ticker which monitors the server SVID
// for expiration and rotates the SVID as necessary.
func (r *rotator) Run(ctx context.Context) error {
	t := r.c.Clock.Ticker(r.c.Interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			r.c.Log.Debug("Stopping SVID rotator")
			return nil
		case <-t.C:
			if r.shouldRotate() {
				if err := r.rotateSVID(ctx); err != nil {
					r.c.Log.WithError(err).Error("Could not rotate server SVID")
				}
			}
		}
	}
}

// shouldRotate returns a boolean informing the caller of whether or not the
// SVID should be rotated.
func (r *rotator) shouldRotate() bool {
	s := r.state.Value().(State)

	if len(s.SVID) == 0 {
		return true
	}

	return r.c.Clock.Now().After(certHalfLife(s.SVID[0]))
}

// rotateSVID cuts a new server SVID from the CA plugin and installs
// it on the endpoints struct. Also updates the CA certificates.
func (r *rotator) rotateSVID(ctx context.Context) (err error) {
	counter := telemetry_server.StartRotateServerSVIDCall(r.c.Metrics)
	defer counter.Done(&err)
	r.c.Log.Debug("Rotating server SVID")

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}

	// Sign the CSR
	svid, err := r.c.ServerCA.SignServerX509SVID(ctx, ca.ServerX509SVIDParams{
		PublicKey: key.Public(),
	})
	if err != nil {
		return err
	}

	s := State{
		SVID: svid,
		Key:  key,
	}

	r.state.Update(s)
	return nil
}

func certHalfLife(cert *x509.Certificate) time.Time {
	return cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2)
}
