package svid

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/ca"
)

type Rotator struct {
	c *RotatorConfig

	state observer.Property
}

// State is the current SVID and key
type State struct {
	SVID []*x509.Certificate
	Key  crypto.Signer
}

// Start generates a new SVID and then starts the rotator.
func (r *Rotator) Initialize(ctx context.Context) error {
	return r.rotateSVID(ctx)
}

func (r *Rotator) State() State {
	return r.state.Value().(State)
}

func (r *Rotator) Subscribe() observer.Stream {
	return r.state.Observe()
}

func (r *Rotator) Interval() time.Duration {
	return r.c.Interval
}

// Run starts a ticker which monitors the server SVID
// for expiration and rotates the SVID as necessary.
func (r *Rotator) Run(ctx context.Context) error {
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
func (r *Rotator) shouldRotate() bool {
	s := r.state.Value().(State)

	if len(s.SVID) == 0 {
		return true
	}

	return r.c.Clock.Now().After(certHalfLife(s.SVID[0]))
}

// rotateSVID cuts a new server SVID from the CA plugin and installs
// it on the endpoints struct. Also updates the CA certificates.
func (r *Rotator) rotateSVID(ctx context.Context) (err error) {
	counter := telemetry_server.StartRotateServerSVIDCall(r.c.Metrics)
	defer counter.Done(&err)
	r.c.Log.Debug("Rotating server SVID")

	signer, err := r.c.KeyType.GenerateSigner()
	if err != nil {
		return err
	}

	serverID, err := idutil.ServerID(r.c.TrustDomain)
	if err != nil {
		// this should never fail; it is purely defensive
		return fmt.Errorf("unable to determine server ID: %w", err)
	}

	svid, err := r.c.ServerCA.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  serverID,
		PublicKey: signer.Public(),
	})
	if err != nil {
		return err
	}

	r.c.Log.WithFields(logrus.Fields{
		telemetry.SPIFFEID:   svid[0].URIs[0].String(),
		telemetry.Expiration: svid[0].NotAfter.Format(time.RFC3339),
	}).Debug("Signed X509 SVID")

	r.state.Update(State{
		SVID: svid,
		Key:  signer,
	})

	return nil
}

func certHalfLife(cert *x509.Certificate) time.Time {
	return cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2)
}
