package svid

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"

	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/ca"
)

var (
	defaultBundleVerificationTicker = 30 * time.Second
)

type Rotator struct {
	c *RotatorConfig

	state           observer.Property
	isSVIDTainted   bool
	taintedReceived chan bool
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

func (r *Rotator) triggerTaintedReceived(tainted bool) {
	r.taintedReceived <- tainted
}

// Run starts a ticker which monitors the server SVID
// for expiration and rotates the SVID as necessary.
func (r *Rotator) Run(ctx context.Context) error {
	t := r.c.Clock.Ticker(r.c.Interval)
	defer t.Stop()

	bundeVerificationTicker := r.c.Clock.Ticker(defaultBundleVerificationTicker)
	defer bundeVerificationTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.c.Log.Debug("Stopping SVID rotator")
			return nil
		case taintedAuthorities := <-r.c.ServerCA.TaintedAuthorities():
			isTainted := r.isX509AuthorityTainted(taintedAuthorities)
			if isTainted {
				r.triggerTaintedReceived(true)
				r.c.Log.Info("Server SVID signed using a tainted authority, forcing rotation of the Server SVID")
				r.isSVIDTainted = true
			}
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

	return r.c.Clock.Now().After(certHalfLife(s.SVID[0])) ||
		r.isSVIDTainted
}

func (r *Rotator) isX509AuthorityTainted(taintedAuthorities []*x509.Certificate) bool {
	svid := r.State().SVID

	rootPool := x509.NewCertPool()
	for _, taintedKey := range taintedAuthorities {
		rootPool.AddCert(taintedKey)
	}

	intermediatePool := x509.NewCertPool()
	for _, intermediateCA := range svid[1:] {
		intermediatePool.AddCert(intermediateCA)
	}

	// Verify certificate chain, using tainted authority as root
	_, err := svid[0].Verify(x509.VerifyOptions{
		Intermediates: intermediatePool,
		Roots:         rootPool,
		CurrentTime:   r.c.Clock.Now(),
	})

	return err == nil
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

	svid, err := r.c.ServerCA.SignServerX509SVID(ctx, ca.ServerX509SVIDParams{
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
	// New SVID must not be tainted. Rotator is notified about tainted
	// authorities only when the intermediate is already rotated.
	r.isSVIDTainted = false

	return nil
}

func certHalfLife(cert *x509.Certificate) time.Time {
	return cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2)
}
