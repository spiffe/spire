package svid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/url"
	"path"
	"time"

	"github.com/imkira/go-observer"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
)

type Rotator interface {
	Initialize(ctx context.Context) error
	Run(ctx context.Context) error

	State() State
	Subscribe() observer.Stream
}

type rotator struct {
	c *RotatorConfig

	state observer.Property

	hooks struct {
		now func() time.Time
	}
}

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
	t := time.NewTicker(r.c.Interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			r.c.Log.Debug("Stopping SVID rotator")
			return nil
		case <-t.C:
			if r.shouldRotate() {
				if err := r.rotateSVID(ctx); err != nil {
					r.c.Log.Errorf("Could not rotate server SVID: %v", err)
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

	ttl := s.SVID[0].NotAfter.Sub(r.hooks.now())
	watermark := s.SVID[0].NotAfter.Sub(s.SVID[0].NotBefore) / 2

	return (ttl < watermark)
}

// rotateSVID cuts a new server SVID from the CA plugin and installs
// it on the endpoints struct. Also updates the CA certificates.
func (r *rotator) rotateSVID(ctx context.Context) (err error) {
	defer telemetry.CountCall(r.c.Metrics, &err, "rotate", "svid")()
	r.c.Log.Debug("Rotating server SVID")

	id := &url.URL{
		Scheme: "spiffe",
		Host:   r.c.TrustDomain.Host,
		Path:   path.Join("spire", "server"),
	}

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}

	csr, err := util.MakeCSR(key, id.String())
	if err != nil {
		return err
	}

	// Sign the CSR
	svid, err := r.c.ServerCA.SignX509SVID(ctx, csr, 0)
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
