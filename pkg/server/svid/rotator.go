package svid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/url"
	"path"
	"time"

	"github.com/imkira/go-observer"
	"github.com/spiffe/spire/pkg/common/util"

	ca_pb "github.com/spiffe/spire/proto/server/ca"
)

type Rotator interface {
	Start() error
	Stop()

	State()     State
	Subscribe() observer.Stream
}

type rotator struct {
	c    *RotatorConfig
	stop chan struct{}

	state observer.Property
}

type State struct {
	SVID *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Start generates a new SVID and then starts the rotator.
func (r *rotator) Start() error {
	err := r.rotateSVID()
	if err != nil {
		return err
	}

	go r.run()
	return nil
}

func (r *rotator) Stop() {
	close(r.stop)
}

func (r *rotator) State() State {
	return r.state.Value().(State)
}

func (r *rotator) Subscribe() observer.Stream {
	return r.state.Observe()
}

// run starts a ticker which monitors the server SVID
// for expiration and invokes rotateSVID() as necessary.
func (r *rotator) run() {
	t := time.NewTicker(r.c.Interval)

	for {
		select {
		case <-r.stop:
			r.c.Log.Debug("Stopping SVID rotator")
			return
		case <-t.C:
			if r.shouldRotate() {
				if err := r.rotateSVID(); err != nil {
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

	ttl := s.SVID.NotAfter.Sub(time.Now())
	watermark := s.SVID.NotAfter.Sub(s.SVID.NotBefore) / 2

	return (ttl < watermark)
}

// rotateSVID cuts a new server SVID from the CA plugin and installs
// it on the endpoints struct. Also updates the CA certificates.
func (r *rotator) rotateSVID() error {
	r.c.Log.Debug("Rotating server SVID")

	id := &url.URL{
		Scheme: "spiffe",
		Host:   r.c.TrustDomain.Host,
		Path:   path.Join("spiffe", "server"),
	}

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}

	csr, err := util.MakeCSR(key, id.String())
	if err != nil {
		return err
	}

	ca := r.c.Catalog.CAs()[0]

	// Sign the CSR
	csrReq := &ca_pb.SignCsrRequest{Csr: csr}
	csrRes, err := ca.SignCsr(csrReq)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(csrRes.SignedCertificate)
	if err != nil {
		return err
	}

	s := State{
		SVID: cert,
		Key:  key,
	}

	r.state.Update(s)
	return nil
}
