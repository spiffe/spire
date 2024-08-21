package svid

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/proto/spire/common"
)

var (
	defaultBundleVerificationTicker = 30 * time.Second
)

type Rotator struct {
	c *RotatorConfig

	lastBundleSequeceNumber uint64
	state                   observer.Property
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

	bundeVerificationTicker := r.c.Clock.Ticker(defaultBundleVerificationTicker)
	defer bundeVerificationTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.c.Log.Debug("Stopping SVID rotator")
			return nil
		case <-bundeVerificationTicker.C:
			sequenceNumber, err := r.processBundle(ctx)
			if err != nil {
				r.c.Log.WithError(err).Error("Failed to process bundle update")
				continue
			}
			r.lastBundleSequeceNumber = sequenceNumber

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

func (r *Rotator) processBundle(ctx context.Context) (uint64, error) {
	// TODO: fetching bundle every time...
	// may we add a new chan into manager that we can consume?
	// or just read bundle from there, to prevent to search bundles from DB?
	cBundle, err := r.c.DataStore.FetchBundle(ctx, r.c.TrustDomain.IDString())
	if err != nil {
		return 0, fmt.Errorf("failed to verify bundle update: %w", err)
	}

	// No bundle update, nothing to process
	if cBundle.SequenceNumber == r.lastBundleSequeceNumber {
		return r.lastBundleSequeceNumber, nil
	}

	isTainted, err := r.isTainted(cBundle)
	if err != nil {
		return 0, fmt.Errorf("failed to verify if bundle is tainted: %w", err)
	}

	if !isTainted {
		return r.lastBundleSequeceNumber, nil
	}

	r.c.Log.Info("Server SVID signed using a tainted authority, forcing rotation...")

	if err := r.rotateSVID(ctx); err != nil {
		return 0, fmt.Errorf("could not rotate server SVID: %w", err)
	}

	// It is possible than intermediate is not rotated yet,
	// verify again.
	isTainted, err = r.isTainted(cBundle)
	if err != nil {
		return 0, fmt.Errorf("failed to verify if new Server SVID is still signed by a tainted authority: %w", err)
	}
	if isTainted {
		return 0, errors.New("intermediate is not rotated, retry rotation")
	}

	return cBundle.SequenceNumber, nil
}

func (r *Rotator) isTainted(cBundle *common.Bundle) (bool, error) {
	svid := r.State().SVID

	// Search for any tainted bundle
	var taintedAuthorities []*x509.Certificate
	for _, eachCert := range cBundle.RootCas {
		if eachCert.TaintedKey {
			// Technically error must never happen
			cert, err := x509.ParseCertificate(eachCert.DerBytes)
			if err != nil {
				return false, fmt.Errorf("failed to parse root CA: %w", err)
			}
			taintedAuthorities = append(taintedAuthorities, cert)
		}
	}

	if len(taintedAuthorities) == 0 {
		// No tainted certs
		return false, nil
	}

	return isX509AuthorityTainted(svid, taintedAuthorities), nil
}

func isX509AuthorityTainted(svid []*x509.Certificate, taintedAuthorities []*x509.Certificate) bool {
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

	return nil
}

func certHalfLife(cert *x509.Certificate) time.Time {
	return cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2)
}
