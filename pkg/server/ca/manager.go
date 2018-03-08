package ca

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/upstreamca"

	tomb "gopkg.in/tomb.v2"
)

type Manager interface {
	// Start the CA Manager. Blocks until the CA is fully intialized.
	Start() error

	// Wait on the CA manager to either encounter an error or shutdown.
	Wait() error

	// Shutdown the CA manager.
	Shutdown()
}

type manager struct {
	c   *Config
	t   *tomb.Tomb
	mtx *sync.RWMutex

	caCert     *x509.Certificate
	nextCACert *x509.Certificate

	rotateTicker *time.Ticker
	pruneTicker  *time.Ticker
}

func (m *manager) Start() error {
	err := m.prepareNextCA()
	if err != nil {
		return fmt.Errorf("create ca certificate: %v", err)
	}

	err = m.activateNextCA()
	if err != nil {
		return fmt.Errorf("activate ca certificate: %v", err)
	}

	m.t.Go(m.startCARotator)
	m.t.Go(m.startPruner)
	return nil
}

func (m *manager) Wait() error {
	return m.t.Wait()
}

func (m *manager) Shutdown() {
	m.t.Kill(nil)
}

func (m *manager) startCARotator() error {
	for {
		select {
		case <-m.rotateTicker.C:
			err := m.caRotate()
			if err != nil {
				m.c.Log.Errorf("Problem encountered while tending to CA rotation: %v", err)
			}
		case <-m.t.Dying():
			return tomb.ErrDying
		}
	}
}

// caRotate inspects certificate expiration times and determines if rotation
// actions need to be performed, calling either prepareNextCA() or activateNextCA()
// as needed.
//
// TODO: This could probably be simplified with something like a FSM
func (m *manager) caRotate() error {
	if m.caCert == nil {
		return errors.New("ca manager not initialized; no ca cert present")
	}

	// Prepare a new CA once the current one is 1/2 of the way to expiration
	ttl := time.Until(m.caCert.NotAfter)
	lifetime := m.caCert.NotAfter.Sub(m.caCert.NotBefore)
	if (ttl < lifetime/2) && m.nextCACert == nil {
		return m.prepareNextCA()
	}

	// Activate the new CA once the current one is 5/6ths of the way to expiration
	if ttl < lifetime/6 {
		return m.activateNextCA()
	}

	// Nothing to see here, move along now...
	return nil
}

func (m *manager) prepareNextCA() error {
	m.c.Log.Debug("Creating a new CA certificate")

	// Get a CSR from the CA plugin
	serverCA := m.c.Catalog.CAs()[0]
	csrRes, err := serverCA.GenerateCsr(&ca.GenerateCsrRequest{})
	if err != nil {
		return fmt.Errorf("generate csr: %v", err)
	}

	// Get it signed by Upstream
	upstreamCA := m.c.Catalog.UpstreamCAs()[0]
	signRes, err := upstreamCA.SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: csrRes.Csr})
	if err != nil {
		return fmt.Errorf("submit csr to upstream ca: %v", err)
	}

	// Store the new cert
	cert, err := x509.ParseCertificate(signRes.Cert)
	if err != nil {
		return fmt.Errorf("invalid cert from upstream: %v", err)
	}

	m.mtx.RLock()
	storeReq := &datastore.Bundle{
		TrustDomain: m.c.TrustDomain.String(),
		CaCerts:     cert.Raw,
	}
	m.mtx.RUnlock()

	ds := m.c.Catalog.DataStores()[0]
	_, err = ds.AppendBundle(storeReq)
	if err != nil {
		return fmt.Errorf("store new ca cert: %v", err)
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.nextCACert = cert
	return nil
}

func (m *manager) activateNextCA() error {
	if m.nextCACert == nil {
		return errors.New("next ca cert not prepared")
	}

	m.c.Log.Debug("Activating new CA certificate")
	serverCA := m.c.Catalog.CAs()[0]

	loadReq := &ca.LoadCertificateRequest{
		SignedIntermediateCert: m.nextCACert.Raw,
	}
	_, err := serverCA.LoadCertificate(loadReq)
	if err != nil {
		return fmt.Errorf("load new ca cert: %v", err)
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.caCert = m.nextCACert
	m.nextCACert = nil
	return nil
}

func (m *manager) startPruner() error {
	for {
		select {
		case <-m.pruneTicker.C:
			err := m.prune()
			if err != nil {
				m.c.Log.Errorf("Could not prune CA certificates: %v", err)
			}
		case <-m.t.Dying():
			return tomb.ErrDying
		}
	}
}

func (m *manager) prune() error {
	ds := m.c.Catalog.DataStores()[0]

	oldBundle := &datastore.Bundle{TrustDomain: m.c.TrustDomain.String()}
	oldBundle, err := ds.FetchBundle(oldBundle)
	if err != nil {
		return fmt.Errorf("fetch bundle: %v", err)
	}

	newBundle := &datastore.Bundle{
		TrustDomain: oldBundle.TrustDomain,
		CaCerts:     []byte{},
	}

	certs, err := x509.ParseCertificates(oldBundle.CaCerts)
	if err != nil {
		return fmt.Errorf("parse bundle from datastore: %v", err)
	}

	var reload bool
	for _, c := range certs {
		// Be gentle while removing CA certificates
		// If expired < 24hrs ago, keep it.
		// TODO: should this be relaxed even further?
		if c.NotAfter.After(time.Now().Add(-24 * time.Hour)) {
			newBundle.CaCerts = append(newBundle.CaCerts, c.Raw...)
		} else {
			reload = true
			m.c.Log.Infof("Pruning CA certificate number %v with expiry date %v", c.SerialNumber, c.NotAfter)
		}
	}

	if len(newBundle.CaCerts) == 0 {
		m.c.Log.Warn("All known CA certificates have expired! Pruning has been halted.")
		return errors.New("would prune all certificates")
	}

	if reload {
		_, err = ds.UpdateBundle(newBundle)
		if err != nil {
			return fmt.Errorf("write new bundle: %v", err)
		}
	}

	return nil
}
