package ca

import (
	"crypto/x509"
	"fmt"
	"sync"

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

	caCert *x509.Certificate
}

func (m *manager) Start() error {
	err := m.rotateCA()
	if err != nil {
		return fmt.Errorf("rotate ca cert: %v", err)
	}

	return nil
}

func (m *manager) Wait() error {
	// Until we actually need tomb, just wait for dying state
	<-m.t.Dying()
	return nil
}

func (m *manager) Shutdown() {
	m.t.Kill(nil)
}

func (m *manager) rotateCA() error {
	m.c.Log.Debug("Initiating rotation of signing certificate")

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

	// Load the new cert into the CA plugin
	loadReq := &ca.LoadCertificateRequest{
		SignedIntermediateCert: cert.Raw,
	}
	_, err = serverCA.LoadCertificate(loadReq)
	if err != nil {
		return fmt.Errorf("load new ca cert: %v", err)
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.caCert = cert
	return nil
}
