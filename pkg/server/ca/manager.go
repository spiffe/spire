package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/upstreamca"
)

type Manager interface {
	// Initializes the CA manager. Must be called before a call to Run().
	Initialize(ctx context.Context) error

	// Run runs the CA manager. It blocks until a failure or the context is
	// canceled.
	Run(ctx context.Context) error
}

type manager struct {
	c   *Config
	mtx *sync.RWMutex

	caCert     *x509.Certificate
	nextCACert *x509.Certificate
}

func (m *manager) Initialize(ctx context.Context) error {
	if err := m.prepareNextCA(ctx); err != nil {
		return fmt.Errorf("create ca certificate: %v", err)
	}

	if err := m.activateNextCA(ctx); err != nil {
		return fmt.Errorf("activate ca certificate: %v", err)
	}

	return nil
}

func (m *manager) Run(ctx context.Context) error {
	err := util.RunTasks(ctx,
		func(ctx context.Context) error {
			return m.startCARotator(ctx, 1*time.Minute)
		},
		func(ctx context.Context) error {
			return m.startPruner(ctx, 6*time.Hour)
		})
	if err == context.Canceled {
		err = nil
	}
	return nil
}

func (m *manager) startCARotator(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := m.caRotate(ctx)
			if err != nil {
				m.c.Log.Errorf("Problem encountered while tending to CA rotation: %v", err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// caRotate inspects certificate expiration times and determines if rotation
// actions need to be performed, calling either prepareNextCA() or activateNextCA()
// as needed.
//
// TODO: This could probably be simplified with something like a FSM
func (m *manager) caRotate(ctx context.Context) error {
	if m.caCert == nil {
		return errors.New("ca manager not initialized; no ca cert present")
	}

	// Prepare a new CA once the current one is 1/2 of the way to expiration
	ttl := time.Until(m.caCert.NotAfter)
	lifetime := m.caCert.NotAfter.Sub(m.caCert.NotBefore)
	if (ttl < lifetime/2) && m.nextCACert == nil {
		if err := m.prepareNextCA(ctx); err != nil {
			return err
		}
	}

	// Activate the new CA once the current one is 5/6ths of the way to expiration
	if ttl < lifetime/6 {
		if err := m.activateNextCA(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (m *manager) prepareNextCA(ctx context.Context) error {
	m.c.Log.Debug("Creating a new CA certificate")

	// Get a CSR from the CA plugin
	serverCA := m.c.Catalog.CAs()[0]
	csrRes, err := serverCA.GenerateCsr(ctx, &ca.GenerateCsrRequest{})
	if err != nil {
		return fmt.Errorf("generate csr: %v", err)
	}

	// Get it signed by Upstream
	upstreamCA := m.c.Catalog.UpstreamCAs()[0]
	signRes, err := upstreamCA.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: csrRes.Csr})
	if err != nil {
		return fmt.Errorf("submit csr to upstream ca: %v", err)
	}

	cert, err := x509.ParseCertificate(signRes.Cert)
	if err != nil {
		return fmt.Errorf("invalid cert from upstream: %v", err)
	}

	err = m.storeCACert(ctx, cert, signRes.UpstreamTrustBundle)
	if err != nil {
		return fmt.Errorf("store new ca cert: %v", err)
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.nextCACert = cert
	return nil
}

func (m *manager) activateNextCA(ctx context.Context) error {
	if m.nextCACert == nil {
		return errors.New("next ca cert not prepared")
	}

	m.c.Log.Debug("Activating new CA certificate")
	serverCA := m.c.Catalog.CAs()[0]

	loadReq := &ca.LoadCertificateRequest{
		SignedIntermediateCert: m.nextCACert.Raw,
	}
	_, err := serverCA.LoadCertificate(ctx, loadReq)
	if err != nil {
		return fmt.Errorf("load new ca cert: %v", err)
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.caCert = m.nextCACert
	m.nextCACert = nil
	return nil
}

func (m *manager) startPruner(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.prune(ctx); err != nil {
				m.c.Log.Errorf("Could not prune CA certificates: %v", err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *manager) prune(ctx context.Context) error {
	ds := m.c.Catalog.DataStores()[0]

	oldBundle := &datastore.Bundle{TrustDomain: m.c.TrustDomain.String()}
	oldBundle, err := ds.FetchBundle(ctx, oldBundle)
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
		_, err = ds.UpdateBundle(ctx, newBundle)
		if err != nil {
			return fmt.Errorf("write new bundle: %v", err)
		}
	}

	return nil
}

func (m *manager) storeCACert(ctx context.Context, caCert *x509.Certificate, upstreamBundle []byte) error {
	m.mtx.RLock()
	storeReq := &datastore.Bundle{
		TrustDomain: m.c.TrustDomain.String(),
		CaCerts:     caCert.Raw,
	}
	m.mtx.RUnlock()

	if m.c.UpstreamBundle {
		storeReq.CaCerts = append(storeReq.CaCerts, upstreamBundle...)
	}

	ds := m.c.Catalog.DataStores()[0]
	_, err := ds.AppendBundle(ctx, storeReq)
	if err != nil {
		return err
	}

	return nil
}
