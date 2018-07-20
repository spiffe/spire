package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/url"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/keymanager"
	"github.com/spiffe/spire/proto/server/upstreamca"
)

const (
	DefaultSVIDTTL  = time.Hour
	DefaultCATTL    = 24 * time.Hour
	backdate        = time.Second * 10
	safetyThreshold = 24 * time.Hour
)

type ManagerConfig struct {
	Catalog        catalog.Catalog
	TrustDomain    url.URL
	UpstreamBundle bool
	SVIDTTL        time.Duration
	CATTL          time.Duration
	CASubject      pkix.Name
	CertsPath      string
	Log            logrus.FieldLogger
}

type Manager interface {
	// Initializes the CA manager. Must be called before a call to Run().
	Initialize(ctx context.Context) error

	// Run runs the CA manager. It blocks until a failure or the context is
	// canceled.
	Run(ctx context.Context) error

	// Returns the CA being managed
	CA() ServerCA
}

type keypairSet struct {
	slot   string
	x509CA *x509.Certificate
}

func (k *keypairSet) X509CAKeyId() string {
	return fmt.Sprintf("x509-CA-%s", k.slot)
}

func (k *keypairSet) Reset() {
	k.x509CA = nil
}

type manager struct {
	c  *ManagerConfig
	ca *serverCA

	current *keypairSet
	next    *keypairSet

	hooks struct {
		now func() time.Time
	}
}

func NewManager(c *ManagerConfig) *manager {
	if c.SVIDTTL <= 0 {
		c.SVIDTTL = DefaultSVIDTTL
	}
	if c.CATTL <= 0 {
		c.CATTL = DefaultCATTL
	}

	m := &manager{
		c: c,
		ca: newServerCA(serverCAConfig{
			Catalog:     c.Catalog,
			TrustDomain: c.TrustDomain,
			DefaultTTL:  c.SVIDTTL,
		}),
		current: &keypairSet{
			slot: "A",
		},
		next: &keypairSet{
			slot: "B",
		},
	}
	m.hooks.now = time.Now
	return m
}

func (m *manager) Initialize(ctx context.Context) error {
	m.c.Log.Debugf("TTL: CA=%s SVID=%s", m.c.CATTL, m.c.SVIDTTL)

	if err := m.loadKeypairSets(ctx); err != nil {
		return err
	}
	if err := m.rotateCAs(ctx); err != nil {
		return err
	}

	return nil
}

func (m *manager) Run(ctx context.Context) error {
	err := util.RunTasks(ctx,
		func(ctx context.Context) error {
			return m.rotateCAsEvery(ctx, 1*time.Minute)
		},
		func(ctx context.Context) error {
			return m.pruneBundleEvery(ctx, 6*time.Hour)
		})
	if err == context.Canceled {
		err = nil
	}
	return nil
}

func (m *manager) CA() ServerCA {
	return m.ca
}

func (m *manager) rotateCAsEvery(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := m.rotateCAs(ctx)
			if err != nil {
				m.c.Log.Errorf("Manager unable to rotate CAs: %v", err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *manager) rotateCAs(ctx context.Context) error {
	// if there is no current keypair set, generate one
	if m.current.x509CA == nil {
		if err := m.prepareKeypairSet(ctx, m.current); err != nil {
			return err
		}
		m.setKeypairSet()
	}

	// if there is no next keypair set and the current is within the
	// preparation threshold, generate one.
	if m.next.x509CA == nil && m.shouldPrepare() {
		if err := m.prepareKeypairSet(ctx, m.next); err != nil {
			return err
		}
	}

	if m.shouldActivate() {
		m.current.Reset()
		m.current, m.next = m.next, m.current
		m.writeKeypairSets()
		m.setKeypairSet()
	}

	return nil
}

func (m *manager) pruneBundleEvery(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.pruneBundle(ctx); err != nil {
				m.c.Log.Errorf("Manager could not prune CA certificates: %v", err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *manager) pruneBundle(ctx context.Context) error {
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
		if c.NotAfter.After(m.hooks.now().Add(-safetyThreshold)) {
			newBundle.CaCerts = append(newBundle.CaCerts, c.Raw...)
		} else {
			reload = true
			m.c.Log.Infof("Manager is pruning CA certificate number %v with expiry date %v", c.SerialNumber, c.NotAfter)
		}
	}

	if len(newBundle.CaCerts) == 0 {
		m.c.Log.Warn("Manager pruning halted; all known CA certificates have expired")
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

func (m *manager) appendBundle(ctx context.Context, caCerts []byte) error {
	req := &datastore.Bundle{
		TrustDomain: m.c.TrustDomain.String(),
		CaCerts:     caCerts,
	}

	ds := m.c.Catalog.DataStores()[0]
	if _, err := ds.AppendBundle(ctx, req); err != nil {
		return err
	}

	return nil
}

func (m *manager) prepareKeypairSet(ctx context.Context, kps *keypairSet) error {
	m.c.Log.Debugf("Manager is preparing keypair set %q", kps.slot)
	kps.Reset()

	now := m.hooks.now()
	notBefore := now.Add(-backdate)
	notAfter := now.Add(m.c.CATTL)

	km := m.c.Catalog.KeyManagers()[0]

	// create/rotate the keymanager key
	signer, err := cryptoutil.GenerateKeyAndSigner(ctx, km, kps.X509CAKeyId(), keymanager.KeyAlgorithm_ECDSA_P384)
	if err != nil {
		return err
	}

	// either self-sign or sign with the upstream CA
	var cert *x509.Certificate
	var upstreamBundle []byte
	if upstreamCAs := m.c.Catalog.UpstreamCAs(); len(upstreamCAs) > 0 {
		cert, upstreamBundle, err = UpstreamSignServerCACertificate(ctx, upstreamCAs[0], signer, m.c.TrustDomain.Host, m.c.CASubject)
		if err != nil {
			return err
		}
	} else {
		cert, err = SelfSignServerCACertificate(signer, m.c.TrustDomain.Host, m.c.CASubject, notBefore, notAfter)
		if err != nil {
			return err
		}
	}

	bundle := make([]byte, 0, len(cert.Raw)+len(upstreamBundle))
	if m.c.UpstreamBundle {
		bundle = append(bundle, upstreamBundle...)
	}
	bundle = append(bundle, cert.Raw...)

	if err := m.appendBundle(ctx, bundle); err != nil {
		return err
	}

	kps.x509CA = cert
	m.writeKeypairSets()
	return nil
}

func (m *manager) loadKeypairSets(ctx context.Context) error {
	if m.c.CertsPath == "" {
		return nil
	}

	km := m.c.Catalog.KeyManagers()[0]
	publicKeys, err := loadPublicKeys(ctx, km)
	if err != nil {
		return err
	}

	certificates, err := loadCertificates(m.c.CertsPath)
	if err != nil {
		return err
	}

	lookup := func(keyId string) *x509.Certificate {
		certificate := certificates[keyId]
		publicKey := publicKeys[keyId]
		if certificate != nil && publicKey != nil && certMatchesKey(certificate, publicKey) {
			return certificate
		}
		return nil
	}

	m.current.x509CA = lookup(m.current.X509CAKeyId())
	m.next.x509CA = lookup(m.next.X509CAKeyId())

	if m.current.x509CA != nil && m.next.x509CA != nil &&
		m.current.x509CA.NotBefore.After(m.next.x509CA.NotBefore) {
		// swap the current and next keypair to get ascending order
		m.current, m.next = m.next, m.current
	}

	m.c.Log.Debugf("Manager has loaded keypair sets")
	if m.current.x509CA != nil {
		m.setKeypairSet()
	}
	return nil
}

func (m *manager) getCurrentKeypairSet() *keypairSet {
	return m.current
}

func (m *manager) getNextKeypairSet() *keypairSet {
	return m.next
}

func (m *manager) setKeypairSet() {
	m.c.Log.Debugf("Manager is activating keypair set %q", m.current.slot)
	m.ca.setKeypairSet(*m.current)
}

func (m *manager) writeKeypairSets() {
	if m.c.CertsPath == "" {
		return
	}
	certificates := make(map[string]*x509.Certificate)
	if m.current.x509CA != nil {
		certificates[m.current.X509CAKeyId()] = m.current.x509CA
	}
	if m.next.x509CA != nil {
		certificates[m.next.X509CAKeyId()] = m.next.x509CA
	}
	if err := writeCertificates(m.c.CertsPath, certificates); err != nil {
		m.c.Log.Warnf("unable to write keypair sets: %v", err)
	}
}

func (m *manager) shouldPrepare() bool {
	return m.current.x509CA == nil || m.hooks.now().After(preparationThreshold(m.current.x509CA))
}

func (m *manager) shouldActivate() bool {
	return m.current.x509CA == nil || m.hooks.now().After(activationThreshold(m.current.x509CA))
}

func certMatchesKey(certificate *x509.Certificate, publicKey crypto.PublicKey) bool {
	matches, err := x509util.CertificateMatchesKey(certificate, publicKey)
	if err != nil {
		return false
	}

	return matches
}

func GenerateServerCACSR(signer crypto.Signer, trustDomain string, subject pkix.Name) ([]byte, error) {
	spiffeID := &url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
	}

	template := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		URIs:               []*url.URL{spiffeID},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, signer)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

func UpstreamSignServerCACertificate(ctx context.Context, upstreamCA upstreamca.UpstreamCA, signer crypto.Signer, trustDomain string, subject pkix.Name) (*x509.Certificate, []byte, error) {
	csr, err := GenerateServerCACSR(signer, trustDomain, subject)
	if err != nil {
		return nil, nil, err
	}

	csrResp, err := upstreamCA.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{
		Csr: csr,
	})
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(csrResp.Cert)
	if err != nil {
		return nil, nil, err
	}
	return cert, csrResp.UpstreamTrustBundle, nil
}

func SelfSignServerCACertificate(signer crypto.Signer, trustDomain string, subject pkix.Name, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	csr, err := GenerateServerCACSR(signer, trustDomain, subject)
	if err != nil {
		return nil, err
	}

	template, err := CreateServerCATemplate(csr, trustDomain, notBefore, notAfter, big.NewInt(0))
	if err != nil {
		return nil, err
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func loadPublicKeys(ctx context.Context, km keymanager.KeyManager) (map[string]crypto.PublicKey, error) {
	resp, err := km.GetPublicKeys(ctx, &keymanager.GetPublicKeysRequest{})
	if err != nil {
		return nil, err
	}

	publicKeys := make(map[string]crypto.PublicKey)
	for _, publicKey := range resp.PublicKeys {
		x, err := x509.ParsePKIXPublicKey(publicKey.PkixData)
		if err != nil {
			return nil, err
		}
		publicKeys[publicKey.Id] = x
	}

	return publicKeys, nil
}

type certificateData struct {
	Certs map[string][]byte `json:"certs"`
}

func loadCertificates(path string) (map[string]*x509.Certificate, error) {
	certs := make(map[string]*x509.Certificate)

	jsonBytes, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return certs, nil
		}
		return nil, err
	}

	data := new(certificateData)
	if err := json.Unmarshal(jsonBytes, data); err != nil {
		return nil, fmt.Errorf("unable to decode certificate JSON: %v", err)
	}

	for id, certBytes := range data.Certs {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate %q: %v", id, err)
		}
		certs[id] = cert
	}

	return certs, nil
}

func writeCertificates(path string, certs map[string]*x509.Certificate) error {
	data := &certificateData{
		Certs: make(map[string][]byte),
	}
	for id, cert := range certs {
		data.Certs[id] = cert.Raw
	}

	jsonBytes, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return err
	}

	return diskutil.AtomicWriteFile(path, jsonBytes, 0644)
}

func preparationThreshold(cert *x509.Certificate) time.Time {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	return cert.NotAfter.Add(-lifetime / 2)
}

func activationThreshold(cert *x509.Certificate) time.Time {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	return cert.NotAfter.Add(-lifetime / 6)
}
