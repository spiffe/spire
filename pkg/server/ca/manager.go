package ca

import (
	"bytes"
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
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/keymanager"
	"github.com/spiffe/spire/proto/server/upstreamca"
	"github.com/zeebo/errs"
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

type caX509CA struct {
	// the CA certificate
	cert *x509.Certificate

	// this is the full chain of trust from the server CA back to the upstream
	// CA. If the server CA is self-signed, this list will only contain the
	// server CA certificate.
	chain []*x509.Certificate
}

type caPublicKey struct {
	*common.PublicKey

	// public key parsed from the common.PublicKey message
	publicKey crypto.PublicKey

	// parsed "notAfter" time from the common.PublicKey message
	notAfter time.Time
}

type keypairSet struct {
	slot          string
	x509CA        *caX509CA
	jwtSigningKey *caPublicKey
}

func (k *keypairSet) X509CAKeyID() string {
	return fmt.Sprintf("x509-CA-%s", k.slot)
}

func (k *keypairSet) JWTSignerKeyID() string {
	return fmt.Sprintf("JWT-Signer-%s", k.slot)
}

func (k *keypairSet) Reset() {
	k.x509CA = nil
	k.jwtSigningKey = nil
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
	return err
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

	now := m.hooks.now().Add(-safetyThreshold)

	resp, err := ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: m.c.TrustDomain.String(),
	})
	if err != nil {
		return errs.Wrap(err)
	}
	oldBundle := resp.Bundle
	if oldBundle == nil {
		// no bundle to prune
		return nil
	}

	newBundle := &datastore.Bundle{
		TrustDomainId: oldBundle.TrustDomainId,
	}
	changed := false
pruneRootCA:
	for _, rootCA := range oldBundle.RootCas {
		certs, err := x509.ParseCertificates(rootCA.DerBytes)
		if err != nil {
			return errs.Wrap(err)
		}
		// if any cert in the chain has expired beyond the safety
		// threshhold, throw the whole chain out
		for _, cert := range certs {
			if !cert.NotAfter.After(now) {
				m.c.Log.Infof("Manager is pruning CA certificate number %v with expiry date %v", cert.SerialNumber, cert.NotAfter)
				changed = true
				continue pruneRootCA
			}
		}
		newBundle.RootCas = append(newBundle.RootCas, rootCA)
	}

	for _, jwtSigningKey := range oldBundle.JwtSigningKeys {
		notAfter := time.Unix(jwtSigningKey.NotAfter, 0)
		if !notAfter.After(now) {
			m.c.Log.Infof("Manager is pruning JWT signing key %q with expiry date %v", jwtSigningKey.Kid, notAfter)
			changed = true
			continue
		}
		newBundle.JwtSigningKeys = append(newBundle.JwtSigningKeys, jwtSigningKey)
	}

	if len(newBundle.RootCas) == 0 {
		m.c.Log.Warn("Manager pruning halted; all known CA certificates have expired")
		return errors.New("would prune all certificates")
	}

	if len(newBundle.JwtSigningKeys) == 0 {
		m.c.Log.Warn("Manager pruning halted; all known JWT signing keys have expired")
		return errors.New("would prune all JWT signing keys")
	}

	if changed {
		_, err := ds.UpdateBundle(ctx, &datastore.UpdateBundleRequest{
			Bundle: newBundle,
		})
		if err != nil {
			return fmt.Errorf("write new bundle: %v", err)
		}
	}

	return nil
}

func (m *manager) appendBundle(ctx context.Context, rootCA *x509.Certificate, jwtSigningKey *common.PublicKey) error {
	ds := m.c.Catalog.DataStores()[0]
	if _, err := ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
		Bundle: &common.Bundle{
			TrustDomainId: m.c.TrustDomain.String(),
			RootCas: []*common.Certificate{
				{DerBytes: rootCA.Raw},
			},
			JwtSigningKeys: []*common.PublicKey{
				jwtSigningKey,
			},
		},
	}); err != nil {
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
	x509CASigner, err := cryptoutil.GenerateKeyAndSigner(ctx, km, kps.X509CAKeyID(), keymanager.KeyAlgorithm_ECDSA_P384)
	if err != nil {
		return err
	}

	// either self-sign or sign with the upstream CA
	var cert *x509.Certificate
	var upstreamBundle []*x509.Certificate
	if upstreamCAs := m.c.Catalog.UpstreamCAs(); len(upstreamCAs) > 0 {
		cert, upstreamBundle, err = UpstreamSignServerCACertificate(ctx, upstreamCAs[0], x509CASigner, m.c.TrustDomain.Host, m.c.CASubject)
		if err != nil {
			return err
		}
	} else {
		cert, err = SelfSignServerCACertificate(x509CASigner, m.c.TrustDomain.Host, m.c.CASubject, notBefore, notAfter)
		if err != nil {
			return err
		}
	}

	jwtSigningKeyPKIX, err := cryptoutil.GenerateKeyRaw(ctx, km, kps.JWTSignerKeyID(), keymanager.KeyAlgorithm_ECDSA_P256)
	if err != nil {
		return err
	}

	kid, err := newKeyID()
	if err != nil {
		return err
	}

	jwtSigningKey, err := caPublicKeyFromPublicKey(&common.PublicKey{
		PkixBytes: jwtSigningKeyPKIX,
		Kid:       kid,
		NotAfter:  cert.NotAfter.Unix(),
	})
	if err != nil {
		return err
	}

	// The root CA added to the bundle is either the upstream "root" or the
	// newly signed server CA.
	rootCA := cert
	chain := []*x509.Certificate{cert}
	if m.c.UpstreamBundle && len(upstreamBundle) > 0 {
		rootCA = upstreamBundle[len(upstreamBundle)-1]
		chain = append(chain, upstreamBundle...)
	}

	if err := m.appendBundle(ctx, rootCA, jwtSigningKey.PublicKey); err != nil {
		return err
	}

	kps.x509CA = &caX509CA{
		cert:  cert,
		chain: chain,
	}
	kps.jwtSigningKey = jwtSigningKey
	m.writeKeypairSets()
	return nil
}

func (m *manager) loadKeypairSets(ctx context.Context) error {
	if m.c.CertsPath == "" {
		return nil
	}

	km := m.c.Catalog.KeyManagers()[0]
	keys, err := loadKeyManagerKeys(ctx, km)
	if err != nil {
		return err
	}

	ds := m.c.Catalog.DataStores()[0]
	resp, err := ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: m.c.TrustDomain.String(),
	})
	if err != nil {
		return errs.Wrap(err)
	}

	var rootCAs []*x509.Certificate
	if resp.Bundle != nil {
		rootCAs, err = bundleutil.RootCAsFromBundleProto(resp.Bundle)
		if err != nil {
			return err
		}
	}

	x509CAs, publicKeys, err := m.loadKeypairData(m.c.CertsPath, rootCAs)
	if err != nil {
		return err
	}

	lookupX509CA := func(keyID string) *caX509CA {
		x509CA := x509CAs[keyID]
		key := keys[keyID]
		if x509CA != nil && key != nil && certMatchesKey(x509CA.cert, key) {
			return x509CA
		}
		return nil
	}

	lookupPublicKey := func(keyID string) *caPublicKey {
		publicKey := publicKeys[keyID]
		key := keys[keyID]
		if publicKey != nil && key != nil && publicKeyEqual(publicKey.publicKey, key) {
			return publicKey
		}
		return nil
	}

	// load up the current keypair set and make sure it has all required certs
	m.current.x509CA = lookupX509CA(m.current.X509CAKeyID())
	m.current.jwtSigningKey = lookupPublicKey(m.current.JWTSignerKeyID())
	if m.current.x509CA == nil || m.current.jwtSigningKey == nil {
		m.current.Reset()
	}

	// load up the next keypair set and make sure it has all required certs
	m.next.x509CA = lookupX509CA(m.next.X509CAKeyID())
	m.next.jwtSigningKey = lookupPublicKey(m.next.JWTSignerKeyID())
	if m.next.x509CA == nil || m.next.jwtSigningKey == nil {
		m.next.Reset()
	}

	if m.current.x509CA != nil && m.next.x509CA != nil &&
		m.current.x509CA.cert.NotBefore.After(m.next.x509CA.cert.NotBefore) {
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
	x509CAs := make(map[string]*caX509CA)
	publicKeys := make(map[string]*caPublicKey)
	if m.current.x509CA != nil {
		x509CAs[m.current.X509CAKeyID()] = m.current.x509CA
	}
	if m.current.jwtSigningKey != nil {
		publicKeys[m.current.JWTSignerKeyID()] = m.current.jwtSigningKey
	}
	if m.next.x509CA != nil {
		x509CAs[m.next.X509CAKeyID()] = m.next.x509CA
	}
	if m.next.jwtSigningKey != nil {
		publicKeys[m.next.JWTSignerKeyID()] = m.next.jwtSigningKey
	}
	if err := writeKeypairData(m.c.CertsPath, x509CAs, publicKeys); err != nil {
		m.c.Log.Errorf("unable to write keypair sets: %v", err)
	}
}

func (m *manager) shouldPrepare() bool {
	return m.current.x509CA == nil || m.hooks.now().After(preparationThreshold(m.current.x509CA.cert))
}

func (m *manager) shouldActivate() bool {
	return m.current.x509CA == nil || m.hooks.now().After(activationThreshold(m.current.x509CA.cert))
}

type keypairData struct {
	DEPRECATEDCerts map[string][]byte `json:"certs"`
	CAs             map[string][]byte `json:"cas"`
	PublicKeys      map[string][]byte `json:"public_keys"`
}

func (m *manager) loadKeypairData(path string, bundleCerts []*x509.Certificate) (map[string]*caX509CA, map[string]*caPublicKey, error) {
	x509CAs := make(map[string]*caX509CA)
	publicKeys := make(map[string]*caPublicKey)

	jsonBytes, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return x509CAs, publicKeys, nil
		}
		return nil, nil, err
	}

	data := new(keypairData)
	if err := json.Unmarshal(jsonBytes, data); err != nil {
		return nil, nil, fmt.Errorf("unable to decode certificate JSON: %v", err)
	}

	for id, caBytes := range data.CAs {
		certs, err := x509.ParseCertificates(caBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse certificate %q: %v", id, err)
		}
		if len(certs) == 0 {
			continue
		}
		x509CAs[id] = &caX509CA{
			cert:  certs[0],
			chain: certs,
		}
	}

	for id, publicKeyBytes := range data.PublicKeys {
		publicKey := new(common.PublicKey)
		if err := proto.Unmarshal(publicKeyBytes, publicKey); err != nil {
			return nil, nil, fmt.Errorf("unable to parse public key %q: %v", id, err)
		}
		mpk, err := caPublicKeyFromPublicKey(publicKey)
		if err != nil {
			return nil, nil, err
		}
		publicKeys[id] = mpk
	}

	for id, certBytes := range data.DEPRECATEDCerts {
		// skip items that already exist (should never happen)
		if x509CAs[id] != nil || publicKeys[id] != nil {
			m.c.Log.Warnf("skipping deprecated cert %q in keypair data; already exists", id)
			continue
		}

		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse deprecated cert %q: %v", id, err)
		}

		if strings.HasPrefix(id, "x509-CA-") {
			certs := buildCertChain(cert, bundleCerts)
			x509CAs[id] = &caX509CA{
				cert:  certs[0],
				chain: certs,
			}
		}

		if strings.HasPrefix(id, "JWT-Signer-") {
			// converting the JWT cert to key is trivial. Just pull out
			// the public key and expiration from the cert and generate
			// a deterministic key id.
			pkixBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to marshal public key from deprecated cert %q: %v", id, err)
			}

			publicKeys[id] = &caPublicKey{
				PublicKey: &common.PublicKey{
					Kid:       keyIDFromBytes(cert.Signature),
					PkixBytes: pkixBytes,
					NotAfter:  cert.NotAfter.Unix(),
				},
				publicKey: cert.PublicKey,
				notAfter:  cert.NotAfter,
			}
		}
	}

	return x509CAs, publicKeys, nil
}

func certMatchesKey(certificate *x509.Certificate, publicKey crypto.PublicKey) bool {
	matches, err := x509util.CertificateMatchesKey(certificate, publicKey)
	if err != nil {
		return false
	}
	return matches
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	matches, err := cryptoutil.PublicKeyEqual(a, b)
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

func UpstreamSignServerCACertificate(ctx context.Context, upstreamCA upstreamca.UpstreamCA, signer crypto.Signer, trustDomain string, subject pkix.Name) (*x509.Certificate, []*x509.Certificate, error) {
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
	upstream, err := x509.ParseCertificates(csrResp.UpstreamTrustBundle)
	if err != nil {
		return nil, nil, err
	}
	return cert, upstream, nil
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

func loadKeyManagerKeys(ctx context.Context, km keymanager.KeyManager) (map[string]crypto.PublicKey, error) {
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

func writeKeypairData(path string, x509CAs map[string]*caX509CA, publicKeys map[string]*caPublicKey) error {
	data := &keypairData{
		CAs:        make(map[string][]byte),
		PublicKeys: make(map[string][]byte),
	}
	for id, x509CA := range x509CAs {
		var raw []byte
		for _, cert := range x509CA.chain {
			raw = append(raw, cert.Raw...)
		}
		data.CAs[id] = raw
	}

	for id, publicKey := range publicKeys {
		publicKeyBytes, err := proto.Marshal(publicKey.PublicKey)
		if err != nil {
			return errs.Wrap(err)
		}
		data.PublicKeys[id] = publicKeyBytes
	}

	jsonBytes, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return errs.Wrap(err)
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

func caPublicKeyFromPublicKey(pbPublicKey *common.PublicKey) (*caPublicKey, error) {
	publicKey, err := x509.ParsePKIXPublicKey(pbPublicKey.PkixBytes)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	var notAfter time.Time
	if pbPublicKey.NotAfter != 0 {
		notAfter = time.Unix(pbPublicKey.NotAfter, 0)
	}
	return &caPublicKey{
		PublicKey: pbPublicKey,
		publicKey: publicKey,
		notAfter:  notAfter,
	}, nil
}

func cloneBundle(bundle *common.Bundle) *common.Bundle {
	return proto.Clone(bundle).(*common.Bundle)
}

const keyIDAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func keyIDFromBytes(choices []byte) string {
	buf := new(bytes.Buffer)
	for _, choice := range choices {
		buf.WriteByte(keyIDAlphabet[int(choice)%len(keyIDAlphabet)])
	}
	return buf.String()
}

func newKeyID() (string, error) {
	choices := make([]byte, 32)
	_, err := rand.Read(choices)
	if err != nil {
		return "", err
	}
	return keyIDFromBytes(choices), nil
}

func buildCertChain(cert *x509.Certificate, candidates []*x509.Certificate) (chain []*x509.Certificate) {
	chain = append(chain, cert)
	for _, candidate := range candidates {
		if cert.CheckSignatureFrom(candidate) == nil {
			if !cert.Equal(candidate) {
				chain = append(chain, buildCertChain(candidate, candidates)...)
			}
			break
		}
	}
	return chain
}
