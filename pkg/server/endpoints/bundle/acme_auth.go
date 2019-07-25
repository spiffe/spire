package bundle

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"math/big"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/version"
	"github.com/spiffe/spire/pkg/server/endpoints/bundle/internal/autocert"
	"github.com/spiffe/spire/proto/spire/server/keymanager"
	"github.com/zeebo/errs"
	"golang.org/x/crypto/acme"
)

const (
	acmeKeyPrefix = "bundle-acme-"
)

// ACMECache implements a cache for the autocert manager. It makes some
// simplifying assumptions based on our usage for the bundle endpoint. Namely,
// it assumes there is going to be a single cache entry, since we only support
// a single domain. It assumes PEM encoded blocks of data and strips out the
// private key to be stored in the key manager instead of on disk with the rest
// of the data.
type ACMEConfig struct {
	// DirectoryURL is the ACME directory URL
	DirectoryURL string

	// DomainName is the domain name of the certificate to obtain.
	DomainName string

	// CacheDir is the directory on disk where we cache certificates.
	CacheDir string

	// Email is the email address of the account to register with ACME
	Email string
}

func ACMEAuth(log logrus.FieldLogger, km keymanager.KeyManager, config ACMEConfig) ServerAuth {
	// The acme client already defaulting to Let's Encrypt if the URL is unset
	// but we want it populated for logging purposes.
	if config.DirectoryURL == "" {
		config.DirectoryURL = acme.LetsEncryptURL
	}

	return &acmeAuth{
		m: &autocert.Manager{
			Prompt: func(tosURL string) bool {
				log.WithFields(logrus.Fields{
					"directory_url": config.DirectoryURL,
					"tos_url":       tosURL,
					"email":         config.Email,
				}).Info("ACME Terms of Service accepted")
				return true
			},
			Email:      config.Email,
			Cache:      autocert.DirCache(config.CacheDir),
			HostPolicy: autocert.HostWhitelist(config.DomainName),
			Client: &acme.Client{
				DirectoryURL: config.DirectoryURL,
				UserAgent:    "SPIRE-" + version.Version(),
			},
			KeyStore: &acmeKeyStore{
				log: log,
				km:  km,
			},
		},
	}
}

type acmeAuth struct {
	m *autocert.Manager
}

func (a *acmeAuth) GetTLSConfig() *tls.Config {
	return a.m.TLSConfig()
}

type acmeKeyStore struct {
	log logrus.FieldLogger
	km  keymanager.KeyManager
}

func (ks *acmeKeyStore) GetPrivateKey(ctx context.Context, id string) (crypto.Signer, error) {
	keyID := acmeKeyPrefix + id

	resp, err := ks.km.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: keyID,
	})
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if resp.PublicKey == nil {
		return nil, nil
	}

	signer, err := ks.signer(keyID, resp.PublicKey)
	if err != nil {
		return nil, err
	}

	if isACMEAccountKey(id) {
		// The account key is used to sign JWT tokens and needs to sign things
		// differently. Unfortunately, github.com/x/crypto/acme does not
		// properly handle crypto.Signers that aren't of type *ecdsa.PrivateKey
		// so we have to wrap it here.
		signer = jwtSigner{Signer: signer}
	}
	return signer, nil
}

func (ks *acmeKeyStore) NewPrivateKey(ctx context.Context, id string, keyType autocert.KeyType) (crypto.Signer, error) {
	keyID := acmeKeyPrefix + id

	var kmKeyType keymanager.KeyType
	switch keyType {
	case autocert.RSA2048:
		kmKeyType = keymanager.KeyType_RSA_2048
	case autocert.EC256:
		kmKeyType = keymanager.KeyType_EC_P256
	default:
		return nil, errs.New("unsupported key type: %d", keyType)
	}

	resp, err := ks.km.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   keyID,
		KeyType: kmKeyType,
	})
	if err != nil {
		return nil, errs.Wrap(err)
	}

	ks.log.Info("Generated new key for ACME %q", id)
	return ks.signer(keyID, resp.PublicKey)
}

func (ks *acmeKeyStore) signer(id string, kmPublicKey *keymanager.PublicKey) (crypto.Signer, error) {
	publicKey, err := x509.ParsePKIXPublicKey(kmPublicKey.PkixData)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return cryptoutil.NewKeyManagerSigner(ks.km, id, publicKey), nil
}

func isACMEAccountKey(id string) bool {
	return id == "acme_account+key"
}

// jwtSigner adapts a keymanager signer to one that does ECDSA signatures as
// specified by RFC7518.
type jwtSigner struct {
	crypto.Signer
}

func (js jwtSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	sigBytes, err := js.Signer.Sign(rand, digest, opts)
	if err != nil {
		return nil, err
	}

	// not an ECDSA signature? move on.
	publicKey, ok := js.Signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return sigBytes, nil
	}

	// decode R and S
	sigASN1 := struct {
		R, S *big.Int
	}{}
	if _, err := asn1.Unmarshal(sigBytes, &sigASN1); err != nil {
		return nil, err
	}

	r, s := sigASN1.R, sigASN1.S
	rb, sb := r.Bytes(), s.Bytes()
	size := publicKey.Params().BitSize / 8
	if size%8 > 0 {
		size++
	}
	sig := make([]byte, size*2)
	copy(sig[size-len(rb):], rb)
	copy(sig[size*2-len(sb):], sb)
	return sig, nil
}
