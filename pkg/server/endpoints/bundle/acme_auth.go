package bundle

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/version"
	"github.com/spiffe/spire/pkg/server/endpoints/bundle/internal/autocert"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
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

	// ToSAccepted is whether or not the terms of service have been accepted. If
	// not true, and the provider requires acceptance, then certificate
	// retrieval will fail.
	ToSAccepted bool
}

func ACMEAuth(log logrus.FieldLogger, km keymanager.KeyManager, config ACMEConfig) ServerAuth {
	// The acme client already defaulting to Let's Encrypt if the URL is unset
	// but we want it populated for logging purposes.
	if config.DirectoryURL == "" {
		config.DirectoryURL = acme.LetsEncryptURL
	}

	if !config.ToSAccepted {
		log.Warn("ACME Terms of Service have not been accepted. See the `tos_accepted` configurable")
	}

	return &acmeAuth{
		m: &autocert.Manager{
			Prompt: func(tosURL string) bool {
				tosLog := log.WithFields(logrus.Fields{
					"directory_url": config.DirectoryURL,
					"tos_url":       tosURL,
					"email":         config.Email,
				})
				if config.ToSAccepted {
					tosLog.Info("ACME Terms of Service accepted")
					return true
				}
				tosLog.Warn("ACME Terms of Service have not been accepted. See the `tos_accepted` configurable")
				return false
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
		return nil, autocert.ErrNoSuchKey
	}

	return ks.signer(keyID, resp.PublicKey)
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

	ks.log.WithField("id", id).Info("Generated new key")
	return ks.signer(keyID, resp.PublicKey)
}

func (ks *acmeKeyStore) signer(id string, kmPublicKey *keymanager.PublicKey) (crypto.Signer, error) {
	publicKey, err := x509.ParsePKIXPublicKey(kmPublicKey.PkixData)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return cryptoutil.NewKeyManagerSigner(ks.km, id, publicKey), nil
}
