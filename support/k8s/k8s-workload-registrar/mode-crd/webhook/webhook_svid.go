// Package webhook manages the SVID creation and rotation for the k8s-workload-registrar webhook
package webhook

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	spiretypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
)

const (
	certDirMode   = os.FileMode(0o700)
	certsFileName = "tls.crt"
	keyFileName   = "tls.key"
)

type SVIDConfig struct {
	Cluster            string
	Log                logrus.FieldLogger
	Namespace          string
	S                  svidv1.SVIDClient
	TrustDomain        spiffeid.TrustDomain
	WebhookCertDir     string
	WebhookServiceName string
}

type SVID struct {
	c            SVIDConfig
	certHalfLife time.Time
	id           spiffeid.ID
	notAfter     time.Time
}

// NewSVID creates a new SVID struct and creates the SPIFFE ID that will be used
func NewSVID(ctx context.Context, config SVIDConfig) (*SVID, error) {
	err := os.MkdirAll(config.WebhookCertDir, certDirMode)
	if err != nil {
		return nil, err
	}

	id, err := spiffeid.FromSegments(config.TrustDomain, "k8s-workload-registrar", config.Cluster, "webhook")
	if err != nil {
		return nil, fmt.Errorf("unable to generate SPIFFE ID: %w", err)
	}

	return &SVID{
		c:  config,
		id: id,
	}, nil
}

// MintSVID requests the SPIRE Server to mint a new SVID for the webhook
func (e *SVID) MintSVID(ctx context.Context, key crypto.Signer) (err error) {
	e.c.Log.Info("Minting new SVID for webhook")
	// Generate key if not passed in
	if key == nil {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("unable to generate Key: %w", err)
		}
	}

	// Generate Certificate Signing Request
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		URIs: []*url.URL{e.id.URL()},
		DNSNames: []string{
			e.c.WebhookServiceName + "." + e.c.Namespace + ".svc",
		},
	}, key)
	if err != nil {
		return fmt.Errorf("unable to generate CSR: %w", err)
	}

	// Mint new SVID
	var resp *svidv1.MintX509SVIDResponse
	backoff := wait.Backoff{
		Steps:    8,
		Duration: 10 * time.Millisecond,
		Factor:   2.0,
		Jitter:   0.1,
	}
	err = retry.OnError(backoff, e.mintSVIDRetry, func() (err error) {
		resp, err = e.c.S.MintX509SVID(ctx, &svidv1.MintX509SVIDRequest{
			Csr: csr,
		})
		if err != nil {
			return fmt.Errorf("unable to make Mint SVID Request: %w", err)
		}

		// This check is purely defensive.
		if len(resp.Svid.CertChain) == 0 {
			return errors.New("no certificates in Mint SVID Response")
		}

		return nil
	})
	if err != nil {
		return err
	}
	e.c.Log.Info("Successfully minted new SVID for webhook")

	// Parse leaf certificate and calculate half life
	leafCert, err := x509.ParseCertificate(resp.Svid.CertChain[0])
	if err != nil {
		return fmt.Errorf("unable to parse leaf certificate: %w", err)
	}
	e.certHalfLife = certHalfLife(leafCert)
	e.notAfter = leafCert.NotAfter

	// Write SVID and key to disk
	return e.dumpSVID(resp.Svid, key)
}

// SVIDRotator requests a new certificate when half of its lifetime is left
func (e *SVID) SVIDRotator(ctx context.Context) error {
	for {
		ttl := time.Until(e.certHalfLife)
		select {
		case <-time.After(ttl):
			if err := e.MintSVID(ctx, nil); err != nil {
				return fmt.Errorf("unable to mint SVID: %w", err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// mintSVIDRetry tests if the MintX509SVID request should be retried on error or not
func (e *SVID) mintSVIDRetry(err error) bool {
	// Certificate has expired, webhook is no longer functional. Restart and retry.
	if !e.notAfter.IsZero() && time.Now().After(e.notAfter) {
		return false
	}

	e.c.Log.Debug("Unable to contact SPIRE Server to mint webhook SVID, retrying...")
	return true
}

// dumpBundles takes a X509SVIDResponse, representing a svid message from the SPIRE Server
// and write the certs to disk
func (e *SVID) dumpSVID(svid *spiretypes.X509SVID, key crypto.Signer) error {
	// Convert certificates to PEM
	svidPEM := new(bytes.Buffer)
	for _, certDER := range svid.CertChain {
		_ = pem.Encode(svidPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})
	}

	// Convert key to PEM
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := new(bytes.Buffer)
	_ = pem.Encode(keyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	// Write certificates to disk
	certsFileName := path.Join(e.c.WebhookCertDir, certsFileName)
	if err := diskutil.WritePubliclyReadableFile(certsFileName, svidPEM.Bytes()); err != nil {
		return err
	}

	// Write key to disk
	keyFileName := path.Join(e.c.WebhookCertDir, keyFileName)
	return diskutil.WritePrivateFile(keyFileName, keyPEM.Bytes())
}

func certHalfLife(cert *x509.Certificate) time.Time {
	return cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2)
}
