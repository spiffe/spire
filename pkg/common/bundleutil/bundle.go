package bundleutil

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/protobuf/proto"
)

func CommonBundleFromProto(b *types.Bundle) (*common.Bundle, error) {
	if b == nil {
		return nil, errors.New("no bundle provided")
	}

	td, err := spiffeid.TrustDomainFromString(b.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("bundle has an invalid trust domain %q: %w", b.TrustDomain, err)
	}

	var rootCAs []*common.Certificate
	for _, rootCA := range b.X509Authorities {
		rootCAs = append(rootCAs, &common.Certificate{
			DerBytes:   rootCA.Asn1,
			TaintedKey: rootCA.Tainted,
		})
	}

	var jwtKeys []*common.PublicKey
	for _, key := range b.JwtAuthorities {
		if key.KeyId == "" {
			return nil, errors.New("missing key ID")
		}

		jwtKeys = append(jwtKeys, &common.PublicKey{
			PkixBytes:  key.PublicKey,
			Kid:        key.KeyId,
			NotAfter:   key.ExpiresAt,
			TaintedKey: key.Tainted,
		})
	}

	return &common.Bundle{
		TrustDomainId:  td.IDString(),
		RefreshHint:    b.RefreshHint,
		SequenceNumber: b.SequenceNumber,
		RootCas:        rootCAs,
		JwtSigningKeys: jwtKeys,
	}, nil
}

func SPIFFEBundleToProto(b *spiffebundle.Bundle) (*common.Bundle, error) {
	refreshHint, _ := b.RefreshHint()
	s, _ := b.SequenceNumber()

	bundle := &common.Bundle{
		TrustDomainId:  b.TrustDomain().IDString(),
		RefreshHint:    int64(refreshHint.Seconds()),
		SequenceNumber: s,
	}
	for _, rootCA := range b.X509Authorities() {
		bundle.RootCas = append(bundle.RootCas, &common.Certificate{
			DerBytes: rootCA.Raw,
		})
	}

	for kid, key := range b.JWTAuthorities() {
		pkixBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %w", err)
		}
		bundle.JwtSigningKeys = append(bundle.JwtSigningKeys, &common.PublicKey{
			PkixBytes: pkixBytes,
			Kid:       kid,
		})
	}

	return bundle, nil
}

func SPIFFEBundleFromProto(b *common.Bundle) (*spiffebundle.Bundle, error) {
	rootCAs, err := RootCAsFromBundleProto(b)
	if err != nil {
		return nil, err
	}
	jwtSigningKeys, err := JWTSigningKeysFromBundleProto(b)
	if err != nil {
		return nil, err
	}
	td, err := spiffeid.TrustDomainFromString(b.TrustDomainId)
	if err != nil {
		return nil, err
	}

	bundle := spiffebundle.New(td)
	bundle.SetX509Authorities(rootCAs)
	bundle.SetJWTAuthorities(jwtSigningKeys)
	bundle.SetRefreshHint(time.Second * time.Duration(b.RefreshHint))
	bundle.SetSequenceNumber(b.SequenceNumber)

	return bundle, nil
}

func BundleProtoFromRootCA(trustDomainID string, rootCA *x509.Certificate) *common.Bundle {
	return BundleProtoFromRootCAs(trustDomainID, []*x509.Certificate{rootCA})
}

func BundleProtoFromRootCAs(trustDomainID string, rootCAs []*x509.Certificate) *common.Bundle {
	b := &common.Bundle{
		TrustDomainId: trustDomainID,
	}
	for _, rootCA := range rootCAs {
		b.RootCas = append(b.RootCas, &common.Certificate{
			DerBytes: rootCA.Raw,
		})
	}
	return b
}

func RootCAsFromBundleProto(b *common.Bundle) (out []*x509.Certificate, err error) {
	for i, rootCA := range b.RootCas {
		cert, err := x509.ParseCertificate(rootCA.DerBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse root CA %d: %w", i, err)
		}
		out = append(out, cert)
	}
	return out, nil
}

func JWTSigningKeysFromBundleProto(b *common.Bundle) (map[string]crypto.PublicKey, error) {
	out := make(map[string]crypto.PublicKey)
	for i, publicKey := range b.JwtSigningKeys {
		jwtSigningKey, err := x509.ParsePKIXPublicKey(publicKey.PkixBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse JWT signing key %d: %w", i, err)
		}
		out[publicKey.Kid] = jwtSigningKey
	}
	return out, nil
}

func MergeBundles(a, b *common.Bundle) (*common.Bundle, bool) {
	c := cloneBundle(a)

	rootCAs := make(map[string]bool)
	for _, rootCA := range a.RootCas {
		rootCAs[rootCA.String()] = true
	}
	jwtSigningKeys := make(map[string]bool)
	for _, jwtSigningKey := range a.JwtSigningKeys {
		jwtSigningKeys[jwtSigningKey.String()] = true
	}

	var changed bool
	for _, rootCA := range b.RootCas {
		if !rootCAs[rootCA.String()] {
			c.RootCas = append(c.RootCas, rootCA)
			changed = true
		}
	}
	for _, jwtSigningKey := range b.JwtSigningKeys {
		if !jwtSigningKeys[jwtSigningKey.String()] {
			c.JwtSigningKeys = append(c.JwtSigningKeys, jwtSigningKey)
			changed = true
		}
	}
	return c, changed
}

// PruneBundle removes the bundle RootCAs and JWT keys that expired before a given time
// It returns an error if pruning results in a bundle with no CAs or keys
func PruneBundle(bundle *common.Bundle, expiration time.Time, log logrus.FieldLogger) (*common.Bundle, bool, error) {
	if bundle == nil {
		return nil, false, errors.New("current bundle is nil")
	}

	// Zero value is a valid time, but probably unintended
	if expiration.IsZero() {
		return nil, false, errors.New("expiration time is zero value")
	}

	// Creates new bundle with non expired certs only
	newBundle := &common.Bundle{
		TrustDomainId: bundle.TrustDomainId,
	}
	changed := false
pruneRootCA:
	for _, rootCA := range bundle.RootCas {
		certs, err := x509.ParseCertificates(rootCA.DerBytes)
		if err != nil {
			return nil, false, fmt.Errorf("cannot parse certificates: %w", err)
		}
		// if any cert in the chain has expired, throw the whole chain out
		for _, cert := range certs {
			if !cert.NotAfter.After(expiration) {
				log.WithFields(logrus.Fields{
					telemetry.SerialNumber: cert.SerialNumber,
					telemetry.Expiration:   cert.NotAfter,
				}).Info("Pruning CA certificate due to expiration")
				changed = true
				continue pruneRootCA
			}
		}
		newBundle.RootCas = append(newBundle.RootCas, rootCA)
	}

	for _, jwtSigningKey := range bundle.JwtSigningKeys {
		notAfter := time.Unix(jwtSigningKey.NotAfter, 0)
		if !notAfter.After(expiration) {
			log.WithFields(logrus.Fields{
				telemetry.Kid:        jwtSigningKey.Kid,
				telemetry.Expiration: notAfter,
			}).Info("Pruning JWT signing key due to expiration")
			changed = true
			continue
		}
		newBundle.JwtSigningKeys = append(newBundle.JwtSigningKeys, jwtSigningKey)
	}

	if len(newBundle.RootCas) == 0 {
		log.Warn("Pruning halted; all known CA certificates have expired")
		return nil, false, errors.New("would prune all certificates")
	}

	if len(newBundle.JwtSigningKeys) == 0 {
		log.Warn("Pruning halted; all known JWT signing keys have expired")
		return nil, false, errors.New("would prune all JWT signing keys")
	}

	return newBundle, changed, nil
}

// FindX509Authorities search for all X.509 authorities with provided subjectKeyIDs
func FindX509Authorities(bundle *spiffebundle.Bundle, subjectKeyIDs []string) ([]*x509.Certificate, error) {
	var x509Authorities []*x509.Certificate
	for _, subjectKeyID := range subjectKeyIDs {
		x509Authority, err := getX509Authority(bundle, subjectKeyID)
		if err != nil {
			return nil, err
		}

		x509Authorities = append(x509Authorities, x509Authority)
	}

	return x509Authorities, nil
}

func getX509Authority(bundle *spiffebundle.Bundle, subjectKeyID string) (*x509.Certificate, error) {
	for _, x509Authority := range bundle.X509Authorities() {
		authoritySKID := x509util.SubjectKeyIDToString(x509Authority.SubjectKeyId)
		if authoritySKID == subjectKeyID {
			return x509Authority, nil
		}
	}

	return nil, fmt.Errorf("no X.509 authority found with SubjectKeyID %q", subjectKeyID)
}

func cloneBundle(b *common.Bundle) *common.Bundle {
	return proto.Clone(b).(*common.Bundle)
}
