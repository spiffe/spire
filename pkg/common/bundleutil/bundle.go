package bundleutil

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/zeebo/errs"
	"google.golang.org/protobuf/proto"
)

type Bundle struct {
	b              *common.Bundle
	rootCAs        []*x509.Certificate
	jwtSigningKeys map[string]crypto.PublicKey
}

func New(trustDomainID string) *Bundle {
	return &Bundle{
		b: &common.Bundle{
			TrustDomainId: trustDomainID,
		},
		jwtSigningKeys: make(map[string]crypto.PublicKey),
	}
}

func ParseBundle(bundleBytes []byte) (*Bundle, error) {
	b := new(common.Bundle)
	if err := proto.Unmarshal(bundleBytes, b); err != nil {
		return nil, errs.New("unable to unmarshal bundle: %v", err)
	}
	return BundleFromProto(b)
}

func BundleFromProto(b *common.Bundle) (*Bundle, error) {
	rootCAs, err := RootCAsFromBundleProto(b)
	if err != nil {
		return nil, err
	}
	jwtSigningKeys, err := JWTSigningKeysFromBundleProto(b)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		b:              b,
		rootCAs:        rootCAs,
		jwtSigningKeys: jwtSigningKeys,
	}, nil
}

func BundleFromRootCA(trustDomainID string, rootCA *x509.Certificate) *Bundle {
	return bundleFromRootCAs(trustDomainID, rootCA)
}

func BundleFromRootCAs(trustDomainID string, rootCAs []*x509.Certificate) *Bundle {
	return bundleFromRootCAs(trustDomainID, rootCAs...)
}

func CommonBundleFromProto(b *types.Bundle) (*common.Bundle, error) {
	if b == nil {
		return nil, errors.New("no bundle provided")
	}

	td, err := spiffeid.TrustDomainFromString(b.TrustDomain)
	if err != nil {
		return nil, err
	}

	var rootCAs []*common.Certificate
	for _, rootCA := range b.X509Authorities {
		rootCAs = append(rootCAs, &common.Certificate{
			DerBytes: rootCA.Asn1,
		})
	}

	var jwtKeys []*common.PublicKey
	for _, key := range b.JwtAuthorities {
		if key.KeyId == "" {
			return nil, errors.New("missing key ID")
		}

		jwtKeys = append(jwtKeys, &common.PublicKey{
			PkixBytes: key.PublicKey,
			Kid:       key.KeyId,
			NotAfter:  key.ExpiresAt,
		})
	}

	return &common.Bundle{
		TrustDomainId:  td.IDString(),
		RefreshHint:    b.RefreshHint,
		RootCas:        rootCAs,
		JwtSigningKeys: jwtKeys,
	}, nil
}

func bundleFromRootCAs(trustDomainID string, rootCAs ...*x509.Certificate) *Bundle {
	b := New(trustDomainID)
	for _, rootCA := range rootCAs {
		b.AppendRootCA(rootCA)
	}
	return b
}

func (b *Bundle) Proto() *common.Bundle {
	return cloneBundle(b.b)
}

func (b *Bundle) TrustDomainID() string {
	return b.b.TrustDomainId
}

func (b *Bundle) EqualTo(other *Bundle) bool {
	return proto.Equal(b.b, other.b)
}

func (b *Bundle) RootCAs() []*x509.Certificate {
	return b.rootCAs
}

func (b *Bundle) JWTSigningKeys() map[string]crypto.PublicKey {
	return b.jwtSigningKeys
}

// RefreshHint returns the bundle refresh hint.
func (b *Bundle) RefreshHint() time.Duration {
	return time.Second * time.Duration(b.b.RefreshHint)
}

// SetRefreshHint sets the bundle refresh hint to the given duration. It is
// rounded up to the nearest second.
func (b *Bundle) SetRefreshHint(d time.Duration) {
	b.b.RefreshHint = int64((d + (time.Second - 1)) / time.Second)
}

func (b *Bundle) AppendRootCA(rootCA *x509.Certificate) {
	b.b.RootCas = append(b.b.RootCas, &common.Certificate{
		DerBytes: rootCA.Raw,
	})
	b.rootCAs = append(b.rootCAs, rootCA)
}

func (b *Bundle) AppendJWTSigningKey(kid string, key crypto.PublicKey) error {
	if _, ok := b.jwtSigningKeys[kid]; ok {
		return errs.New("JWT Signing Key %q already exists", kid)
	}
	pkixBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return errs.Wrap(err)
	}
	b.b.JwtSigningKeys = append(b.b.JwtSigningKeys, &common.PublicKey{
		Kid:       kid,
		PkixBytes: pkixBytes,
	})
	b.jwtSigningKeys[kid] = key
	return nil
}

func BundleProtoFromRootCADER(trustDomainID string, derBytes []byte) *common.Bundle {
	return &common.Bundle{
		TrustDomainId: trustDomainID,
		RootCas:       []*common.Certificate{{DerBytes: derBytes}},
	}
}

func BundleProtoFromRootCAsDER(trustDomainID string, derBytes []byte) (*common.Bundle, error) {
	rootCAs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return BundleProtoFromRootCAs(trustDomainID, rootCAs), nil
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

func RootCAsDERFromBundleProto(b *common.Bundle) (derBytes []byte) {
	for _, rootCA := range b.RootCas {
		derBytes = append(derBytes, rootCA.DerBytes...)
	}
	return derBytes
}

func RootCAsFromBundleProto(b *common.Bundle) (out []*x509.Certificate, err error) {
	for i, rootCA := range b.RootCas {
		cert, err := x509.ParseCertificate(rootCA.DerBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse root CA %d: %v", i, err)
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
			return nil, fmt.Errorf("unable to parse JWT signing key %d: %v", i, err)
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
// It returns an error if prunning results in a bundle with no CAs or keys
func PruneBundle(bundle *common.Bundle, expiration time.Time, log hclog.Logger) (*common.Bundle, bool, error) {
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
			return nil, false, fmt.Errorf("cannot parse certificates: %v", err)
		}
		// if any cert in the chain has expired, throw the whole chain out
		for _, cert := range certs {
			if !cert.NotAfter.After(expiration) {
				log.Info("Pruning CA certificate due to expiration", telemetry.SerialNumber, cert.SerialNumber, telemetry.Expiration, cert.NotAfter)
				changed = true
				continue pruneRootCA
			}
		}
		newBundle.RootCas = append(newBundle.RootCas, rootCA)
	}

	for _, jwtSigningKey := range bundle.JwtSigningKeys {
		notAfter := time.Unix(jwtSigningKey.NotAfter, 0)
		if !notAfter.After(expiration) {
			log.Info("Pruning JWT signing key due to expiration", telemetry.Kid, jwtSigningKey.Kid, telemetry.Expiration, notAfter)
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

func cloneBundle(b *common.Bundle) *common.Bundle {
	return proto.Clone(b).(*common.Bundle)
}
