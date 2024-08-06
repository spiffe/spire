package api

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
)

func BundleToProto(b *common.Bundle) (*types.Bundle, error) {
	if b == nil {
		return nil, errors.New("no bundle provided")
	}

	td, err := spiffeid.TrustDomainFromString(b.TrustDomainId)
	if err != nil {
		return nil, fmt.Errorf("invalid trust domain id: %w", err)
	}

	return &types.Bundle{
		TrustDomain:     td.Name(),
		RefreshHint:     b.RefreshHint,
		SequenceNumber:  b.SequenceNumber,
		X509Authorities: CertificatesToProto(b.RootCas),
		JwtAuthorities:  PublicKeysToProto(b.JwtSigningKeys),
	}, nil
}

func CertificatesToProto(rootCas []*common.Certificate) []*types.X509Certificate {
	var x509Authorities []*types.X509Certificate
	for _, rootCA := range rootCas {
		x509Authorities = append(x509Authorities, &types.X509Certificate{
			Asn1:    rootCA.DerBytes,
			Tainted: rootCA.TaintedKey,
		})
	}

	return x509Authorities
}
func PublicKeysToProto(keys []*common.PublicKey) []*types.JWTKey {
	var jwtAuthorities []*types.JWTKey
	for _, key := range keys {
		jwtAuthorities = append(jwtAuthorities, &types.JWTKey{
			PublicKey: key.PkixBytes,
			KeyId:     key.Kid,
			ExpiresAt: key.NotAfter,
			Tainted:   key.TaintedKey,
		})
	}
	return jwtAuthorities
}

func ProtoToBundle(b *types.Bundle) (*common.Bundle, error) {
	if b == nil {
		return nil, errors.New("no bundle provided")
	}

	td, err := spiffeid.TrustDomainFromString(b.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("invalid trust domain: %w", err)
	}

	rootCas, err := ParseX509Authorities(b.X509Authorities)
	if err != nil {
		return nil, fmt.Errorf("unable to parse X.509 authority: %w", err)
	}

	jwtSigningKeys, err := ParseJWTAuthorities(b.JwtAuthorities)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JWT authority: %w", err)
	}

	commonBundle := &common.Bundle{
		TrustDomainId:  td.IDString(),
		RefreshHint:    b.RefreshHint,
		SequenceNumber: b.SequenceNumber,
		RootCas:        rootCas,
		JwtSigningKeys: jwtSigningKeys,
	}

	return commonBundle, nil
}

func ProtoToBundleMask(mask *types.BundleMask) *common.BundleMask {
	if mask == nil {
		return nil
	}

	return &common.BundleMask{
		JwtSigningKeys: mask.JwtAuthorities,
		RootCas:        mask.X509Authorities,
		RefreshHint:    mask.RefreshHint,
		SequenceNumber: mask.SequenceNumber,
	}
}

func ParseX509Authorities(certs []*types.X509Certificate) ([]*common.Certificate, error) {
	var rootCAs []*common.Certificate
	for _, rootCA := range certs {
		if _, err := x509.ParseCertificates(rootCA.Asn1); err != nil {
			return nil, err
		}

		rootCAs = append(rootCAs, &common.Certificate{
			DerBytes: rootCA.Asn1,
		})
	}

	return rootCAs, nil
}

func ParseJWTAuthorities(keys []*types.JWTKey) ([]*common.PublicKey, error) {
	var jwtKeys []*common.PublicKey
	for _, key := range keys {
		if _, err := x509.ParsePKIXPublicKey(key.PublicKey); err != nil {
			return nil, err
		}

		if key.KeyId == "" {
			return nil, errors.New("missing key ID")
		}

		jwtKeys = append(jwtKeys, &common.PublicKey{
			PkixBytes: key.PublicKey,
			Kid:       key.KeyId,
			NotAfter:  key.ExpiresAt,
		})
	}

	return jwtKeys, nil
}

func HashByte(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func FieldsFromBundleProto(proto *types.Bundle, inputMask *types.BundleMask) logrus.Fields {
	fields := logrus.Fields{
		telemetry.TrustDomainID: proto.TrustDomain,
	}

	if inputMask == nil || inputMask.RefreshHint {
		fields[telemetry.RefreshHint] = proto.RefreshHint
	}

	if inputMask == nil || inputMask.SequenceNumber {
		fields[telemetry.SequenceNumber] = proto.SequenceNumber
	}

	if inputMask == nil || inputMask.JwtAuthorities {
		for k, v := range FieldsFromJwtAuthoritiesProto(proto.JwtAuthorities) {
			fields[k] = v
		}
	}

	if inputMask == nil || inputMask.X509Authorities {
		for k, v := range FieldsFromX509AuthoritiesProto(proto.X509Authorities) {
			fields[k] = v
		}
	}
	return fields
}

func FieldsFromJwtAuthoritiesProto(jwtAuthorities []*types.JWTKey) logrus.Fields {
	fields := make(logrus.Fields, 3*len(jwtAuthorities))
	for i, jwtAuthority := range jwtAuthorities {
		fields[fmt.Sprintf("%s.%d", telemetry.JWTAuthorityExpiresAt, i)] = jwtAuthority.ExpiresAt
		fields[fmt.Sprintf("%s.%d", telemetry.JWTAuthorityKeyID, i)] = jwtAuthority.KeyId
		fields[fmt.Sprintf("%s.%d", telemetry.JWTAuthorityPublicKeySHA256, i)] = HashByte(jwtAuthority.PublicKey)
	}

	return fields
}

func FieldsFromX509AuthoritiesProto(x509Authorities []*types.X509Certificate) logrus.Fields {
	fields := make(logrus.Fields, len(x509Authorities))
	for i, x509Authority := range x509Authorities {
		fields[fmt.Sprintf("%s.%d", telemetry.X509AuthoritiesASN1SHA256, i)] = HashByte(x509Authority.Asn1)
	}

	return fields
}
