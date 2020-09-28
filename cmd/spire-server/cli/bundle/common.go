package bundle

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/zeebo/errs"
)

const (
	headerFmt = `****************************************
* %s
****************************************
`
	formatPEM    = "pem"
	formatSPIFFE = "spiffe"
)

// loadParamData loads the data from a parameter. If the parameter is empty then
// data is ready from "in", otherwise the parameter is used as a filename to
// read file contents.
func loadParamData(in io.Reader, fn string) ([]byte, error) {
	r := in
	if fn != "" {
		f, err := os.Open(fn)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	return ioutil.ReadAll(r)
}

// printX509Authorities print provided certificates into writer
func printX509Authorities(out io.Writer, certs []*types.X509Certificate) error {
	for _, cert := range certs {
		if err := printCACertsPEM(out, cert.Asn1); err != nil {
			return err
		}
	}
	return nil
}

// printCACertsPEM encodes DER certificates to PEM format and print using writer
func printCACertsPEM(out io.Writer, caCerts []byte) error {
	certs, err := x509.ParseCertificates(caCerts)
	if err != nil {
		return fmt.Errorf("unable to parse certificates ASN.1 DER data: %v", err)
	}

	for _, cert := range certs {
		if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return err
		}
	}
	return nil
}

// printBundle marshal bundle and print using provided writer
func printBundle(out io.Writer, bundle *types.Bundle) error {
	b, err := bundleFromProto(bundle)
	if err != nil {
		return err
	}

	docBytes, err := b.Marshal()
	if err != nil {
		return errs.Wrap(err)
	}

	var o bytes.Buffer
	if err := json.Indent(&o, docBytes, "", "    "); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(out, o.String()); err != nil {
		return errs.Wrap(err)
	}

	return nil
}

// bundleFromProto parse types bundle into spiffe bundle
func bundleFromProto(bundleProto *types.Bundle) (*spiffebundle.Bundle, error) {
	td, err := spiffeid.TrustDomainFromString(bundleProto.TrustDomain)
	if err != nil {
		return nil, err
	}
	x509Authorities, err := x509CertificatesFromProto(bundleProto.X509Authorities)
	if err != nil {
		return nil, err
	}
	jwtAuthorities, err := jwtKeysFromProto(bundleProto.JwtAuthorities)
	if err != nil {
		return nil, err
	}
	bundle := spiffebundle.New(td)
	bundle.SetX509Authorities(x509Authorities)
	bundle.SetJWTAuthorities(jwtAuthorities)
	if bundleProto.RefreshHint > 0 {
		bundle.SetRefreshHint(time.Duration(bundleProto.RefreshHint) * time.Second)
	}
	if bundleProto.SequenceNumber > 0 {
		bundle.SetSequenceNumber(bundleProto.SequenceNumber)
	}
	return bundle, nil
}

// x509CertificatesFromProto parse proto certificates to x509 certificates
func x509CertificatesFromProto(proto []*types.X509Certificate) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for i, auth := range proto {
		cert, err := x509.ParseCertificate(auth.Asn1)
		if err != nil {
			return nil, fmt.Errorf("unable to parse root CA %d: %v", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// jwtKeysFromProto parse proto JWTKeys to PublicKey mapped by key ID
func jwtKeysFromProto(proto []*types.JWTKey) (map[string]crypto.PublicKey, error) {
	keys := make(map[string]crypto.PublicKey)
	for i, publicKey := range proto {
		jwtSigningKey, err := x509.ParsePKIXPublicKey(publicKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("unable to parse JWT signing key %d: %v", i, err)
		}
		keys[publicKey.KeyId] = jwtSigningKey
	}
	return keys, nil
}

func bundleProtoFromX509Authorities(trustDomain string, rootCAs []*x509.Certificate) *types.Bundle {
	b := &types.Bundle{
		TrustDomain: trustDomain,
	}
	for _, rootCA := range rootCAs {
		b.X509Authorities = append(b.X509Authorities, &types.X509Certificate{
			Asn1: rootCA.Raw,
		})
	}
	return b
}

// protoFromSpiffeBundle parse spiffe bundle to proto
func protoFromSpiffeBundle(bundle *spiffebundle.Bundle) (*types.Bundle, error) {
	resp := &types.Bundle{
		TrustDomain:     bundle.TrustDomain().String(),
		X509Authorities: protoFromX509Certificates(bundle.X509Authorities()),
	}

	jwtAuthorities, err := protoFromJwtKeys(bundle.JWTAuthorities())
	if err != nil {
		return nil, err
	}
	resp.JwtAuthorities = jwtAuthorities

	if r, ok := bundle.RefreshHint(); ok {
		resp.RefreshHint = int64(r.Seconds())
	}

	if s, ok := bundle.SequenceNumber(); ok {
		resp.SequenceNumber = s
	}

	return resp, nil
}

// protoFromX509Certificates parse x509 certificates to proto
func protoFromX509Certificates(certs []*x509.Certificate) []*types.X509Certificate {
	var resp []*types.X509Certificate
	for _, cert := range certs {
		resp = append(resp, &types.X509Certificate{
			Asn1: cert.Raw,
		})
	}

	return resp
}

// protoFromJwtKeys parse Public Keys to proto
func protoFromJwtKeys(keys map[string]crypto.PublicKey) ([]*types.JWTKey, error) {
	var resp []*types.JWTKey

	for kid, key := range keys {
		pkixBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}
		resp = append(resp, &types.JWTKey{
			PublicKey: pkixBytes,
			KeyId:     kid,
		})
	}

	return resp, nil
}

func printBundleWithFormat(out io.Writer, bundle *types.Bundle, format string, header bool) error {
	if bundle == nil {
		return errors.New("no bundle provided")
	}

	format, err := validateFormat(format)
	if err != nil {
		return err
	}

	if header {
		if _, err := fmt.Fprintf(out, headerFmt, bundle.TrustDomain); err != nil {
			return err
		}
	}

	if format == formatPEM {
		return printX509Authorities(out, bundle.X509Authorities)
	}

	return printBundle(out, bundle)
}

// validateFormat validates that the provided format is a valid format.
// If no format is provided, the default format is returned
func validateFormat(format string) (string, error) {
	if format == "" {
		format = formatPEM
	}

	format = strings.ToLower(format)

	switch format {
	case formatPEM:
	case formatSPIFFE:
	default:
		return "", fmt.Errorf("invalid format: %q", format)
	}

	return format, nil
}
