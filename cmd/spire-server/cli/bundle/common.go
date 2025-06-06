package bundle

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/pkg/common/jwtutil"
)

const (
	headerFmt = `****************************************
* %s
****************************************
`
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

	return io.ReadAll(r)
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
		return fmt.Errorf("unable to parse certificates ASN.1 DER data: %w", err)
	}

	for _, cert := range certs {
		if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return err
		}
	}
	return nil
}

// printBundle marshals and prints the bundle using the provided writer
func printBundle(out io.Writer, bundle *types.Bundle) error {
	b, err := bundleFromProto(bundle)
	if err != nil {
		return err
	}

	docBytes, err := b.Marshal()
	if err != nil {
		return err
	}

	var o bytes.Buffer
	if err := json.Indent(&o, docBytes, "", "    "); err != nil {
		return err
	}

	_, err = fmt.Fprintln(out, o.String())
	return err
}

// bundleFromProto converts a bundle from the given *types.Bundle to *spiffebundle.Bundle
func bundleFromProto(bundleProto *types.Bundle) (*spiffebundle.Bundle, error) {
	td, err := spiffeid.TrustDomainFromString(bundleProto.TrustDomain)
	if err != nil {
		return nil, err
	}
	x509Authorities, err := x509CertificatesFromProto(bundleProto.X509Authorities)
	if err != nil {
		return nil, err
	}
	jwtAuthorities, err := jwtutil.JWTKeysFromProto(bundleProto.JwtAuthorities)
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

// x509CertificatesFromProto converts X.509 certificates from the given []*types.X509Certificate to []*x509.Certificate
func x509CertificatesFromProto(proto []*types.X509Certificate) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for i, auth := range proto {
		cert, err := x509.ParseCertificate(auth.Asn1)
		if err != nil {
			return nil, fmt.Errorf("unable to parse root CA %d: %w", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
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

	if format == util.FormatPEM {
		return printX509Authorities(out, bundle.X509Authorities)
	}

	return printBundle(out, bundle)
}

// validateFormat validates that the provided format is a valid format.
// If no format is provided, the default format is returned
func validateFormat(format string) (string, error) {
	if format == "" {
		format = util.FormatPEM
	}

	format = strings.ToLower(format)

	switch format {
	case util.FormatPEM:
	case util.FormatSPIFFE:
	default:
		return "", fmt.Errorf("invalid format: %q", format)
	}

	return format, nil
}
