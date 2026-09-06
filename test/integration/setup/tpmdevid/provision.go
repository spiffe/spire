// Provisions a software TPM (swtpm) with the credentials the tpm_devid
// nodeattestor expects, and writes them where the agent and server configs
// point.
//
// It mirrors what test/tpmsimulator does for the unit tests, but drives a real
// TPM over a socket instead of an in-process simulator, so the integration
// suite exercises the same code path an operator would. The templates and the
// NV index are taken from SPIRE itself rather than restated here: the agent
// regenerates the endorsement key from client.DefaultEKTemplateRSA() and reads
// its certificate from tpmutil.EKCertificateHandleRSA at attestation time, so
// anything provisioned under different parameters would fail to attest.
//
// Usage:
//
//	go run provision.go -tpm-socket <path> -agent-dir <dir> -server-dir <dir>
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/tpmdevid/tpmutil"
)

// The "never expires" timestamp from RFC 5280.
var neverExpires = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// DevID key template attributes according to "TPM 2.0 Keys for device identity
// and attestation", section 7.3.4.1.
const devIDKeyAttributes = tpm2.FlagSign |
	tpm2.FlagFixedTPM |
	tpm2.FlagFixedParent |
	tpm2.FlagSensitiveDataOrigin |
	tpm2.FlagUserWithAuth

func main() {
	socket := flag.String("tpm-socket", "", "path to the swtpm unix socket")
	agentDir := flag.String("agent-dir", "", "directory to write the agent DevID credentials into")
	serverDir := flag.String("server-dir", "", "directory to write the server CA bundles into")
	flag.Parse()

	if *socket == "" || *agentDir == "" || *serverDir == "" {
		flag.Usage()
		os.Exit(1)
	}

	if err := provision(*socket, *agentDir, *serverDir); err != nil {
		log.Fatalf("provisioning failed: %v", err)
	}
}

func provision(socket, agentDir, serverDir string) error {
	// Open the TPM the same way the plugin does. On a socket this yields the
	// emulator transport that reconnects per command, which is what swtpm
	// serves. Going through the plugin's wrapper rather than calling go-tpm
	// directly also keeps this building on Windows, where OpenTPM takes no path.
	rwc, err := tpmutil.OpenTPM(socket)
	if err != nil {
		return fmt.Errorf("cannot open TPM at %q: %w", socket, err)
	}
	defer rwc.Close()

	endorsementCA, err := provisionEndorsementCertificate(rwc)
	if err != nil {
		return fmt.Errorf("cannot provision endorsement certificate: %w", err)
	}

	devIDCA, devIDCert, privateBlob, publicBlob, err := provisionDevID(rwc)
	if err != nil {
		return fmt.Errorf("cannot provision DevID: %w", err)
	}

	if err := writeFiles(agentDir, map[string][]byte{
		"devid.crt.pem":   certsToPEM(devIDCert),
		"devid.priv.blob": privateBlob,
		"devid.pub.blob":  publicBlob,
	}); err != nil {
		return err
	}

	return writeFiles(serverDir, map[string][]byte{
		"devid-ca.pem":       certsToPEM(devIDCA),
		"endorsement-ca.pem": certsToPEM(endorsementCA),
	})
}

// provisionEndorsementCertificate regenerates the endorsement key exactly as
// the agent will, certifies it with a throwaway "manufacturer" root, and stores
// the certificate in the NV index the agent reads. Returns the root so the
// server can be configured to trust it.
func provisionEndorsementCertificate(rwc io.ReadWriter) (*x509.Certificate, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("cannot generate endorsement root key: %w", err)
	}

	root, err := createRootCertificate(rootKey, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "endorsement-root"},
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotAfter:              neverExpires,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot create endorsement root certificate: %w", err)
	}

	ekHandle, ekPublicBlob, _, _, _, _, err := tpm2.CreatePrimaryEx(rwc, tpm2.HandleEndorsement,
		tpm2.PCRSelection{}, "", "", client.DefaultEKTemplateRSA())
	if err != nil {
		return nil, fmt.Errorf("cannot create endorsement key: %w", err)
	}
	defer func() {
		if err := tpm2.FlushContext(rwc, ekHandle); err != nil {
			log.Printf("warning: cannot flush endorsement key handle: %v", err)
		}
	}()

	ekPublicKey, err := publicKeyFromBlob(ekPublicBlob)
	if err != nil {
		return nil, fmt.Errorf("cannot get endorsement public key: %w", err)
	}

	ekCert, err := createCertificate(ekPublicKey, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "endorsement-certificate"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotAfter:     neverExpires,
	}, rootKey, root)
	if err != nil {
		return nil, fmt.Errorf("cannot create endorsement certificate: %w", err)
	}

	if err := storeEndorsementCertificate(rwc, ekCert.Raw); err != nil {
		return nil, err
	}

	return root, nil
}

// storeEndorsementCertificate writes the certificate to the NV index the agent
// reads it back from.
func storeEndorsementCertificate(rwc io.ReadWriter, ekCert []byte) error {
	// Undefine first so the provisioner can be run more than once against the
	// same TPM state without failing on an already-defined index.
	_ = tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.EKCertificateHandleRSA)

	err := tpm2.NVDefineSpace(rwc,
		tpm2.HandlePlatform,
		tpmutil.EKCertificateHandleRSA,
		"",
		"",
		nil,
		tpm2.AttrPlatformCreate|tpm2.AttrPPWrite|tpm2.AttrPPRead|tpm2.AttrAuthWrite|tpm2.AttrAuthRead,
		uint16(len(ekCert)))
	if err != nil {
		return fmt.Errorf("cannot define NV space at %08x: %w", tpmutil.EKCertificateHandleRSA, err)
	}

	if err := tpm2.NVWrite(rwc, tpm2.HandlePlatform, tpmutil.EKCertificateHandleRSA, "", ekCert, 0); err != nil {
		return fmt.Errorf("cannot write endorsement certificate to NV: %w", err)
	}

	return nil
}

// provisionDevID creates a DevID key under a storage root key built from the
// same template the agent loads it with, and certifies it with a throwaway
// provisioning CA. Returns the CA root, the leaf, and the TPM key blobs.
func provisionDevID(rwc io.ReadWriter) (*x509.Certificate, *x509.Certificate, []byte, []byte, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot generate DevID root key: %w", err)
	}

	root, err := createRootCertificate(rootKey, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "devid-root"},
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotAfter:              neverExpires,
	})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot create DevID root certificate: %w", err)
	}

	srkHandle, _, _, _, _, _, err := tpm2.CreatePrimaryEx(rwc, tpm2.HandleOwner,
		tpm2.PCRSelection{}, "", "", tpmutil.SRKTemplateHighRSA())
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot create storage root key: %w", err)
	}
	defer func() {
		if err := tpm2.FlushContext(rwc, srkHandle); err != nil {
			log.Printf("warning: cannot flush storage root key handle: %v", err)
		}
	}()

	devIDTemplate := client.AKTemplateRSA()
	devIDTemplate.Attributes = devIDKeyAttributes

	privateBlob, publicBlob, _, _, _, err := tpm2.CreateKey(rwc, srkHandle,
		tpm2.PCRSelection{}, "", "", devIDTemplate)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot create DevID key: %w", err)
	}

	devIDPublicKey, err := publicKeyFromBlob(publicBlob)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot get DevID public key: %w", err)
	}

	leaf, err := createCertificate(devIDPublicKey, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "devid-leaf"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotAfter:     neverExpires,
	}, rootKey, root)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot create DevID certificate: %w", err)
	}

	return root, leaf, privateBlob, publicBlob, nil
}

func publicKeyFromBlob(blob []byte) (any, error) {
	decoded, err := tpm2.DecodePublic(blob)
	if err != nil {
		return nil, fmt.Errorf("cannot decode public blob: %w", err)
	}

	key, err := decoded.Key()
	if err != nil {
		return nil, fmt.Errorf("cannot get key from public blob: %w", err)
	}

	return key, nil
}

func createRootCertificate(key *rsa.PrivateKey, tmpl *x509.Certificate) (*x509.Certificate, error) {
	return createCertificate(&key.PublicKey, tmpl, key, tmpl)
}

func createCertificate(key any, tmpl *x509.Certificate, parentKey *rsa.PrivateKey, parent *x509.Certificate) (*x509.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key, parentKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

func certsToPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, cert := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return out
}

func writeFiles(dir string, files map[string][]byte) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("cannot create directory %q: %w", dir, err)
	}

	for name, contents := range files {
		path := filepath.Join(dir, name)
		// The server and agent containers read these back as a different user
		// than the one that writes them, so they cannot be owner-only. The
		// material is public certificates plus a key blob that is wrapped by
		// the TPM and useless away from it.
		if err := os.WriteFile(path, contents, 0644); err != nil { //nolint: gosec // test fixtures read by containers running as another user
			return fmt.Errorf("cannot write %q: %w", path, err)
		}
	}

	return nil
}
