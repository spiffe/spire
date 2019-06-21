// +build ignore

package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"text/template"
	"time"
)

var (
	namespaceFlag    = flag.String("namespace", "spire", "Kubernetes namespace to put objects under")
	serviceFlag      = flag.String("service", "k8s-workload-registrar", "K8S service for the registrar")
	caKeyAlgFlag     = flag.String("ca-key-alg", "ec-p256", "key algorithm to use for the CA key")
	serverKeyAlgFlag = flag.String("server-key-alg", "ec-p256", "key algorithm to use for the registrar server key")
	clientKeyAlgFlag = flag.String("client-key-alg", "ec-p256", "key algorithm to use for the registrar client key")
	ttlFlag          = flag.Duration("ttl", time.Hour*24*365, "time to live for certificates (0 for never)")

	// The "never expires" timestamp from RFC5280
	neverExpires = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

	now = time.Now()

	funcs = template.FuncMap{
		"inline": inlineFn,
		"base64": base64Fn,
	}

	tmpl = template.Must(template.New("").Funcs(funcs).Parse(`
---

# ConfigMap containing the K8S Workload Registrar server certificate and 
# CA bundle used to verify the client certificate presented by the API server.
#
apiVersion: v1
kind: ConfigMap
metadata:
  name: k8s-workload-registrar-certs
  namespace: {{ .Namespace }}
data:
  server-cert.pem: |
{{ inline 4 .ServerCert }}
  cacert.pem: |
{{ inline 4 .CaCert }}

---

# Kubernetes Secret containing the K8S Workload Registrar server key
apiVersion: v1
kind: Secret
metadata:
  name: k8s-workload-registrar-secret
type: Opaque
data:
  server-key.pem: {{ base64 .ServerKey }}

---

# KubeConfig with client credentials for the API Server to use to call the
# K8S Workload Registrar service
apiVersion: v1
kind: Config
users:
- name: {{ .ServiceDNS }}
  user:
    client-certificate-data: {{ base64 .ClientCert }}
    client-key-data: {{ base64 .ClientKey }}

---

# Validating Webhook Configuration for the K8S Workload Registrar
#
apiVersion: admissionregistration.k8s.io/v1beta1
kind: ValidatingWebhookConfiguration
metadata:
  name: k8s-workload-registrar-webhook
webhooks:
  - name: {{ .ServiceDNS }}
    clientConfig:
      service:
        name: {{ .Service }}
        namespace: {{ .Namespace }}
        path: "/validate"
      caBundle: {{ base64 .CaCert }}
    admissionReviewVersions:
    - v1beta1
    rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      operations: ["CREATE", "DELETE"]
      resources: ["pods"]
      scope: "Namespaced"

`))
)

func main() {
	flag.Parse()

	serviceDNS := makeServiceDNS(*namespaceFlag, *serviceFlag)

	caKey := generateKey(*caKeyAlgFlag)
	caCert := createCACert(caKey)

	serverKey := generateKey(*serverKeyAlgFlag)
	serverCert := createServerCert(caCert, caKey, serverKey, serviceDNS)

	clientKey := generateKey(*clientKeyAlgFlag)
	clientCert := createClientCert(caCert, caKey, clientKey)

	printTmpl(tmpl, map[string]interface{}{
		"Namespace":  *namespaceFlag,
		"Service":    *serviceFlag,
		"ServiceDNS": serviceDNS,
		"CaCert":     certPEM(caCert),
		"ServerCert": certPEM(serverCert),
		"ServerKey":  keyPEM(serverKey),
		"ClientCert": certPEM(clientCert),
		"ClientKey":  keyPEM(clientKey),
	})
}

func generateKey(alg string) crypto.Signer {
	switch strings.ToLower(alg) {
	case "rsa-2048":
		return generateRSAKey(2048)
	case "rsa-4096":
		return generateRSAKey(4096)
	case "ec-p224":
		return generateECKey(elliptic.P224())
	case "ec-p256":
		return generateECKey(elliptic.P256())
	case "ec-p384":
		return generateECKey(elliptic.P384())
	case "ec-p521":
		return generateECKey(elliptic.P521())
	default:
		die("unsupported key algorithm %q", alg)
		// unreachable
		return nil
	}
}

func generateRSAKey(bits int) crypto.Signer {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	checkErr(err, "generating RSA key")
	return key
}

func generateECKey(curve elliptic.Curve) crypto.Signer {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	checkErr(err, "generating EC key")
	return key
}

func createCACert(caKey crypto.Signer) *x509.Certificate {
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "K8S WORKLOAD REGISTRAR CA",
		},
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return createCertificate(tmpl, tmpl, caKey, caKey)
}

func createServerCert(caCert *x509.Certificate, caKey, key crypto.Signer, dnsName string) *x509.Certificate {
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "K8S WORKLOAD REGISTRAR SERVER",
		},
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{dnsName},
	}
	return createCertificate(tmpl, caCert, key, caKey)
}

func createClientCert(caCert *x509.Certificate, caKey, key crypto.Signer) *x509.Certificate {
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "K8S WORKLOAD REGISTRAR CLIENT",
		},
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}
	return createCertificate(tmpl, caCert, key, caKey)
}

func createCertificate(tmpl, parent *x509.Certificate, key, parentKey crypto.Signer) *x509.Certificate {
	tmpl.SerialNumber = randomSerial()
	tmpl.NotBefore = now
	tmpl.NotAfter = neverExpires
	tmpl.AuthorityKeyId = parent.SubjectKeyId
	tmpl.SubjectKeyId = getSubjectKeyId(key.Public())
	if *ttlFlag > 0 {
		tmpl.NotAfter = now.Add(*ttlFlag)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	checkErr(err, "creating certificate")
	cert, err := x509.ParseCertificate(certDER)
	checkErr(err, "parsing certificate")
	return cert
}

func getSubjectKeyId(pubKey interface{}) []byte {
	// Borrowed with love from cfssl under the BSD 2-Clause license
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	checkErr(err, "marshalling public key")

	var subjectKeyInfo = struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}{}

	_, err = asn1.Unmarshal(pubKeyBytes, &subjectKeyInfo)
	checkErr(err, "marshalling subject key info")

	keyID := sha1.Sum(subjectKeyInfo.SubjectPublicKey.Bytes)
	return keyID[:]
}

func makeServiceDNS(namespace, service string) string {
	return fmt.Sprintf("%s.%s.svc", service, namespace)
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func certPEM(cert *x509.Certificate) string {
	return encodePEM("CERTIFICATE", cert.Raw)
}

func keyPEM(key crypto.PrivateKey) string {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	checkErr(err, "marshaling private key")
	return encodePEM("PRIVATE KEY", keyBytes)
}

func encodePEM(typ string, bytes []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  typ,
		Bytes: bytes,
	}))
}

func printTmpl(tmpl *template.Template, data interface{}) {
	err := tmpl.Execute(os.Stdout, data)
	checkErr(err, "rendering %s template", tmpl.Name())
}

func printLn(args ...interface{}) {
	_, err := fmt.Println(args...)
	checkErr(err, "writing to stdout")
}

func randomSerial() *big.Int {
	b := randomBytes(8)
	b[0] &= 0x7f
	serial := int64(binary.BigEndian.Uint64(b))
	return big.NewInt(serial)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	checkErr(err, "reading %d random bytes", n)
	return b
}

// base64Fn base64 encodes a string
func base64Fn(data string) string {
	return base64Encode([]byte(data))
}

// inlineFn formats data at a specific indentation level for inclusion in YAML.
func inlineFn(level int, data string) (string, error) {
	indentation := strings.Repeat(" ", level)
	buf := new(bytes.Buffer)
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		text := scanner.Text()
		if text != "" {
			buf.WriteString(indentation)
		}
		buf.WriteString(text)
		buf.WriteString("\n")
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func checkErr(err error, format string, args ...interface{}) {
	if err != nil {
		die("%s failed: %+v", fmt.Sprintf(format, args...), err)
	}
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args)
	os.Exit(1)
}
