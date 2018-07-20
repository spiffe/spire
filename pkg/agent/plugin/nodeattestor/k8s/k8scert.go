package k8s

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"time"

	certificates "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	csrPemBlockType          = "CERTIFICATE REQUEST"
	ecPrivateKeyPemBlockType = "EC PRIVATE KEY"
)

func getKubeClient(kubeConfigFilePath, clientCertFilePath, clientKeyFilePath, caCertFilePath string) (*kubernetes.Clientset, error) {
	if kubeConfigFilePath == "" {
		// Try KUBECONFIG env variable
		kubeConfigFilePath = os.Getenv("KUBECONFIG")
		if kubeConfigFilePath == "" {
			// Still no luck, try default (home)
			home := os.Getenv("HOME")
			if home != "" {
				kubeConfigFilePath = path.Join(home, ".kube", "config")
			}
		}
	}

	if kubeConfigFilePath == "" {
		return nil, fmt.Errorf("Unable to locate kubeconfig")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("Error accessing kubeconfig %s: %v", kubeConfigFilePath, err)
	}

	config.TLSClientConfig.CertFile = clientCertFilePath
	config.TLSClientConfig.KeyFile = clientKeyFilePath
	config.TLSClientConfig.CAFile = caCertFilePath

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("Error creating clientset: %v", err)
	}
	return clientset, nil
}

func genPrivateKey() (crypto.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Error generating ECDSA private key: %v", err)
	}
	return key, nil
}

func genCSR(key crypto.PrivateKey, name string) ([]byte, error) {
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			// This exact format is required for the CSR to be auto-approved by kube-controller
			// It must also NOT include any DNSNames or IPAddresses
			Organization: []string{"system:nodes"},
			CommonName:   "system:node:" + name,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	return x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
}

func getCSRObject(csrBytes []byte, name string) *certificates.CertificateSigningRequest {
	pemBlock := pem.Block{
		Type:  csrPemBlockType,
		Bytes: csrBytes,
	}
	pemBytes := pem.EncodeToMemory(&pemBlock)

	ret := &certificates.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: certificates.CertificateSigningRequestSpec{
			Groups:  []string{"system:authenticated"},
			Request: pemBytes,
			Usages:  []certificates.KeyUsage{"digital signature", "key encipherment", "client auth"},
		},
	}
	return ret
}

func fetchK8sCert(kubeConfigFilePath, clientCertFilePath, clientKeyFilePath, caCertFilePath string) (*tls.Certificate, error) {
	kubeClient, err := getKubeClient(kubeConfigFilePath, clientCertFilePath, clientKeyFilePath, caCertFilePath)
	if err != nil {
		return nil, fmt.Errorf("Error creating Kubernetes client: %v", err)
	}

	key, err := genPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("Error creating private key: %v", err)
	}

	agentName, err := os.Hostname()
	if err != nil {
		agentName = "unknown"
	}

	csr, err := genCSR(key, agentName)
	if err != nil {
		return nil, fmt.Errorf("Error creating certificate signing request: %v", err)
	}

	csrObjectName := fmt.Sprintf("%s-%d", agentName, time.Now().Unix())
	csrObject := getCSRObject(csr, csrObjectName)

	// Create CSR object in ApiServer
	csrObject, err = kubeClient.CertificatesV1beta1().CertificateSigningRequests().Create(csrObject)
	if err != nil {
		return nil, fmt.Errorf("unable to create the certificate signing request: %s", err)
	}

	// Watch for approval
	var cert []byte
	watcher, err := kubeClient.CertificatesV1beta1().CertificateSigningRequests().Watch(metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("Error watching CSRs on ApiServer: %v", err)
	}
	wc := watcher.ResultChan()
	for event := range wc {
		csr, ok := event.Object.(*certificates.CertificateSigningRequest)
		if !ok {
			return nil, fmt.Errorf("unexpected event type during watch")
		}
		if event.Type == watch.Modified && csr.ObjectMeta.Name == csrObjectName {
			for _, cond := range csr.Status.Conditions {
				if cond.Type == certificates.CertificateApproved {
					cert = csr.Status.Certificate
					break
				}
			}
		}
		if len(cert) > 0 {
			break // approved
		}
	}

	keyBytes, err := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("Error marshalling ECDSA private key: %v", err)
	}
	pemKey := &pem.Block{
		Type:  ecPrivateKeyPemBlockType,
		Bytes: keyBytes,
	}
	pemKeyBytes := pem.EncodeToMemory(pemKey)

	tlsCert, err := tls.X509KeyPair(cert, pemKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("Error forming x509 key pair: %v", err)
	}
	return &tlsCert, nil
}
