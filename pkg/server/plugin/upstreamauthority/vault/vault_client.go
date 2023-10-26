package vault

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/go-hclog"
	vapi "github.com/hashicorp/vault/api"
	"github.com/imdario/mergo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spiffe/spire/pkg/common/pemutil"
)

const (
	envVaultAddr            = "VAULT_ADDR"
	envVaultToken           = "VAULT_TOKEN"
	envVaultClientCert      = "VAULT_CLIENT_CERT"
	envVaultClientKey       = "VAULT_CLIENT_KEY"
	envVaultCACert          = "VAULT_CACERT"
	envVaultAppRoleID       = "VAULT_APPROLE_ID"
	envVaultAppRoleSecretID = "VAULT_APPROLE_SECRET_ID" // #nosec G101
	envVaultNamespace       = "VAULT_NAMESPACE"

	defaultCertMountPoint    = "cert"
	defaultPKIMountPoint     = "pki"
	defaultAppRoleMountPoint = "approle"
	defaultK8sMountPoint     = "kubernetes"
)

type AuthMethod int

const (
	_ AuthMethod = iota
	CERT
	TOKEN
	APPROLE
	K8S
)

// ClientConfig represents configuration parameters for vault client
type ClientConfig struct {
	Logger hclog.Logger
	// vault client parameters
	clientParams *ClientParams
}

type ClientParams struct {
	// A URL of Vault server. (e.g., https://vault.example.com:8443/)
	VaultAddr string
	// Name of mount point where PKI secret engine is mounted. (e.e., /<mount_point>/ca/pem )
	PKIMountPoint string
	// token string to use when auth method is 'token'
	Token string
	// Name of mount point where TLS Cert auth method is mounted. (e.g., /auth/<mount_point>/login )
	CertAuthMountPoint string
	// Name of the Vault role.
	// If given, the plugin authenticates against only the named role
	CertAuthRoleName string
	// Path to a client certificate file to be used when auth method is 'cert'
	ClientCertPath string
	// Path to a client private key file to be used when auth method is 'cert'
	ClientKeyPath string
	// Path to a CA certificate file to be used when client verifies a server certificate
	CACertPath string
	// Name of mount point where AppRole auth method is mounted. (e.g., /auth/<mount_point>/login )
	AppRoleAuthMountPoint string
	// An identifier of AppRole
	AppRoleID string
	// A credential set of AppRole
	AppRoleSecretID string
	// Name of the mount point where Kubernetes auth method is mounted. (e.g., /auth/<mount_point>/login)
	K8sAuthMountPoint string
	// Name of the Vault role.
	// The plugin authenticates against the named role.
	K8sAuthRoleName string
	// Path to a K8s Service Account Token to be used when auth method is 'k8s'
	K8sAuthTokenPath string
	// If true, client accepts any certificates.
	// It should be used only test environment so on.
	TLSSKipVerify bool
	// MaxRetries controls the number of times to retry to connect
	// Set to 0 to disable retrying.
	// If the value is nil, to use the default in hashicorp/vault/api.
	MaxRetries *int
	// Name of the Vault namespace
	Namespace string
}

type Client struct {
	vaultClient  *vapi.Client
	clientParams *ClientParams
}

// SignCSRResponse includes certificates which are generates by Vault
type SignCSRResponse struct {
	// A certificate requested to sign
	CACertPEM string
	// A certificate of CA(Vault)
	UpstreamCACertPEM string
	// Set of Upstream CA certificates
	UpstreamCACertChainPEM []string
}

// NewClientConfig returns a new *ClientConfig with default parameters.
func NewClientConfig(cp *ClientParams, logger hclog.Logger) (*ClientConfig, error) {
	cc := &ClientConfig{
		Logger: logger,
	}
	defaultParams := &ClientParams{
		CertAuthMountPoint:    defaultCertMountPoint,
		AppRoleAuthMountPoint: defaultAppRoleMountPoint,
		K8sAuthMountPoint:     defaultK8sMountPoint,
		PKIMountPoint:         defaultPKIMountPoint,
	}
	if err := mergo.Merge(cp, defaultParams); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to merge client params: %v", err)
	}
	cc.clientParams = cp
	return cc, nil
}

// NewAuthenticatedClient returns a new authenticated vault client with given authentication method
func (c *ClientConfig) NewAuthenticatedClient(method AuthMethod, renewCh chan struct{}) (client *Client, err error) {
	config := vapi.DefaultConfig()
	config.Address = c.clientParams.VaultAddr
	if c.clientParams.MaxRetries != nil {
		config.MaxRetries = *c.clientParams.MaxRetries
	}

	if err := c.configureTLS(config); err != nil {
		return nil, err
	}
	vc, err := vapi.NewClient(config)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to create Vault client: %v", err)
	}

	if c.clientParams.Namespace != "" {
		vc.SetNamespace(c.clientParams.Namespace)
	}

	client = &Client{
		vaultClient:  vc,
		clientParams: c.clientParams,
	}

	var sec *vapi.Secret
	switch method {
	case TOKEN:
		sec, err = client.LookupSelf(c.clientParams.Token)
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, status.Error(codes.Internal, "lookup self response is nil")
		}
	case CERT:
		path := fmt.Sprintf("auth/%v/login", c.clientParams.CertAuthMountPoint)
		sec, err = client.Auth(path, map[string]any{
			"name": c.clientParams.CertAuthRoleName,
		})
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, status.Error(codes.Internal, "tls cert authentication response is nil")
		}
	case APPROLE:
		path := fmt.Sprintf("auth/%v/login", c.clientParams.AppRoleAuthMountPoint)
		body := map[string]any{
			"role_id":   c.clientParams.AppRoleID,
			"secret_id": c.clientParams.AppRoleSecretID,
		}
		sec, err = client.Auth(path, body)
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, status.Error(codes.Internal, "approle authentication response is nil")
		}
	case K8S:
		b, err := os.ReadFile(c.clientParams.K8sAuthTokenPath)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to read k8s service account token: %v", err)
		}
		path := fmt.Sprintf("auth/%s/login", c.clientParams.K8sAuthMountPoint)
		body := map[string]any{
			"role": c.clientParams.K8sAuthRoleName,
			"jwt":  string(b),
		}
		sec, err = client.Auth(path, body)
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, status.Error(codes.Internal, "k8s authentication response is nil")
		}
	}

	err = handleRenewToken(vc, sec, renewCh, c.Logger)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// handleRenewToken handles renewing the vault token.
// if the token is non-renewable or renew failed, renewCh will be closed.
func handleRenewToken(vc *vapi.Client, sec *vapi.Secret, renewCh chan struct{}, logger hclog.Logger) error {
	if sec == nil || sec.Auth == nil {
		return status.Error(codes.InvalidArgument, "secret is nil")
	}

	if sec.Auth.LeaseDuration == 0 {
		logger.Debug("Token will never expire")
		return nil
	}
	if !sec.Auth.Renewable {
		logger.Debug("Token is not renewable")
		close(renewCh)
		return nil
	}
	renew, err := NewRenew(vc, sec, logger)
	if err != nil {
		return err
	}

	go func() {
		defer close(renewCh)
		renew.Run()
	}()

	logger.Debug("Token will be renewed")

	return nil
}

// ConfigureTLS Configures TLS for Vault Client
func (c *ClientConfig) configureTLS(vc *vapi.Config) error {
	if vc.HttpClient == nil {
		vc.HttpClient = vapi.DefaultConfig().HttpClient
	}
	clientTLSConfig := vc.HttpClient.Transport.(*http.Transport).TLSClientConfig

	var clientCert tls.Certificate
	foundClientCert := false

	switch {
	case c.clientParams.ClientCertPath != "" && c.clientParams.ClientKeyPath != "":
		c, err := tls.LoadX509KeyPair(c.clientParams.ClientCertPath, c.clientParams.ClientKeyPath)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "failed to parse client cert and private-key: %v", err)
		}
		clientCert = c
		foundClientCert = true
	case c.clientParams.ClientCertPath != "" || c.clientParams.ClientKeyPath != "":
		return status.Error(codes.InvalidArgument, "both client cert and client key are required")
	}

	if c.clientParams.CACertPath != "" {
		certs, err := pemutil.LoadCertificates(c.clientParams.CACertPath)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "failed to load CA certificate: %v", err)
		}
		pool := x509.NewCertPool()
		for _, cert := range certs {
			pool.AddCert(cert)
		}
		clientTLSConfig.RootCAs = pool
	}

	if c.clientParams.TLSSKipVerify {
		clientTLSConfig.InsecureSkipVerify = true
	}

	if foundClientCert {
		clientTLSConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		}
	}

	return nil
}

// SetToken wraps vapi.Client.SetToken()
func (c *Client) SetToken(v string) {
	c.vaultClient.SetToken(v)
}

// Auth authenticates to vault server with TLS certificate method
func (c *Client) Auth(path string, body map[string]any) (*vapi.Secret, error) {
	c.vaultClient.ClearToken()
	secret, err := c.vaultClient.Logical().Write(path, body)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication failed %v: %v", path, err)
	}

	tokenID, err := secret.TokenID()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "authentication is successful, but could not get token: %v", err)
	}
	c.vaultClient.SetToken(tokenID)
	return secret, nil
}

func (c *Client) LookupSelf(token string) (*vapi.Secret, error) {
	if token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is empty")
	}
	c.SetToken(token)

	secret, err := c.vaultClient.Logical().Read("auth/token/lookup-self")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "token lookup failed: %v", err)
	}

	id, err := secret.TokenID()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get TokenID: %v", err)
	}
	renewable, err := secret.TokenIsRenewable()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to determine if token is renewable: %v", err)
	}
	ttl, err := secret.TokenTTL()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get token ttl: %v", err)
	}
	secret.Auth = &vapi.SecretAuth{
		ClientToken:   id,
		Renewable:     renewable,
		LeaseDuration: int(ttl.Seconds()),
		// don't care any parameters
	}
	return secret, nil
}

// SignIntermediate requests sign-intermediate endpoint to generate certificate.
// ttl = TTL for Intermediate CA Certificate
// csr = Certificate Signing Request
// see: https://www.vaultproject.io/api/secret/pki/index.html#sign-intermediate
func (c *Client) SignIntermediate(ttl string, csr *x509.CertificateRequest) (*SignCSRResponse, error) {
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})

	var uris []string
	for _, uri := range csr.URIs {
		uris = append(uris, uri.String())
	}
	if len(uris) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "CSR must have at least one URI")
	}

	reqData := map[string]any{
		"common_name":  csr.Subject.CommonName,
		"organization": strings.Join(csr.Subject.Organization, ","),
		"country":      strings.Join(csr.Subject.Country, ","),
		"uri_sans":     strings.Join(uris, ","),
		"csr":          string(csrPEM),
		"ttl":          ttl,
	}

	path := fmt.Sprintf("/%s/root/sign-intermediate", c.clientParams.PKIMountPoint)
	s, err := c.vaultClient.Logical().Write(path, reqData)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign intermediate: %v", err)
	}

	resp := &SignCSRResponse{}

	certData, ok := s.Data["certificate"]
	if !ok {
		return nil, status.Error(codes.Internal, "request is successful, but certificate data is empty")
	}
	cert, ok := certData.(string)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected certificate data type %T but got %T", cert, certData)
	}
	resp.CACertPEM = cert

	caCertData, ok := s.Data["issuing_ca"]
	if !ok {
		return nil, status.Error(codes.Internal, "request is successful, but issuing_ca data is empty")
	}
	caCert, ok := caCertData.(string)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected issuing_ca data type %T but got %T", caCert, caCertData)
	}
	resp.UpstreamCACertPEM = caCert

	// expect to be empty case when Vault is Root CA.
	if caChainData, ok := s.Data["ca_chain"]; ok {
		caChainCertsObj, ok := caChainData.([]any)
		if !ok {
			return nil, status.Errorf(codes.Internal, "expected ca_chain data type %T but got %T", caChainCertsObj, caChainData)
		}
		var caChainCerts []string
		for _, caChainCertObj := range caChainCertsObj {
			caChainCert, ok := caChainCertObj.(string)
			if !ok {
				return nil, status.Errorf(codes.Internal, "expected ca_chain element data type %T but got %T", caChainCert, caChainCertObj)
			}
			caChainCerts = append(caChainCerts, caChainCert)
		}
		resp.UpstreamCACertChainPEM = caChainCerts
	}

	return resp, nil
}
