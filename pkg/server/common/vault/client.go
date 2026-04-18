package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	EnvVaultAddr              = "VAULT_ADDR"
	EnvVaultToken             = "VAULT_TOKEN"
	EnvVaultClientCert        = "VAULT_CLIENT_CERT"
	EnvVaultClientKey         = "VAULT_CLIENT_KEY"
	EnvVaultCACert            = "VAULT_CACERT"
	EnvVaultAppRoleID         = "VAULT_APPROLE_ID"
	EnvVaultAppRoleSecretID   = "VAULT_APPROLE_SECRET_ID" // #nosec G101
	EnvVaultNamespace         = "VAULT_NAMESPACE"
	EnvVaultTransitEnginePath = "VAULT_TRANSIT_ENGINE_PATH"

	defaultCertMountPoint    = "cert"
	defaultPKIMountPoint     = "pki"
	defaultTransitEnginePath = "transit"
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

type TransitKeyType string

const (
	TransitKeyTypeRSA2048   TransitKeyType = "rsa-2048"
	TransitKeyTypeRSA4096   TransitKeyType = "rsa-4096"
	TransitKeyTypeECDSAP256 TransitKeyType = "ecdsa-p256"
	TransitKeyTypeECDSAP384 TransitKeyType = "ecdsa-p384"
)

type TransitHashAlgorithm string

const (
	TransitHashAlgorithmSHA256 TransitHashAlgorithm = "sha2-256"
	TransitHashAlgorithmSHA384 TransitHashAlgorithm = "sha2-384"
	TransitHashAlgorithmSHA512 TransitHashAlgorithm = "sha2-512"
	TransitHashAlgorithmNone   TransitHashAlgorithm = "none"
)

type TransitSignatureAlgorithm string

const (
	TransitSignatureAlgorithmNone              TransitSignatureAlgorithm = ""
	TransitSignatureSignatureAlgorithmPSS      TransitSignatureAlgorithm = "pss"
	TransitSignatureSignatureAlgorithmPKCS1v15 TransitSignatureAlgorithm = "pkcs1v15"
)

type KeyEntry struct {
	KeyName string
	// KeyType is the top-level type from Vault (e.g., "ecdsa-p256", "rsa-2048").
	KeyType string
	KeyData map[string]any
}

// ClientConfig represents configuration parameters for vault client
type ClientConfig struct {
	Logger hclog.Logger
	// vault client parameters
	ClientParams *ClientParams
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
	TLSSkipVerify bool
	// MaxRetries controls the number of times to retry to connect
	// Set to 0 to disable retrying.
	// If the value is nil, to use the default in hashicorp/vault/api.
	MaxRetries *int
	// Name of the Vault namespace
	Namespace string
	// TransitEnginePath specifies the path to the transit engine to perform key operations.
	TransitEnginePath string
}

type Client struct {
	vaultClient  *vapi.Client
	ClientParams *ClientParams
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
		TransitEnginePath:     defaultTransitEnginePath,
	}
	if err := mergo.Merge(cp, defaultParams); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to merge client params: %v", err)
	}
	cc.ClientParams = cp
	return cc, nil
}

// NewAuthenticatedClient returns a new authenticated vault client with given authentication method
func (c *ClientConfig) NewAuthenticatedClient(method AuthMethod, renewCh chan struct{}) (client *Client, err error) {
	config := vapi.DefaultConfig()
	config.Address = c.ClientParams.VaultAddr
	if c.ClientParams.MaxRetries != nil {
		config.MaxRetries = *c.ClientParams.MaxRetries
	}

	if err := c.configureTLS(config); err != nil {
		return nil, err
	}
	vc, err := vapi.NewClient(config)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to create Vault client: %v", err)
	}

	if c.ClientParams.Namespace != "" {
		vc.SetNamespace(c.ClientParams.Namespace)
	}

	client = &Client{
		vaultClient:  vc,
		ClientParams: c.ClientParams,
	}

	var sec *vapi.Secret
	switch method {
	case TOKEN:
		sec, err = client.LookupSelf(c.ClientParams.Token)
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, status.Error(codes.Internal, "lookup self response is nil")
		}
	case CERT:
		path := fmt.Sprintf("auth/%v/login", c.ClientParams.CertAuthMountPoint)
		sec, err = client.Auth(path, map[string]any{
			"name": c.ClientParams.CertAuthRoleName,
		})
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, status.Error(codes.Internal, "tls cert authentication response is nil")
		}
	case APPROLE:
		path := fmt.Sprintf("auth/%v/login", c.ClientParams.AppRoleAuthMountPoint)
		body := map[string]any{
			"role_id":   c.ClientParams.AppRoleID,
			"secret_id": c.ClientParams.AppRoleSecretID,
		}
		sec, err = client.Auth(path, body)
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, status.Error(codes.Internal, "approle authentication response is nil")
		}
	case K8S:
		b, err := os.ReadFile(c.ClientParams.K8sAuthTokenPath)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to read k8s service account token: %v", err)
		}
		path := fmt.Sprintf("auth/%s/login", c.ClientParams.K8sAuthMountPoint)
		body := map[string]any{
			"role": c.ClientParams.K8sAuthRoleName,
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

	transport, ok := vc.HttpClient.Transport.(*http.Transport)
	if !ok {
		return status.Errorf(codes.Internal, "http client transport is of incorrect type. Expected is %T but was %T", transport, vc.HttpClient.Transport)
	}
	clientTLSConfig := transport.TLSClientConfig

	var clientCert tls.Certificate
	foundClientCert := false

	switch {
	case c.ClientParams.ClientCertPath != "" && c.ClientParams.ClientKeyPath != "":
		c, err := tls.LoadX509KeyPair(c.ClientParams.ClientCertPath, c.ClientParams.ClientKeyPath)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "failed to parse client cert and private-key: %v", err)
		}
		clientCert = c
		foundClientCert = true
	case c.ClientParams.ClientCertPath != "" || c.ClientParams.ClientKeyPath != "":
		return status.Error(codes.InvalidArgument, "both client cert and client key are required")
	}

	if c.ClientParams.CACertPath != "" {
		certs, err := pemutil.LoadCertificates(c.ClientParams.CACertPath)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "failed to load CA certificate: %v", err)
		}
		pool := x509.NewCertPool()
		for _, cert := range certs {
			pool.AddCert(cert)
		}
		clientTLSConfig.RootCAs = pool
	}

	if c.ClientParams.TLSSkipVerify {
		clientTLSConfig.InsecureSkipVerify = true
	}

	if foundClientCert {
		clientTLSConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		}
	}

	return nil
}

// VaultClient returns the underlying vault API client.
func (c *Client) VaultClient() *vapi.Client {
	return c.vaultClient
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

	path := fmt.Sprintf("/%s/root/sign-intermediate", c.ClientParams.PKIMountPoint)
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

// CreateKey creates a new key in the specified transit secret engine
// See: https://developer.hashicorp.com/vault/api-docs/secret/transit#create-key
func (c *Client) CreateKey(ctx context.Context, keyName string, keyType TransitKeyType) error {
	arguments := map[string]any{
		"type":       keyType,
		"exportable": "false", // SPIRE keys are never exportable
	}

	_, err := c.vaultClient.Logical().WriteWithContext(ctx, fmt.Sprintf("/%s/keys/%s", c.ClientParams.TransitEnginePath, keyName), arguments)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create transit engine key: %v", err)
	}

	return nil
}

// DeleteKey deletes a key in the specified transit secret engine
// See: https://developer.hashicorp.com/vault/api-docs/secret/transit#update-key-configuration and https://developer.hashicorp.com/vault/api-docs/secret/transit#delete-key
func (c *Client) DeleteKey(ctx context.Context, keyName string) error {
	arguments := map[string]any{
		"deletion_allowed": "true",
	}

	// First, we need to enable deletion of the key. This is disabled by default.
	_, err := c.vaultClient.Logical().WriteWithContext(ctx, fmt.Sprintf("/%s/keys/%s/config", c.ClientParams.TransitEnginePath, keyName), arguments)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to enable deletion of transit engine key: %v", err)
	}

	_, err = c.vaultClient.Logical().DeleteWithContext(ctx, fmt.Sprintf("/%s/keys/%s", c.ClientParams.TransitEnginePath, keyName))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to delete transit engine key: %v", err)
	}

	return nil
}

// SignData signs the data using the transit engine key with the key name.
// See: https://developer.hashicorp.com/vault/api-docs/secret/transit#sign-data
func (c *Client) SignData(ctx context.Context, keyName string, data []byte, hashAlgo TransitHashAlgorithm, signatureAlgo TransitSignatureAlgorithm) ([]byte, error) {
	encodedData := base64.StdEncoding.EncodeToString(data)

	body := map[string]any{
		"input":                 encodedData,
		"signature_algorithm":   signatureAlgo,
		"marshalling_algorithm": "asn1",
		"prehashed":             "true",
	}

	sigResp, err := c.vaultClient.Logical().WriteWithContext(ctx, fmt.Sprintf("/%s/sign/%s/%s", c.ClientParams.TransitEnginePath, keyName, hashAlgo), body)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "transit engine sign call failed: %v", err)
	}

	sig, ok := sigResp.Data["signature"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "transit engine sign call was successful but signature is missing")
	}

	sigStr, ok := sig.(string)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected signature data type %T but got %T", sigStr, sig)
	}

	// Vault adds an application specific prefix that we need to remove
	cutSig, ok := strings.CutPrefix(sigStr, "vault:v1:")
	if !ok {
		return nil, status.Error(codes.Internal, "signature is missing vault prefix")
	}

	sigData, err := base64.StdEncoding.DecodeString(cutSig)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to base64 decode signature: %v", err)
	}

	return sigData, nil
}

// GetKeys returns all the keys of the transit engine.
// See: https://developer.hashicorp.com/vault/api-docs/secret/transit#list-keys
func (c *Client) GetKeys(ctx context.Context) ([]*KeyEntry, error) {
	var keyEntries []*KeyEntry

	listResp, err := c.vaultClient.Logical().ListWithContext(ctx, fmt.Sprintf("/%s/keys", c.ClientParams.TransitEnginePath))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "transit engine list keys call failed: %v", err)
	}

	if listResp == nil {
		return []*KeyEntry{}, nil
	}

	keys, ok := listResp.Data["keys"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "transit engine list keys call was successful but keys are missing")
	}

	keyNames, ok := keys.([]any)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected keys data type %T but got %T", keyNames, keys)
	}

	for _, keyName := range keyNames {
		keyNameStr, ok := keyName.(string)
		if !ok {
			return nil, status.Errorf(codes.Internal, "expected key id data type %T but got %T", keyNameStr, keyName)
		}

		ke, err := c.GetKey(ctx, keyNameStr)
		if err != nil {
			return nil, err
		}

		keyEntries = append(keyEntries, ke)
	}

	return keyEntries, nil
}

// GetKey returns a specific key from the transit engine.
// See: https://developer.hashicorp.com/vault/api-docs/secret/transit#read-key
func (c *Client) GetKey(ctx context.Context, keyName string) (*KeyEntry, error) {
	res, err := c.vaultClient.Logical().ReadWithContext(ctx, fmt.Sprintf("/%s/keys/%s", c.ClientParams.TransitEnginePath, keyName))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get transit engine key: %v", err)
	}

	keyType, ok := res.Data["type"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "transit engine get key call was successful but type is missing")
	}
	keyTypeStr, ok := keyType.(string)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected key type data type %T but got %T", keyTypeStr, keyType)
	}

	latestVersionRaw, ok := res.Data["latest_version"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "transit engine get key call was successful but latest_version is missing")
	}
	// The Vault SDK deserializes JSON numbers as json.Number in map[string]any.
	latestVersionNum, ok := latestVersionRaw.(json.Number)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected latest_version data type json.Number but got %T", latestVersionRaw)
	}
	latestVersion := latestVersionNum.String()

	keys, ok := res.Data["keys"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "transit engine get key call was successful but keys are missing")
	}
	keyMap, ok := keys.(map[string]any)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected key map data type %T but got %T", keyMap, keys)
	}

	currentKey, ok := keyMap[latestVersion]
	if !ok {
		return nil, status.Errorf(codes.Internal, "unable to find key with version %s in key map", latestVersion)
	}
	currentKeyMap, ok := currentKey.(map[string]any)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected key data type %T but got %T", currentKeyMap, currentKey)
	}

	return &KeyEntry{KeyName: keyName, KeyType: keyTypeStr, KeyData: currentKeyMap}, nil
}
