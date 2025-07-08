package vault

import (
	"context"
	"crypto/x509"
	"os"
	"strconv"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
)

const (
	pluginName = "vault"

	PluginConfigMalformed = "plugin configuration is malformed"
)

// BuiltIn constructs a catalog.BuiltIn using a new instance of this plugin.
func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		upstreamauthorityv1.UpstreamAuthorityPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type Configuration struct {
	// A URL of Vault server. (e.g., https://vault.example.com:8443/)
	VaultAddr string `hcl:"vault_addr" json:"vault_addr"`
	// Name of the mount point where PKI secret engine is mounted. (e.g., /<mount_point>/ca/pem)
	PKIMountPoint string `hcl:"pki_mount_point" json:"pki_mount_point"`
	// Configuration for the Token authentication method
	TokenAuth *TokenAuthConfig `hcl:"token_auth" json:"token_auth,omitempty"`
	// Configuration for the Client Certificate authentication method
	CertAuth *CertAuthConfig `hcl:"cert_auth" json:"cert_auth,omitempty"`
	// Configuration for the AppRole authentication method
	AppRoleAuth *AppRoleAuthConfig `hcl:"approle_auth" json:"approle_auth,omitempty"`
	// Configuration for the Kubernetes authentication method
	K8sAuth *K8sAuthConfig `hcl:"k8s_auth" json:"k8s_auth,omitempty"`
	// Path to a CA certificate file that the client verifies the server certificate.
	// Only PEM format is supported.
	CACertPath string `hcl:"ca_cert_path" json:"ca_cert_path"`
	// If true, vault client accepts any server certificates.
	// It should be used only test environment so on.
	InsecureSkipVerify bool `hcl:"insecure_skip_verify" json:"insecure_skip_verify"`
	// Name of the Vault namespace
	Namespace string `hcl:"namespace" json:"namespace"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Configuration {
	newConfig := new(Configuration)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportError("plugin configuration is malformed")
		return nil
	}

	// TODO: add field validations

	// TODO: consider moving some elements of parseAuthMethod into config checking
	// TODO: consider moving some elements of genClientParams into config checking
	// TODO: consider moving some elements of NewClientConfig into config checking

	return newConfig
}

// TokenAuthConfig represents parameters for token auth method
type TokenAuthConfig struct {
	// Token string to set into "X-Vault-Token" header
	Token string `hcl:"token" json:"token"`
}

// CertAuthConfig represents parameters for cert auth method
type CertAuthConfig struct {
	// Name of the mount point where Client Certificate Auth method is mounted. (e.g., /auth/<mount_point>/login)
	// If the value is empty, use default mount point (/auth/cert)
	CertAuthMountPoint string `hcl:"cert_auth_mount_point" json:"cert_auth_mount_point"`
	// Name of the Vault role.
	// If given, the plugin authenticates against only the named role.
	CertAuthRoleName string `hcl:"cert_auth_role_name" json:"cert_auth_role_name"`
	// Path to a client certificate file.
	// Only PEM format is supported.
	ClientCertPath string `hcl:"client_cert_path" json:"client_cert_path"`
	// Path to a client private key file.
	// Only PEM format is supported.
	ClientKeyPath string `hcl:"client_key_path" json:"client_key_path"`
}

// AppRoleAuthConfig represents parameters for AppRole auth method.
type AppRoleAuthConfig struct {
	// Name of the mount point where AppRole auth method is mounted. (e.g., /auth/<mount_point>/login)
	// If the value is empty, use default mount point (/auth/approle)
	AppRoleMountPoint string `hcl:"approle_auth_mount_point" json:"approle_auth_mount_point"`
	// An identifier that selects the AppRole
	RoleID string `hcl:"approle_id" json:"approle_id"`
	// A credential that is required for login.
	SecretID string `hcl:"approle_secret_id" json:"approle_secret_id"`
}

// K8sAuthConfig represents parameters for Kubernetes auth method.
type K8sAuthConfig struct {
	// Name of the mount point where Kubernetes auth method is mounted. (e.g., /auth/<mount_point>/login)
	// If the value is empty, use default mount point (/auth/kubernetes)
	K8sAuthMountPoint string `hcl:"k8s_auth_mount_point" json:"k8s_auth_mount_point"`
	// Name of the Vault role.
	// The plugin authenticates against the named role.
	K8sAuthRoleName string `hcl:"k8s_auth_role_name" json:"k8s_auth_role_name"`
	// Path to the Kubernetes Service Account Token to use authentication with the Vault.
	TokenPath string `hcl:"token_path" json:"token_path"`
}

type Plugin struct {
	upstreamauthorityv1.UnsafeUpstreamAuthorityServer
	configv1.UnsafeConfigServer

	mtx    *sync.RWMutex
	logger hclog.Logger

	authMethod AuthMethod
	cc         *ClientConfig
	vc         *Client

	hooks struct {
		lookupEnv func(string) (string, bool)
	}
}

func New() *Plugin {
	p := &Plugin{
		mtx: &sync.RWMutex{},
	}

	p.hooks.lookupEnv = os.LookupEnv

	return p
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.logger = log
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	am, err := parseAuthMethod(newConfig)
	if err != nil {
		return nil, err
	}
	cp, err := p.genClientParams(am, newConfig)
	if err != nil {
		return nil, err
	}
	vcConfig, err := NewClientConfig(cp, p.logger)
	if err != nil {
		return nil, err
	}

	p.authMethod = am
	p.cc = vcConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, err
}

func (p *Plugin) MintX509CAAndSubscribe(req *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	if p.cc == nil {
		return status.Error(codes.FailedPrecondition, "plugin not configured")
	}

	var ttl string
	if req.PreferredTtl == 0 {
		ttl = ""
	} else {
		ttl = strconv.Itoa(int(req.PreferredTtl))
	}

	csr, err := x509.ParseCertificateRequest(req.Csr)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to parse CSR data: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	renewCh := make(chan struct{})
	if p.vc == nil {
		vc, err := p.cc.NewAuthenticatedClient(p.authMethod, renewCh)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to prepare authenticated client: %v", err)
		}
		p.vc = vc

		// if renewCh has been closed, the token can not be renewed and may expire,
		// it needs to re-authenticate to the Vault.
		go func() {
			<-renewCh
			p.mtx.Lock()
			defer p.mtx.Unlock()
			p.vc = nil
			p.logger.Debug("Going to re-authenticate to the Vault at the next signing request time")
		}()
	}

	signResp, err := p.vc.SignIntermediate(ttl, csr)
	if err != nil {
		return err
	}
	if signResp == nil {
		return status.Error(codes.Internal, "unexpected empty response from UpstreamAuthority")
	}

	// Parse CACert in PEM format
	var upstreamRootPEM string
	if len(signResp.UpstreamCACertChainPEM) == 0 {
		upstreamRootPEM = signResp.UpstreamCACertPEM
	} else {
		upstreamRootPEM = signResp.UpstreamCACertChainPEM[len(signResp.UpstreamCACertChainPEM)-1]
	}
	upstreamRoot, err := pemutil.ParseCertificate([]byte(upstreamRootPEM))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to parse Root CA certificate: %v", err)
	}

	upstreamX509Roots, err := x509certificate.ToPluginFromCertificates([]*x509.Certificate{upstreamRoot})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response upstream X.509 roots: %v", err)
	}

	// Parse PEM format data to get DER format data
	certificate, err := pemutil.ParseCertificate([]byte(signResp.CACertPEM))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to parse certificate: %v", err)
	}
	certChain := []*x509.Certificate{certificate}
	for _, c := range signResp.UpstreamCACertChainPEM {
		if c == upstreamRootPEM {
			continue
		}
		// Since Vault v1.11.0, the signed CA certificate appears within the ca_chain
		// https://github.com/hashicorp/vault/blob/v1.11.0/changelog/15524.txt
		if c == signResp.CACertPEM {
			continue
		}

		b, err := pemutil.ParseCertificate([]byte(c))
		if err != nil {
			return status.Errorf(codes.Internal, "failed to parse upstream bundle certificates: %v", err)
		}
		certChain = append(certChain, b)
	}

	x509CAChain, err := x509certificate.ToPluginFromCertificates(certChain)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response X.509 CA chain: %v", err)
	}

	return stream.Send(&upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       x509CAChain,
		UpstreamX509Roots: upstreamX509Roots,
	})
}

// PublishJWTKeyAndSubscribe is not implemented by the wrapper and returns a codes.Unimplemented status
func (*Plugin) PublishJWTKeyAndSubscribe(*upstreamauthorityv1.PublishJWTKeyRequest, upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	return status.Error(codes.Unimplemented, "publishing upstream is unsupported")
}

func (p *Plugin) SubscribeToLocalBundle(req *upstreamauthorityv1.SubscribeToLocalBundleRequest, stream upstreamauthorityv1.UpstreamAuthority_SubscribeToLocalBundleServer) error {
	return status.Error(codes.Unimplemented, "fetching upstream trust bundle is unsupported")
}

func (p *Plugin) genClientParams(method AuthMethod, config *Configuration) (*ClientParams, error) {
	cp := &ClientParams{
		VaultAddr:     p.getEnvOrDefault(envVaultAddr, config.VaultAddr),
		CACertPath:    p.getEnvOrDefault(envVaultCACert, config.CACertPath),
		PKIMountPoint: config.PKIMountPoint,
		TLSSKipVerify: config.InsecureSkipVerify,
		Namespace:     p.getEnvOrDefault(envVaultNamespace, config.Namespace),
	}

	switch method {
	case TOKEN:
		cp.Token = p.getEnvOrDefault(envVaultToken, config.TokenAuth.Token)
	case CERT:
		cp.CertAuthMountPoint = config.CertAuth.CertAuthMountPoint
		cp.CertAuthRoleName = config.CertAuth.CertAuthRoleName
		cp.ClientCertPath = p.getEnvOrDefault(envVaultClientCert, config.CertAuth.ClientCertPath)
		cp.ClientKeyPath = p.getEnvOrDefault(envVaultClientKey, config.CertAuth.ClientKeyPath)
	case APPROLE:
		cp.AppRoleAuthMountPoint = config.AppRoleAuth.AppRoleMountPoint
		cp.AppRoleID = p.getEnvOrDefault(envVaultAppRoleID, config.AppRoleAuth.RoleID)
		cp.AppRoleSecretID = p.getEnvOrDefault(envVaultAppRoleSecretID, config.AppRoleAuth.SecretID)
	case K8S:
		if config.K8sAuth.K8sAuthRoleName == "" {
			return nil, status.Error(codes.InvalidArgument, "k8s_auth_role_name is required")
		}
		if config.K8sAuth.TokenPath == "" {
			return nil, status.Error(codes.InvalidArgument, "token_path is required")
		}
		cp.K8sAuthMountPoint = config.K8sAuth.K8sAuthMountPoint
		cp.K8sAuthRoleName = config.K8sAuth.K8sAuthRoleName
		cp.K8sAuthTokenPath = config.K8sAuth.TokenPath
	}

	return cp, nil
}

func (p *Plugin) getEnvOrDefault(envKey, fallback string) string {
	if value, ok := p.hooks.lookupEnv(envKey); ok {
		return value
	}
	return fallback
}

func parseAuthMethod(config *Configuration) (AuthMethod, error) {
	var authMethod AuthMethod
	if config.TokenAuth != nil {
		authMethod = TOKEN
	}
	if config.CertAuth != nil {
		if err := checkForAuthMethodConfigured(authMethod); err != nil {
			return 0, err
		}
		authMethod = CERT
	}
	if config.AppRoleAuth != nil {
		if err := checkForAuthMethodConfigured(authMethod); err != nil {
			return 0, err
		}
		authMethod = APPROLE
	}
	if config.K8sAuth != nil {
		if err := checkForAuthMethodConfigured(authMethod); err != nil {
			return 0, err
		}
		authMethod = K8S
	}

	if authMethod != 0 {
		return authMethod, nil
	}

	return 0, status.Error(codes.InvalidArgument, "must be configured one of these authentication method 'Token, Client Certificate, AppRole or Kubernetes")
}

func checkForAuthMethodConfigured(authMethod AuthMethod) error {
	if authMethod != 0 {
		return status.Error(codes.InvalidArgument, "only one authentication method can be configured")
	}
	return nil
}
