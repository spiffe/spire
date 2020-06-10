package vault

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

const (
	pluginName = "vault"
)

// BuiltIn constructs a catalog Plugin using a new instance of this plugin.
func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, upstreamauthority.PluginServer(p))
}

type PluginConfig struct {
	// A URL of Vault server. (e.g., https://vault.example.com:8443/)
	VaultAddr string `hcl:"vault_addr"`
	// Name of the mount point where PKI secret engine is mounted. (e.g., /<mount_point>/ca/pem)
	PKIMountPoint string `hcl:"pki_mount_point"`
	// Configuration for the Token authentication method
	TokenAuth TokenAuthConfig `hcl:"token_auth"`
	// Configuration for the Client Certificate authentication method
	CertAuth CertAuthConfig `hcl:"cert_auth"`
	// Configuration for the AppRole authentication method
	AppRoleAuth AppRoleAuthConfig `hcl:"approle_auth"`
	// Path to a CA certificate file that the client verifies the server certificate.
	// Only PEM format is supported.
	CACertPath string `hcl:"ca_cert_path"`
	// If true, vault client accepts any server certificates.
	// It should be used only test environment so on.
	InsecureSkipVerify bool `hcl:"insecure_skip_verify"`
}

// TokenAuth represents parameters for token auth method
type TokenAuthConfig struct {
	// Token string to set into "X-Vault-Token" header
	Token string `hcl:"token"`
}

// CertAuth represents parameters for cert auth method
type CertAuthConfig struct {
	// Name of the mount point where Client Certificate Auth method is mounted. (e.g., /auth/<mount_point>/login)
	// If the value is empty, use default mount point (/auth/cert)
	CertAuthMountPoint string `hcl:"cert_auth_mount_point"`
	// Path to a client certificate file.
	// Only PEM format is supported.
	ClientCertPath string `hcl:"client_cert_path"`
	// Path to a client private key file.
	// Only PEM format is supported.
	ClientKeyPath string `hcl:"client_key_path"`
}

// AppRoleAuth represents parameters for AppRole auth method.
type AppRoleAuthConfig struct {
	// Name of the mount point where AppRole auth method is mounted. (e.g., /auth/<mount_point>/login)
	// If the value is empty, use default mount point (/auth/approle)
	AppRoleMountPoint string `hcl:"approle_auth_mount_point"`
	// An identifier that selects the AppRole
	RoleID string `hcl:"approle_id"`
	// A credential that is required for login.
	SecretID string `hcl:"approle_secret_id"`
}

type Plugin struct {
	mtx    *sync.RWMutex
	logger hclog.Logger
	vc     *Client
}

func New() *Plugin {
	return &Plugin{
		mtx: &sync.RWMutex{},
	}
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.logger = log
}

func (p *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := new(PluginConfig)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, fmt.Errorf("failed to decode configuration file: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	am, err := parseAuthMethod(config)
	if err != nil {
		return nil, err
	}

	cp := &ClientParams{
		VaultAddr:             getEnvOrDefault(envVaultAddr, config.VaultAddr),
		CACertPath:            getEnvOrDefault(envVaultCACert, config.CACertPath),
		Token:                 getEnvOrDefault(envVaultToken, config.TokenAuth.Token),
		PKIMountPoint:         config.PKIMountPoint,
		CertAuthMountPoint:    config.CertAuth.CertAuthMountPoint,
		ClientKeyPath:         getEnvOrDefault(envVaultClientKey, config.CertAuth.ClientKeyPath),
		ClientCertPath:        getEnvOrDefault(envVaultClientCert, config.CertAuth.ClientCertPath),
		AppRoleAuthMountPoint: config.AppRoleAuth.AppRoleMountPoint,
		AppRoleID:             getEnvOrDefault(envVaultAppRoleID, config.AppRoleAuth.RoleID),
		AppRoleSecretID:       getEnvOrDefault(envVaultAppRoleSecretID, config.AppRoleAuth.SecretID),
		TLSSKipVerify:         config.InsecureSkipVerify,
	}
	vcConfig, err := NewClientConfig(cp, p.logger)
	if err != nil {
		return nil, err
	}

	vc, err := vcConfig.NewAuthenticatedClient(am)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare vault authentication: %v", err)
	}

	p.vc = vc

	return &spi.ConfigureResponse{}, nil
}

func (p *Plugin) MintX509CA(req *upstreamauthority.MintX509CARequest, stream upstreamauthority.UpstreamAuthority_MintX509CAServer) error {
	var ttl string
	if req.PreferredTtl == 0 {
		ttl = ""
	} else {
		ttl = strconv.Itoa(int(req.PreferredTtl))
	}

	csr, err := x509.ParseCertificateRequest(req.GetCsr())
	if err != nil {
		return fmt.Errorf("failed to parse CSR data: %v", err)
	}

	signResp, err := p.vc.SignIntermediate(ttl, csr)
	if err != nil {
		return fmt.Errorf("failed to request signing the intermediate certificate: %v", err)
	}
	if signResp == nil {
		return errors.New("unexpected empty response from UpstreamAuthority")
	}

	// Parse PEM format data to get DER format data
	certificate, err := pemutil.ParseCertificate([]byte(signResp.CertPEM))
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}
	certChain := [][]byte{certificate.Raw}

	caCert, err := pemutil.ParseCertificate([]byte(signResp.CACertPEM))
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %v", err)
	}
	bundles := [][]byte{caCert.Raw}

	for _, c := range signResp.CACertChainPEM {
		if c == signResp.CACertPEM {
			continue
		}

		b, err := pemutil.ParseCertificate([]byte(c))
		if err != nil {
			return fmt.Errorf("failed to parse upstream bundle certificates: %v", err)
		}
		bundles = append(bundles, b.Raw)
	}

	return stream.Send(&upstreamauthority.MintX509CAResponse{
		X509CaChain:       certChain,
		UpstreamX509Roots: bundles,
	})
}

func (*Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// PublishJWTKey is not implemented by the wrapper and returns a codes.Unimplemented status
func (*Plugin) PublishJWTKey(*upstreamauthority.PublishJWTKeyRequest, upstreamauthority.UpstreamAuthority_PublishJWTKeyServer) error {
	return makeError(codes.Unimplemented, "publishing upstream is unsupported")
}

func makeError(code codes.Code, format string, args ...interface{}) error {
	return status.Errorf(code, "vault: "+format, args...)
}

func parseAuthMethod(config *PluginConfig) (AuthMethod, error) {
	if config.TokenAuth.Token != "" {
		return TOKEN, nil
	}
	if config.CertAuth.ClientCertPath != "" {
		return CERT, nil
	}
	if config.AppRoleAuth.RoleID != "" {
		return APPROLE, nil
	}

	return 0, errors.New("must be configured one of these authentication method 'Token or Cert or AppRole'")
}

func getEnvOrDefault(envKey, fallback string) string {
	if value, ok := os.LookupEnv(envKey); ok {
		return value
	}
	return fallback
}
