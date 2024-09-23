// Package sshpop implements ssh proof of possession based node attestation.
package sshpop

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"golang.org/x/crypto/ssh"
)

const (
	// PluginName is used for identifying this plugin type for protobuf blobs.
	PluginName = "sshpop"

	defaultHostKeyPath  = "/etc/ssh/ssh_host_rsa_key"
	defaultHostCertPath = "/etc/ssh/ssh_host_rsa_key-cert.pub"
	nonceLen            = 32
)

var (
	// DefaultAgentPathTemplate is the default text/template.
	DefaultAgentPathTemplate = agentpathtemplate.MustParse("/{{ .PluginName}}/{{ .Fingerprint }}")
)

// agentPathTemplateData is used to hydrate the agent path template used in generating spiffe ids.
type agentPathTemplateData struct {
	*ssh.Certificate
	PluginName  string
	Fingerprint string
	Hostname    string
}

// Client is a factory for generating client handshake objects.
type Client struct {
	cert   *ssh.Certificate
	signer ssh.Signer
}

// Server is a factory for generating server handshake objects.
type Server struct {
	certChecker       *ssh.CertChecker
	agentPathTemplate *agentpathtemplate.Template
	trustDomain       spiffeid.TrustDomain
	canonicalDomain   string
}

// ClientConfig configures the client.
type ClientConfig struct {
	HostKeyPath  string `hcl:"host_key_path"`
	HostCertPath string `hcl:"host_cert_path"`

	cert   *ssh.Certificate
	signer ssh.Signer
}

type ClientConfigRequest struct {
	coreConfig *configv1.CoreConfiguration
	hclText    string
}

func (ccr *ClientConfigRequest) GetCoreConfiguration() *configv1.CoreConfiguration {
	return ccr.coreConfig
}

func (ccr *ClientConfigRequest) GetHclConfiguration() string {
	return ccr.hclText
}

type ServerConfigRequest struct {
	coreConfig *configv1.CoreConfiguration
	hclText    string
}

func (scr *ServerConfigRequest) GetCoreConfiguration() *configv1.CoreConfiguration {
	return scr.coreConfig
}

func (scr *ServerConfigRequest) GetHclConfiguration() string {
	return scr.hclText
}

// ServerConfig configures the server.
type ServerConfig struct {
	CertAuthorities     []string `hcl:"cert_authorities"`
	CertAuthoritiesPath string   `hcl:"cert_authorities_path"`
	// CanonicalDomain specifies the domain suffix for validating the hostname against
	// the certificate's valid principals. See CanonicalDomains in ssh_config(5).
	CanonicalDomain   string `hcl:"canonical_domain"`
	AgentPathTemplate string `hcl:"agent_path_template"`

	certChecker       *ssh.CertChecker
	agentPathTemplate *agentpathtemplate.Template
	trustDomain       spiffeid.TrustDomain
}

func BuildServerConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *ServerConfig {
	newConfig := new(ServerConfig)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("failed to decode configuration: %v", err)
		return nil
	}

	newConfig.trustDomain = coreConfig.TrustDomain

	if newConfig.CertAuthorities == nil && newConfig.CertAuthoritiesPath == "" {
		status.ReportErrorf("missing required config value for \"cert_authorities\" or \"cert_authorities_path\"")
	}
	var certAuthorities []string
	if newConfig.CertAuthorities != nil {
		certAuthorities = append(certAuthorities, newConfig.CertAuthorities...)
	}
	if newConfig.CertAuthoritiesPath != "" {
		fileCertAuthorities, err := pubkeysFromPath(newConfig.CertAuthoritiesPath)
		if err != nil {
			status.ReportErrorf("failed to get cert authorities from file: %v", err)
		}
		certAuthorities = append(certAuthorities, fileCertAuthorities...)
	}

	certChecker, err := certCheckerFromPubkeys(certAuthorities)
	if err != nil {
		status.ReportErrorf("failed to create cert checker: %v", err)
	}
	newConfig.certChecker = certChecker

	newConfig.agentPathTemplate = DefaultAgentPathTemplate
	if len(newConfig.AgentPathTemplate) != 0 {
		tmpl, err := agentpathtemplate.Parse(newConfig.AgentPathTemplate)
		if err != nil {
			status.ReportErrorf("failed to parse agent svid template: %q", newConfig.AgentPathTemplate)
		} else {
			newConfig.agentPathTemplate = tmpl
		}
	}

	return newConfig
}

func (sc *ServerConfig) NewServer() *Server {
	return &Server{
		certChecker:       sc.certChecker,
		agentPathTemplate: sc.agentPathTemplate,
		trustDomain:       sc.trustDomain,
		canonicalDomain:   sc.CanonicalDomain,
	}
}

func BuildClientConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *ClientConfig {
	newConfig := new(ClientConfig)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("failed to decode configuration: %v", err)
		return nil
	}

	newConfig.HostKeyPath = stringOrDefault(newConfig.HostKeyPath, defaultHostKeyPath)
	newConfig.HostCertPath = stringOrDefault(newConfig.HostCertPath, defaultHostCertPath)

	keyBytes, err := os.ReadFile(newConfig.HostKeyPath)
	if err != nil {
		status.ReportErrorf("failed to read host key file: %v", err)
	}
	certBytes, err := os.ReadFile(newConfig.HostCertPath)
	if err != nil {
		status.ReportErrorf("failed to read host cert file: %v", err)
	}
	if keyBytes != nil && certBytes != nil {
		cert, signer, err := getCertAndSignerFromBytes(certBytes, keyBytes)
		if err != nil {
			status.ReportErrorf("failed to get cert and signer from pem: %v", err)
		}
		newConfig.cert = cert
		newConfig.signer = signer
	}

	return newConfig
}

func (cc *ClientConfig) NewClient() *Client {
	return &Client{
		cert:   cc.cert,
		signer: cc.signer,
	}
}

func NewClient(trustDomain string, configString string) (*Client, error) {
	request := &ClientConfigRequest{
		coreConfig: &configv1.CoreConfiguration{
			TrustDomain: fmt.Sprintf("spiffe://%s", trustDomain),
		},
		hclText: configString,
	}

	newClientConfig, _, err := pluginconf.Build(request, BuildClientConfig)
	if err != nil {
		return nil, err
	}

	return newClientConfig.NewClient(), nil
}

func stringOrDefault(configValue, defaultValue string) string {
	if configValue == "" {
		return defaultValue
	}
	return configValue
}

func getCertAndSignerFromBytes(certBytes, keyBytes []byte) (*ssh.Certificate, ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, nil, err
	}
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, nil, err
	}
	cert, ok := pubkey.(*ssh.Certificate)
	if !ok {
		return nil, nil, errors.New("pubkey isn't a certificate")
	}
	return cert, signer, nil
}

func NewServer(trustDomain, configString string) (*Server, error) {
	request := &ServerConfigRequest{
		coreConfig: &configv1.CoreConfiguration{
			TrustDomain: trustDomain,
		},
		hclText: configString,
	}

	newServerConfig, _, err := pluginconf.Build(request, BuildServerConfig)
	if err != nil {
		return nil, err
	}

	return newServerConfig.NewServer(), nil
}

func pubkeysFromPath(pubkeysPath string) ([]string, error) {
	pubkeysBytes, err := os.ReadFile(pubkeysPath)
	if err != nil {
		return nil, err
	}
	splitPubkeys := strings.Split(string(pubkeysBytes), "\n")
	var pubkeys []string
	for _, pubkey := range splitPubkeys {
		if pubkey == "" {
			continue
		}
		pubkeys = append(pubkeys, pubkey)
	}
	if pubkeys == nil {
		return nil, fmt.Errorf("no data found in file: %q", pubkeysPath)
	}
	return pubkeys, nil
}

func certCheckerFromPubkeys(certAuthorities []string) (*ssh.CertChecker, error) {
	if len(certAuthorities) == 0 {
		return nil, errors.New("must provide at least one cert authority")
	}
	authorities := make(map[string]bool)
	for _, certAuthority := range certAuthorities {
		authority, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certAuthority))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key %q: %w", certAuthority, err)
		}
		authorities[ssh.FingerprintSHA256(authority)] = true
	}
	return &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return authorities[ssh.FingerprintSHA256(auth)]
		},
	}, nil
}

func (c *Client) NewHandshake() *ClientHandshake {
	return &ClientHandshake{
		c: c,
	}
}

func (s *Server) NewHandshake() *ServerHandshake {
	return &ServerHandshake{
		s: s,
	}
}
