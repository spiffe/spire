// Package sshpop implements ssh proof of posession based node attestation.
package sshpop

import (
	"errors"
	"fmt"
	"io/ioutil"
	"text/template"

	"github.com/hashicorp/hcl"
	"github.com/zeebo/errs"
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
	DefaultAgentPathTemplate = template.Must(template.New("agent-path").Parse("{{ .PluginName}}/{{ .Fingerprint }}"))

	// sshpop-specific error class
	errClass = errs.Class(PluginName)
)

// agentPathTemplateData is used to hydrate the agent path template used in generating spiffe ids.
type agentPathTemplateData struct {
	*ssh.Certificate
	PluginName  string
	Fingerprint string
}

// Client is a factory for generating client handshake objects.
type Client struct {
	cert              *ssh.Certificate
	signer            ssh.Signer
	agentPathTemplate *template.Template
	trustDomain       string
}

// Server is a factory for generating server handshake objects.
type Server struct {
	certChecker       *ssh.CertChecker
	agentPathTemplate *template.Template
	trustDomain       string
}

// ClientConfig configures the client.
type ClientConfig struct {
	HostKeyPath       string `hcl:"host_key_path"`
	HostCertPath      string `hcl:"host_cert_path"`
	AgentPathTemplate string `hcl:"agent_path_template"`
}

// ServerConfig configures the server.
type ServerConfig struct {
	CertAuthorities   []string `hcl:"cert_authorities"`
	AgentPathTemplate string   `hcl:"agent_path_template"`
}

func NewClient(trustDomain, configString string) (*Client, error) {
	if trustDomain == "" {
		return nil, Errorf("trust_domain global configuration is required")
	}
	config := new(ClientConfig)
	if err := hcl.Decode(config, configString); err != nil {
		return nil, Errorf("failed to decode configuration: %v", err)
	}
	config.HostKeyPath = stringOrDefault(config.HostKeyPath, defaultHostKeyPath)
	config.HostCertPath = stringOrDefault(config.HostCertPath, defaultHostCertPath)
	keyBytes, err := ioutil.ReadFile(config.HostKeyPath)
	if err != nil {
		return nil, Errorf("failed to read host key file: %v", err)
	}
	certBytes, err := ioutil.ReadFile(config.HostCertPath)
	if err != nil {
		return nil, Errorf("failed to read host cert file: %v", err)
	}
	cert, signer, err := getCertAndSignerFromBytes(certBytes, keyBytes)
	if err != nil {
		return nil, Errorf("failed to get cert and signer from pem: %v", err)
	}
	agentPathTemplate := DefaultAgentPathTemplate
	if len(config.AgentPathTemplate) > 0 {
		tmpl, err := template.New("agent-path").Parse(config.AgentPathTemplate)
		if err != nil {
			return nil, Errorf("failed to parse agent svid template: %q", config.AgentPathTemplate)
		}
		agentPathTemplate = tmpl
	}
	return &Client{
		cert:              cert,
		signer:            signer,
		agentPathTemplate: agentPathTemplate,
		trustDomain:       trustDomain,
	}, nil
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
	if trustDomain == "" {
		return nil, Errorf("trust_domain global configuration is required")
	}
	config := new(ServerConfig)
	if err := hcl.Decode(config, configString); err != nil {
		return nil, Errorf("failed to decode configuration: %v", err)
	}
	if config.CertAuthorities == nil {
		return nil, Errorf("missing required config value for \"cert_authorities\"")
	}
	certChecker, err := certCheckerFromPubkeys(config.CertAuthorities)
	if err != nil {
		return nil, Errorf("failed to create cert checker: %v", err)
	}
	agentPathTemplate := DefaultAgentPathTemplate
	if len(config.AgentPathTemplate) > 0 {
		tmpl, err := template.New("agent-path").Parse(config.AgentPathTemplate)
		if err != nil {
			return nil, fmt.Errorf("failed to parse agent svid template: %q", config.AgentPathTemplate)
		}
		agentPathTemplate = tmpl
	}
	return &Server{
		certChecker:       certChecker,
		agentPathTemplate: agentPathTemplate,
		trustDomain:       trustDomain,
	}, nil
}

func certCheckerFromPubkeys(certAuthorities []string) (*ssh.CertChecker, error) {
	if len(certAuthorities) == 0 {
		return nil, errors.New("must provide at least one cert authority")
	}
	authorities := make(map[string]bool)
	for _, certAuthority := range certAuthorities {
		authority, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certAuthority))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key %q: %v", certAuthority, err)
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

// Errorf is a ssh plugin specific error.
func Errorf(format string, a ...interface{}) error {
	return errClass.New(format, a...)
}
