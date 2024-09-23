package ejbca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"

	ejbcaclient "github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// This compile-time assertion ensures the plugin conforms properly to the
	// pluginsdk.NeedsLogger interface.
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

const (
	pluginName = "ejbca"
)

type newEjbcaAuthenticatorFunc func(*Config) (ejbcaclient.Authenticator, error)
type getEnvFunc func(string) string
type readFileFunc func(string) ([]byte, error)

// Plugin implements the UpstreamAuthority plugin
type Plugin struct {
	// UnimplementedUpstreamAuthorityServer is embedded to satisfy gRPC
	upstreamauthorityv1.UnimplementedUpstreamAuthorityServer

	// UnimplementedConfigServer is embedded to satisfy gRPC
	configv1.UnimplementedConfigServer

	config    *Config
	configMtx sync.RWMutex

	// The logger received from the framework via the SetLogger method
	logger hclog.Logger

	client ejbcaClient

	hooks struct {
		newAuthenticator newEjbcaAuthenticatorFunc
		getEnv           getEnvFunc
		readFile         readFileFunc
	}
}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		upstreamauthorityv1.UpstreamAuthorityPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// Config defines the configuration for the plugin.
type Config struct {
	Hostname               string `hcl:"hostname" json:"hostname"`
	CaCertPath             string `hcl:"ca_cert_path" json:"ca_cert_path"`
	ClientCertPath         string `hcl:"client_cert_path" json:"client_cert_path"`
	ClientCertKeyPath      string `hcl:"client_cert_key_path" json:"client_cert_key_path"`
	CAName                 string `hcl:"ca_name" json:"ca_name"`
	EndEntityProfileName   string `hcl:"end_entity_profile_name" json:"end_entity_profile_name"`
	CertificateProfileName string `hcl:"certificate_profile_name" json:"certificate_profile_name"`
	DefaultEndEntityName   string `hcl:"end_entity_name" json:"end_entity_name"`
	AccountBindingID       string `hcl:"account_binding_id" json:"account_binding_id"`
}

func (p *Plugin) buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Config {
	logger := p.logger.Named("parseConfig")
	logger.Debug("Decoding EJBCA configuration")

	newConfig := &Config{}
	if err := hcl.Decode(&newConfig, hclText); err != nil {
		status.ReportErrorf("failed to decode configuration: %v", err)
		return nil
	}

	if newConfig.Hostname == "" {
		status.ReportError("hostname is required")
	}
	if newConfig.CAName == "" {
		status.ReportError("ca_name is required")
	}
	if newConfig.EndEntityProfileName == "" {
		status.ReportError("end_entity_profile_name is required")
	}
	if newConfig.CertificateProfileName == "" {
		status.ReportError("certificate_profile_name is required")
	}

	// If ClientCertPath or ClientCertKeyPath were not found in the main server conf file,
	// load them from the environment.
	if newConfig.ClientCertPath == "" {
		newConfig.ClientCertPath = p.hooks.getEnv("EJBCA_CLIENT_CERT_PATH")
	}
	if newConfig.ClientCertKeyPath == "" {
		newConfig.ClientCertKeyPath = p.hooks.getEnv("EJBCA_CLIENT_CERT_KEY_PATH")
	}

	// If ClientCertPath or ClientCertKeyPath were not present in either the conf file or
	// the environment, return an error.
	if newConfig.ClientCertPath == "" {
		logger.Error("Client certificate is required for mTLS authentication")
		status.ReportError("client_cert or EJBCA_CLIENT_CERT_PATH is required for mTLS authentication")
	}
	if newConfig.ClientCertKeyPath == "" {
		logger.Error("Client key is required for mTLS authentication")
		status.ReportError("client_key or EJBCA_CLIENT_KEY_PATH is required for mTLS authentication")
	}

	if newConfig.CaCertPath == "" {
		newConfig.CaCertPath = p.hooks.getEnv("EJBCA_CA_CERT_PATH")
	}

	return newConfig
}

// New returns an instantiated EJBCA UpstreamAuthority plugin
func New() *Plugin {
	p := &Plugin{}
	p.hooks.newAuthenticator = p.getAuthenticator
	p.hooks.getEnv = os.Getenv
	p.hooks.readFile = os.ReadFile
	return p
}

// Configure configures the EJBCA UpstreamAuthority plugin. This is invoked by SPIRE when the plugin is
// first loaded. After the first invocation, it may be used to reconfigure the plugin.
func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, p.buildConfig)
	if err != nil {
		return nil, err
	}

	authenticator, err := p.hooks.newAuthenticator(newConfig)
	if err != nil {
		return nil, err
	}

	client, err := p.newEjbcaClient(newConfig, authenticator)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to create EJBCA client: %v", err)
	}

	p.setConfig(newConfig)
	p.setClient(client)
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, p.buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

// SetLogger is called by the framework when the plugin is loaded and provides
// the plugin with a logger wired up to SPIRE's logging facilities.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

// MintX509CAAndSubscribe implements the UpstreamAuthority MintX509CAAndSubscribe RPC. Mints an X.509 CA and responds
// with the signed X.509 CA certificate chain and upstream X.509 roots. The stream is kept open but new roots will
// not be published unless the CA is rotated and a new X.509 CA is minted.
//
// Implementation note:
//   - It's important that the EJBCA Certificate Profile and End Entity Profile are properly configured before
//     using this plugin. The plugin does not attempt to configure these profiles.
func (p *Plugin) MintX509CAAndSubscribe(req *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	var err error
	if p.client == nil {
		return status.Error(codes.FailedPrecondition, "ejbca upstreamauthority is not configured")
	}

	logger := p.logger.Named("MintX509CAAndSubscribe")
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	logger.Debug("Parsing CSR from request")
	parsedCsr, err := x509.ParseCertificateRequest(req.Csr)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to parse CSR: %v", err)
	}
	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.Csr})

	logger.Debug("Determining end entity name")
	endEntityName, err := p.getEndEntityName(config, parsedCsr)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to determine end entity name: %v", err)
	}

	logger.Debug("Preparing EJBCA enrollment request")
	password, err := generateRandomString(16)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to generate random password: %v", err)
	}
	enrollConfig := ejbcaclient.NewEnrollCertificateRestRequest()
	enrollConfig.SetUsername(endEntityName)
	enrollConfig.SetPassword(password)

	// Configure the request using local state and the CSR
	enrollConfig.SetCertificateRequest(string(csrPem))
	enrollConfig.SetCertificateAuthorityName(config.CAName)
	enrollConfig.SetCertificateProfileName(config.CertificateProfileName)
	enrollConfig.SetEndEntityProfileName(config.EndEntityProfileName)
	enrollConfig.SetIncludeChain(true)
	enrollConfig.SetAccountBindingId(config.AccountBindingID)

	logger.Debug("Prepared EJBCA enrollment request", "subject", parsedCsr.Subject.String(), "uriSANs", parsedCsr.URIs, "endEntityName", endEntityName, "caName", config.CAName, "certificateProfileName", config.CertificateProfileName, "endEntityProfileName", config.EndEntityProfileName, "accountBindingId", config.AccountBindingID)

	logger.Info("Enrolling certificate with EJBCA")
	enrollResponse, httpResponse, err := p.client.EnrollPkcs10Certificate(stream.Context()).
		EnrollCertificateRestRequest(*enrollConfig).
		Execute()
	if err != nil {
		return p.parseEjbcaError("failed to enroll CSR", err)
	}
	if httpResponse != nil && httpResponse.Body != nil {
		httpResponse.Body.Close()
	}

	var certBytes []byte
	var caBytes []byte
	switch {
	case enrollResponse.GetResponseFormat() == "PEM":
		logger.Debug("EJBCA returned certificate in PEM format - serializing")

		block, _ := pem.Decode([]byte(enrollResponse.GetCertificate()))
		if block == nil {
			return status.Error(codes.Internal, "failed to parse certificate PEM")
		}
		certBytes = block.Bytes

		for _, ca := range enrollResponse.CertificateChain {
			block, _ := pem.Decode([]byte(ca))
			if block == nil {
				return status.Error(codes.Internal, "failed to parse CA certificate PEM")
			}
			caBytes = append(caBytes, block.Bytes...)
		}
	case enrollResponse.GetResponseFormat() == "DER":
		logger.Debug("EJBCA returned certificate in DER format - serializing")

		bytes, err := base64.StdEncoding.DecodeString(enrollResponse.GetCertificate())
		if err != nil {
			return status.Errorf(codes.Internal, "failed to base64 decode DER certificate: %v", err)
		}
		certBytes = append(certBytes, bytes...)

		for _, ca := range enrollResponse.CertificateChain {
			bytes, err := base64.StdEncoding.DecodeString(ca)
			if err != nil {
				return status.Errorf(codes.Internal, "failed to base64 decode DER CA certificate: %v", err)
			}
			caBytes = append(caBytes, bytes...)
		}
	default:
		return status.Errorf(codes.Internal, "ejbca returned unsupported certificate format: %q", enrollResponse.GetResponseFormat())
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to serialize certificate issued by EJBCA: %v", err)
	}

	caChain, err := x509.ParseCertificates(caBytes)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to serialize CA chain returned by EJBCA: %v", err)
	}

	if len(caChain) == 0 {
		return status.Error(codes.Internal, "EJBCA did not return a CA chain")
	}

	rootCa := caChain[len(caChain)-1]
	logger.Debug("Retrieved root CA from CA chain", "rootCa", rootCa.Subject.String(), "intermediates", len(caChain)-1)

	// x509CertificateChain contains the leaf CA certificate, then any intermediates up to but not including the root CA.
	x509CertificateAuthorityChain, err := x509certificate.ToPluginFromCertificates(append([]*x509.Certificate{cert}, caChain[:len(caChain)-1]...))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to serialize certificate chain: %v", err)
	}

	rootCACertificate, err := x509certificate.ToPluginFromCertificates([]*x509.Certificate{rootCa})
	if err != nil {
		return status.Errorf(codes.Internal, "failed to serialize upstream X.509 roots: %v", err)
	}

	return stream.Send(&upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       x509CertificateAuthorityChain,
		UpstreamX509Roots: rootCACertificate,
	})
}

// The EJBCA UpstreamAuthority plugin does not support publishing JWT keys.
func (p *Plugin) PublishJWTKeyAndSubscribe(_ *upstreamauthorityv1.PublishJWTKeyRequest, _ upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	return status.Error(codes.Unimplemented, "publishing JWT keys is not supported by the EJBCA UpstreamAuthority plugin")
}

// setConfig replaces the configuration atomically under a write lock.
func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	p.config = config
	p.configMtx.Unlock()
}

// getConfig gets the configuration under a read lock.
func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

// setClient replaces the client atomically under a write lock.
func (p *Plugin) setClient(client ejbcaClient) {
	p.configMtx.Lock()
	p.client = client
	p.configMtx.Unlock()
}

// getEndEntityName calculates the End Entity Name based on the default_end_entity_name from the EJBCA UpstreamAuthority
// configuration. The possible values are:
// - cn: Uses the Common Name from the CSR's Distinguished Name.
// - dns: Uses the first DNS Name from the CSR's Subject Alternative Names (SANs).
// - uri: Uses the first URI from the CSR's Subject Alternative Names (SANs).
// - ip: Uses the first IP Address from the CSR's Subject Alternative Names (SANs).
// - Custom Value: Any other string will be directly used as the End Entity Name.
// If the default_end_entity_name is not set, the plugin will determine the End Entity Name in the same order as above.
func (p *Plugin) getEndEntityName(config *Config, csr *x509.CertificateRequest) (string, error) {
	logger := p.logger.Named("getEndEntityName")

	eeName := ""
	// 1. If the endEntityName option is set, determine the end entity name based on the option
	// 2. If the endEntityName option is not set, determine the end entity name based on the CSR

	// cn: Use the CommonName from the CertificateRequest's DN
	if config.DefaultEndEntityName == "cn" || config.DefaultEndEntityName == "" {
		if csr.Subject.CommonName != "" {
			eeName = csr.Subject.CommonName
			logger.Debug("Using CommonName from the CSR's DN as the EJBCA end entity name", "endEntityName", eeName)
			return eeName, nil
		}
	}

	// dns: Use the first DNSName from the CertificateRequest's DNSNames SANs
	if config.DefaultEndEntityName == "dns" || config.DefaultEndEntityName == "" {
		if len(csr.DNSNames) > 0 && csr.DNSNames[0] != "" {
			eeName = csr.DNSNames[0]
			logger.Debug("Using the first DNSName from the CSR's DNSNames SANs as the EJBCA end entity name", "endEntityName", eeName)
			return eeName, nil
		}
	}

	// uri: Use the first URI from the CertificateRequest's URI Sans
	if config.DefaultEndEntityName == "uri" || config.DefaultEndEntityName == "" {
		if len(csr.URIs) > 0 {
			eeName = csr.URIs[0].String()
			logger.Debug("Using the first URI from the CSR's URI Sans as the EJBCA end entity name", "endEntityName", eeName)
			return eeName, nil
		}
	}

	// ip: Use the first IPAddress from the CertificateRequest's IPAddresses SANs
	if config.DefaultEndEntityName == "ip" || config.DefaultEndEntityName == "" {
		if len(csr.IPAddresses) > 0 {
			eeName = csr.IPAddresses[0].String()
			logger.Debug("Using the first IPAddress from the CSR's IPAddresses SANs as the EJBCA end entity name", "endEntityName", eeName)
			return eeName, nil
		}
	}

	// End of defaults; if the endEntityName option is set to anything but cn, dns, or uri, use the option as the end entity name
	if config.DefaultEndEntityName != "" && config.DefaultEndEntityName != "cn" && config.DefaultEndEntityName != "dns" && config.DefaultEndEntityName != "uri" {
		eeName = config.DefaultEndEntityName
		logger.Debug("Using the default_end_entity_name config value as the EJBCA end entity name", "endEntityName", eeName)
		return eeName, nil
	}

	// If we get here, we were unable to determine the end entity name
	logger.Error(fmt.Sprintf("the endEntityName option is set to %q, but no valid end entity name could be determined from the CertificateRequest", config.DefaultEndEntityName))

	return "", fmt.Errorf("no valid end entity name could be determined from the CertificateRequest")
}

// parseEjbcaError parses an error returned by the EJBCA API and returns a gRPC status error.
func (p *Plugin) parseEjbcaError(detail string, err error) error {
	if err == nil {
		return nil
	}
	logger := p.logger.Named("parseEjbcaError")
	errString := fmt.Sprintf("%s - %s", detail, err.Error())

	ejbcaError := &ejbcaclient.GenericOpenAPIError{}
	if errors.As(err, &ejbcaError) {
		errString += fmt.Sprintf(" - EJBCA API returned error %s", ejbcaError.Body())
	}

	logger.Error("EJBCA returned an error", "error", errString)

	return status.Errorf(codes.Internal, "EJBCA returned an error: %s", errString)
}

// generateRandomString generates a random string of the specified length
func generateRandomString(length int) (string, error) {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		b[i] = letters[num.Int64()]
	}
	return string(b), nil
}
