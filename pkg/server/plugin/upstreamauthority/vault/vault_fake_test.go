package vault

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
)

const (
	defaultTLSAuthEndpoint          = "/v1/auth/cert/login"
	defaultAppRoleAuthEndpoint      = "/v1/auth/approle/login"
	defaultSignIntermediateEndpoint = "/v1/pki/root/sign-intermediate"
	defaultRenewEndpoint            = "/v1/auth/token/renew-self"

	listenAddr = "127.0.0.1:0"
)

var (
	testCertAuthConfigTpl = `
vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "_test_data/keys/EC/root_cert.pem"
cert_auth {
   tls_auth_mount_point = "test-auth"
   client_cert_path = "_test_data/keys/EC/client_cert.pem"
   client_key_path  = "_test_data/keys/EC/client_key.pem"
}`
	/* #nosec G101 */
	testTokenAuthConfigTpl = `
vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "_test_data/keys/EC/root_cert.pem"
token_auth {
   token  = "test-token"
}`

	testAppRoleAuthConfigTpl = `
vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "_test_data/keys/EC/root_cert.pem"
approle_auth {
   approle_auth_mount_point = "test-auth"
   approle_id = "test-approle-id"
   approle_secret_id  = "test-approle-secret-id"
}`

	testCertAuthResponse = `{
  "auth": {
    "client_token": "cf95f87d-f95b-47ff-b1f5-ba7bff850425",
    "policies": [
      "web",
      "stage"
    ],
    "lease_duration": 3600,
    "renewable": true
  }
}`

	testAppRoleAuthResponse = `{
  "auth": {
    "renewable": true,
    "lease_duration": 1200,
    "metadata": null,
    "token_policies": [
      "default"
    ],
    "accessor": "fd6c9a00-d2dc-3b11-0be5-af7ae0e1d374",
    "client_token": "5b1a0318-679c-9c45-e5c6-d1b9a9035d49"
  },
  "warnings": null,
  "wrap_info": null,
  "data": null,
  "lease_duration": 0,
  "renewable": false,
  "lease_id": ""
}`

	testSignIntermediateResponse = `{
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "certificate": "-----BEGIN CERTIFICATE-----\nMIIBmjCCAUCgAwIBAgIJAJQ2zT1xCwf9MAkGByqGSM49BAEwNTELMAkGA1UEBhMC\nVVMxDzANBgNVBAoMBlNQSUZGRTEVMBMGA1UEAwwMdGVzdC1yb290LWNhMB4XDTIw\nMDUyODA1NTgxOVoXDTMwMDUyNjA1NTgxOVowPTELMAkGA1UEBhMCVVMxDzANBgNV\nBAoMBlNQSUZGRTEdMBsGA1UEAwwUdGVzdC1pbnRlcm1lZGlhdGUtY2EwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAQl25uLXYCtUuC56HBfiuSPRihZh+XZFe1azAt8\nm4JFFQE0MKYBGmuv+dtxbb7S1DWDIWe+/TgnwPlvPZ2fG8H1ozIwMDAgBgNVHREE\nGTAXhhVzcGlmZmU6Ly9pbnRlcm1lZGlhdGUwDAYDVR0TBAUwAwEB/zAJBgcqhkjO\nPQQBA0kAMEYCIQC75fPz270uBP654XhWXTzAv+pEy2i3tUIbeinFXuhhYQIhAJdm\nEt2IvChBiw2vII7Be7LUQq20qF6YIWaZbIYVLwD3\n-----END CERTIFICATE-----",
    "issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIBjDCCATGgAwIBAgIJALZY6FEA9r6kMAoGCCqGSM49BAMCMDUxCzAJBgNVBAYT\nAlVTMQ8wDQYDVQQKDAZTUElGRkUxFTATBgNVBAMMDHRlc3Qtcm9vdC1jYTAeFw0y\nMDA1MjgwNTUxNTVaFw0zMDA1MjYwNTUxNTVaMDUxCzAJBgNVBAYTAlVTMQ8wDQYD\nVQQKDAZTUElGRkUxFTATBgNVBAMMDHRlc3Qtcm9vdC1jYTBZMBMGByqGSM49AgEG\nCCqGSM49AwEHA0IABO4U2vNH4ZuiexLCujPFh/r0fydL0Z+4JaVYh1Kx/m8KDFv7\ncaPNTZJwqNpZfvNxDO8YT0TGajLDmYI++/jZyBWjKjAoMBgGA1UdEQQRMA+GDXNw\naWZmZTovL3Jvb3QwDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAz+Pu\nb7yIGRTvWEj/ucQZXNnQc12GbWOPMO2dvA9I/BcCIQD0CeqIvkXunFMDy7SiyhgH\nvQpKl7ELFz1vtklgN2P8cg==\n-----END CERTIFICATE-----",
    "ca_chain": ["-----BEGIN CERTIFICATE-----\nMIIBjDCCATGgAwIBAgIJALZY6FEA9r6kMAoGCCqGSM49BAMCMDUxCzAJBgNVBAYT\nAlVTMQ8wDQYDVQQKDAZTUElGRkUxFTATBgNVBAMMDHRlc3Qtcm9vdC1jYTAeFw0y\nMDA1MjgwNTUxNTVaFw0zMDA1MjYwNTUxNTVaMDUxCzAJBgNVBAYTAlVTMQ8wDQYD\nVQQKDAZTUElGRkUxFTATBgNVBAMMDHRlc3Qtcm9vdC1jYTBZMBMGByqGSM49AgEG\nCCqGSM49AwEHA0IABO4U2vNH4ZuiexLCujPFh/r0fydL0Z+4JaVYh1Kx/m8KDFv7\ncaPNTZJwqNpZfvNxDO8YT0TGajLDmYI++/jZyBWjKjAoMBgGA1UdEQQRMA+GDXNw\naWZmZTovL3Jvb3QwDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAz+Pu\nb7yIGRTvWEj/ucQZXNnQc12GbWOPMO2dvA9I/BcCIQD0CeqIvkXunFMDy7SiyhgH\nvQpKl7ELFz1vtklgN2P8cg==\n-----END CERTIFICATE-----"],
    "serial_number": "39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58"
  },
  "auth": null
}`

	testInvalidSignIntermediateResponse = `{
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "certificate": "invalid-pem",
    "issuing_ca": "invalid-pem",
    "ca_chain": ["invalid-pem"],
    "serial_number": "39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58"
  },
  "auth": null
}`

	testRenewResponse = `{
  "auth": {
    "client_token": "test-client-token",
    "policies": ["app", "test"],
    "metadata": {
      "user": "test"
    },
    "lease_duration": 3600,
    "renewable": true
  }
}`
)

type FakeVaultServerConfig struct {
	ListenAddr                   string
	ServerCertificatePemPath     string
	ServerKeyPemPath             string
	CertAuthReqEndpoint          string
	CertAuthReqHandler           func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	CertAuthResponseCode         int
	CertAuthResponse             []byte
	AppRoleAuthReqEndpoint       string
	AppRoleAuthReqHandler        func(code int, resp []byte) func(w http.ResponseWriter, r *http.Request)
	AppRoleAuthResponseCode      int
	AppRoleAuthResponse          []byte
	SignIntermediateReqEndpoint  string
	SignIntermediateReqHandler   func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	SignIntermediateResponseCode int
	SignIntermediateResponse     []byte
	RenewReqEndpoint             string
	RenewReqHandler              func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	RenewResponseCode            int
	RenewResponse                []byte
}

// NewFakeVaultServerConfig returns VaultServerConfig with default values
func NewFakeVaultServerConfig() *FakeVaultServerConfig {
	return &FakeVaultServerConfig{
		ListenAddr:                  listenAddr,
		CertAuthReqEndpoint:         defaultTLSAuthEndpoint,
		CertAuthReqHandler:          defaultReqHandler,
		AppRoleAuthReqEndpoint:      defaultAppRoleAuthEndpoint,
		AppRoleAuthReqHandler:       defaultReqHandler,
		SignIntermediateReqEndpoint: defaultSignIntermediateEndpoint,
		SignIntermediateReqHandler:  defaultReqHandler,
		RenewReqEndpoint:            defaultRenewEndpoint,
		RenewReqHandler:             defaultReqHandler,
	}
}

func defaultReqHandler(code int, resp []byte) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write(resp)
	}
}

func (v *FakeVaultServerConfig) NewTLSServer() (srv *httptest.Server, addr string, err error) {
	cert, err := tls.LoadX509KeyPair(v.ServerCertificatePemPath, v.ServerKeyPemPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load key-pair: %v", err)
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	l, err := tls.Listen("tcp", v.ListenAddr, config)
	if err != nil {
		return nil, "", fmt.Errorf("failed to listen test server: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(v.CertAuthReqEndpoint, v.CertAuthReqHandler(v.CertAuthResponseCode, v.CertAuthResponse))
	mux.HandleFunc(v.AppRoleAuthReqEndpoint, v.AppRoleAuthReqHandler(v.AppRoleAuthResponseCode, v.AppRoleAuthResponse))
	mux.HandleFunc(v.SignIntermediateReqEndpoint, v.SignIntermediateReqHandler(v.SignIntermediateResponseCode, v.SignIntermediateResponse))
	mux.HandleFunc(v.RenewReqEndpoint, v.RenewReqHandler(v.RenewResponseCode, v.RenewResponse))

	srv = httptest.NewUnstartedServer(mux)
	srv.Listener = l
	return srv, l.Addr().String(), nil
}
