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
	defaultK8sAuthEndpoint          = "/v1/auth/kubernetes/login"
	defaultSignIntermediateEndpoint = "/v1/pki/root/sign-intermediate"
	defaultRenewEndpoint            = "/v1/auth/token/renew-self"
	defaultLookupSelfEndpoint       = "/v1/auth/token/lookup-self"

	listenAddr = "127.0.0.1:0"
)

var (
	testConfigWithVaultAddrEnvTpl = `
pki_mount_point = "test-pki"
ca_cert_path = "testdata/root-cert.pem"	
token_auth {
   token  = "test-token"
}`

	testCertAuthConfigTpl = `
vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "testdata/root-cert.pem"
cert_auth {
   cert_auth_mount_point = "test-cert-auth"
   cert_auth_role_name = "test"
   client_cert_path = "testdata/client-cert.pem"
   client_key_path  = "testdata/client-key.pem"
}`

	testCertAuthConfigWithEnvTpl = `
vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "testdata/root-cert.pem"
cert_auth {
   cert_auth_mount_point = "test-cert-auth"
}`

	/* #nosec G101 */
	testTokenAuthConfigTpl = `
vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "testdata/root-cert.pem"
token_auth {
   token  = "test-token"
}`

	/* #nosec G101 */
	testTokenAuthConfigWithEnvTpl = `
vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "testdata/root-cert.pem"
token_auth {}`

	testAppRoleAuthConfigTpl = `
vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "testdata/root-cert.pem"
approle_auth {
   approle_auth_mount_point = "test-approle-auth"
   approle_id = "test-approle-id"
   approle_secret_id  = "test-approle-secret-id"
}`

	testAppRoleAuthConfigWithEnvTpl = `
vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "testdata/root-cert.pem"
approle_auth {
   approle_auth_mount_point = "test-approle-auth"
}`

	testK8sAuthConfigTpl = `
vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "testdata/root-cert.pem"
k8s_auth {
   k8s_auth_mount_point = "test-k8s-auth"
   k8s_auth_role_name = "my-role"
   token_path = "testdata/k8s/token"
}`

	testK8sAuthNoRoleNameTpl = `
vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "testdata/root-cert.pem"
k8s_auth {
   k8s_auth_mount_point = "test-k8s-auth"
   token_path = "testdata/k8s/token"
}`

	/* #nosec G101 */
	testK8sAuthNoTokenPathTpl = `
vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "testdata/root-cert.pem"
k8s_auth {
   k8s_auth_mount_point = "test-k8s-auth"
   k8s_auth_role_name = "my-role"
}`

	testMultipleAuthConfigsTpl = `
vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "testdata/root-cert.pem"
cert_auth {}
token_auth {}
approle_auth {
	approle_auth_mount_point = "test-approle-auth"
	approle_id = "test-approle-id"
	approle_secret_id  = "test-approle-secret-id"
}`

	testNamespaceConfigTpl = `
namespace = "test-ns"
vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "testdata/root-cert.pem"
token_auth {
   token  = "test-token"
}
`
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

	testCertAuthResponseNotRenewable = `{
  "auth": {
    "client_token": "cf95f87d-f95b-47ff-b1f5-ba7bff850425",
    "policies": [
      "web",
      "stage"
    ],
    "lease_duration": 3600,
    "renewable": false
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

	testAppRoleAuthResponseNotRenewable = `{
  "auth": {
    "renewable": false,
    "lease_duration": 3600,
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

	testK8sAuthResponse = `{
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": null,
  "wrap_info": null,
  "warnings": null,
  "auth": {
    "client_token": "s.scngmDktKCWVRhkggMiyV7E7",
    "accessor": "",
    "policies": ["default"],
    "token_policies": ["default"],
    "metadata": {
      "role": "my-role",
      "service_account_name": "spire-server",
      "service_account_namespace": "spire",
      "service_account_secret_name": "",
      "service_account_uid": "6808b4c7-0b53-45f4-83f7-e8937756eeae"
    },
    "lease_duration": 3600,
    "renewable": true,
    "entity_id": "c69a6e0e-3f2c-98a0-39f9-e4d3d7cc294f",
    "token_type": "service",
    "orphan": true
  }
}
`

	testK8sAuthResponseNotRenewable = `{
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": null,
  "wrap_info": null,
  "warnings": null,
  "auth": {
    "client_token": "b.AAAAAQIUprvfquccAKnvL....",
    "accessor": "",
    "policies": ["default"],
    "token_policies": ["default"],
    "metadata": {
      "role": "my-role",
      "service_account_name": "spire-server",
      "service_account_namespace": "spire",
      "service_account_secret_name": "",
      "service_account_uid": "6808b4c7-0b53-45f4-83f7-e8937756eeae"
    },
    "lease_duration": 3600,
    "renewable": false,
    "entity_id": "c69a6e0e-3f2c-98a0-39f9-e4d3d7cc294f",
    "token_type": "batch",
    "orphan": true
  }
}`

	testLegacySignIntermediateResponse = `{
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "certificate": "-----BEGIN CERTIFICATE-----\nMIIBuTCCAWCgAwIBAgIUcu/nDfbzp9Lkejglw9Ydq5p4EKswCgYIKoZIzj0EAwIw\nPTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBlNQSUZGRTEdMBsGA1UEAwwUdGVzdC1p\nbnRlcm1lZGlhdGUtY2EwHhcNMjAxMjEwMDAwOTU4WhcNMzAxMjA4MDAwOTU4WjBD\nMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGU1BJRkZFMSMwIQYDVQQDDBp0ZXN0LWlu\ndGVybWVkaWF0ZS12YXVsdC1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHH3\ntT/1y6F4Vl6OGNugqQk7mnh2TAZSoszzI7paASkXUzNSfpwPhdK0JoIpolRq5Rkj\nv05PFwYjQzevFCJNiVCjODA2MCYGA1UdEQQfMB2GG3NwaWZmZTovL2ludGVybWVk\naWF0ZS12YXVsdDAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAv0nCyf\nlfxspBzobIsCY6Sso1YP5dmEknMKVb1X664vAiAqRjbY5ldxGRNi2paV0mRbxrUg\nPiy9LQzOiXrRvT5Thw==\n-----END CERTIFICATE-----",
    "issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIBmjCCAUCgAwIBAgIJAJQ2zT1xCwf9MAkGByqGSM49BAEwNTELMAkGA1UEBhMC\nVVMxDzANBgNVBAoMBlNQSUZGRTEVMBMGA1UEAwwMdGVzdC1yb290LWNhMB4XDTIw\nMDUyODA1NTgxOVoXDTMwMDUyNjA1NTgxOVowPTELMAkGA1UEBhMCVVMxDzANBgNV\nBAoMBlNQSUZGRTEdMBsGA1UEAwwUdGVzdC1pbnRlcm1lZGlhdGUtY2EwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAQl25uLXYCtUuC56HBfiuSPRihZh+XZFe1azAt8\nm4JFFQE0MKYBGmuv+dtxbb7S1DWDIWe+/TgnwPlvPZ2fG8H1ozIwMDAgBgNVHREE\nGTAXhhVzcGlmZmU6Ly9pbnRlcm1lZGlhdGUwDAYDVR0TBAUwAwEB/zAJBgcqhkjO\nPQQBA0kAMEYCIQC75fPz270uBP654XhWXTzAv+pEy2i3tUIbeinFXuhhYQIhAJdm\nEt2IvChBiw2vII7Be7LUQq20qF6YIWaZbIYVLwD3\n-----END CERTIFICATE-----",
    "ca_chain": ["-----BEGIN CERTIFICATE-----\nMIIBmjCCAUCgAwIBAgIJAJQ2zT1xCwf9MAkGByqGSM49BAEwNTELMAkGA1UEBhMC\nVVMxDzANBgNVBAoMBlNQSUZGRTEVMBMGA1UEAwwMdGVzdC1yb290LWNhMB4XDTIw\nMDUyODA1NTgxOVoXDTMwMDUyNjA1NTgxOVowPTELMAkGA1UEBhMCVVMxDzANBgNV\nBAoMBlNQSUZGRTEdMBsGA1UEAwwUdGVzdC1pbnRlcm1lZGlhdGUtY2EwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAQl25uLXYCtUuC56HBfiuSPRihZh+XZFe1azAt8\nm4JFFQE0MKYBGmuv+dtxbb7S1DWDIWe+/TgnwPlvPZ2fG8H1ozIwMDAgBgNVHREE\nGTAXhhVzcGlmZmU6Ly9pbnRlcm1lZGlhdGUwDAYDVR0TBAUwAwEB/zAJBgcqhkjO\nPQQBA0kAMEYCIQC75fPz270uBP654XhWXTzAv+pEy2i3tUIbeinFXuhhYQIhAJdm\nEt2IvChBiw2vII7Be7LUQq20qF6YIWaZbIYVLwD3\n-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\nMIIBjDCCATGgAwIBAgIJALZY6FEA9r6kMAoGCCqGSM49BAMCMDUxCzAJBgNVBAYT\nAlVTMQ8wDQYDVQQKDAZTUElGRkUxFTATBgNVBAMMDHRlc3Qtcm9vdC1jYTAeFw0y\nMDA1MjgwNTUxNTVaFw0zMDA1MjYwNTUxNTVaMDUxCzAJBgNVBAYTAlVTMQ8wDQYD\nVQQKDAZTUElGRkUxFTATBgNVBAMMDHRlc3Qtcm9vdC1jYTBZMBMGByqGSM49AgEG\nCCqGSM49AwEHA0IABO4U2vNH4ZuiexLCujPFh/r0fydL0Z+4JaVYh1Kx/m8KDFv7\ncaPNTZJwqNpZfvNxDO8YT0TGajLDmYI++/jZyBWjKjAoMBgGA1UdEQQRMA+GDXNw\naWZmZTovL3Jvb3QwDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAz+Pu\nb7yIGRTvWEj/ucQZXNnQc12GbWOPMO2dvA9I/BcCIQD0CeqIvkXunFMDy7SiyhgH\nvQpKl7ELFz1vtklgN2P8cg==\n-----END CERTIFICATE-----"],
    "serial_number": "39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58"
  },
  "auth": null
}`

	testSignIntermediateResponse = `{
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "certificate": "-----BEGIN CERTIFICATE-----\nMIIBuTCCAWCgAwIBAgIUcu/nDfbzp9Lkejglw9Ydq5p4EKswCgYIKoZIzj0EAwIw\nPTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBlNQSUZGRTEdMBsGA1UEAwwUdGVzdC1p\nbnRlcm1lZGlhdGUtY2EwHhcNMjAxMjEwMDAwOTU4WhcNMzAxMjA4MDAwOTU4WjBD\nMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGU1BJRkZFMSMwIQYDVQQDDBp0ZXN0LWlu\ndGVybWVkaWF0ZS12YXVsdC1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHH3\ntT/1y6F4Vl6OGNugqQk7mnh2TAZSoszzI7paASkXUzNSfpwPhdK0JoIpolRq5Rkj\nv05PFwYjQzevFCJNiVCjODA2MCYGA1UdEQQfMB2GG3NwaWZmZTovL2ludGVybWVk\naWF0ZS12YXVsdDAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAv0nCyf\nlfxspBzobIsCY6Sso1YP5dmEknMKVb1X664vAiAqRjbY5ldxGRNi2paV0mRbxrUg\nPiy9LQzOiXrRvT5Thw==\n-----END CERTIFICATE-----",
    "issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIBmjCCAUCgAwIBAgIJAJQ2zT1xCwf9MAkGByqGSM49BAEwNTELMAkGA1UEBhMC\nVVMxDzANBgNVBAoMBlNQSUZGRTEVMBMGA1UEAwwMdGVzdC1yb290LWNhMB4XDTIw\nMDUyODA1NTgxOVoXDTMwMDUyNjA1NTgxOVowPTELMAkGA1UEBhMCVVMxDzANBgNV\nBAoMBlNQSUZGRTEdMBsGA1UEAwwUdGVzdC1pbnRlcm1lZGlhdGUtY2EwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAQl25uLXYCtUuC56HBfiuSPRihZh+XZFe1azAt8\nm4JFFQE0MKYBGmuv+dtxbb7S1DWDIWe+/TgnwPlvPZ2fG8H1ozIwMDAgBgNVHREE\nGTAXhhVzcGlmZmU6Ly9pbnRlcm1lZGlhdGUwDAYDVR0TBAUwAwEB/zAJBgcqhkjO\nPQQBA0kAMEYCIQC75fPz270uBP654XhWXTzAv+pEy2i3tUIbeinFXuhhYQIhAJdm\nEt2IvChBiw2vII7Be7LUQq20qF6YIWaZbIYVLwD3\n-----END CERTIFICATE-----",
    "ca_chain": ["-----BEGIN CERTIFICATE-----\nMIIBuTCCAWCgAwIBAgIUcu/nDfbzp9Lkejglw9Ydq5p4EKswCgYIKoZIzj0EAwIw\nPTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBlNQSUZGRTEdMBsGA1UEAwwUdGVzdC1p\nbnRlcm1lZGlhdGUtY2EwHhcNMjAxMjEwMDAwOTU4WhcNMzAxMjA4MDAwOTU4WjBD\nMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGU1BJRkZFMSMwIQYDVQQDDBp0ZXN0LWlu\ndGVybWVkaWF0ZS12YXVsdC1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHH3\ntT/1y6F4Vl6OGNugqQk7mnh2TAZSoszzI7paASkXUzNSfpwPhdK0JoIpolRq5Rkj\nv05PFwYjQzevFCJNiVCjODA2MCYGA1UdEQQfMB2GG3NwaWZmZTovL2ludGVybWVk\naWF0ZS12YXVsdDAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAv0nCyf\nlfxspBzobIsCY6Sso1YP5dmEknMKVb1X664vAiAqRjbY5ldxGRNi2paV0mRbxrUg\nPiy9LQzOiXrRvT5Thw==\n-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\nMIIBmjCCAUCgAwIBAgIJAJQ2zT1xCwf9MAkGByqGSM49BAEwNTELMAkGA1UEBhMC\nVVMxDzANBgNVBAoMBlNQSUZGRTEVMBMGA1UEAwwMdGVzdC1yb290LWNhMB4XDTIw\nMDUyODA1NTgxOVoXDTMwMDUyNjA1NTgxOVowPTELMAkGA1UEBhMCVVMxDzANBgNV\nBAoMBlNQSUZGRTEdMBsGA1UEAwwUdGVzdC1pbnRlcm1lZGlhdGUtY2EwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAQl25uLXYCtUuC56HBfiuSPRihZh+XZFe1azAt8\nm4JFFQE0MKYBGmuv+dtxbb7S1DWDIWe+/TgnwPlvPZ2fG8H1ozIwMDAgBgNVHREE\nGTAXhhVzcGlmZmU6Ly9pbnRlcm1lZGlhdGUwDAYDVR0TBAUwAwEB/zAJBgcqhkjO\nPQQBA0kAMEYCIQC75fPz270uBP654XhWXTzAv+pEy2i3tUIbeinFXuhhYQIhAJdm\nEt2IvChBiw2vII7Be7LUQq20qF6YIWaZbIYVLwD3\n-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\nMIIBjDCCATGgAwIBAgIJALZY6FEA9r6kMAoGCCqGSM49BAMCMDUxCzAJBgNVBAYT\nAlVTMQ8wDQYDVQQKDAZTUElGRkUxFTATBgNVBAMMDHRlc3Qtcm9vdC1jYTAeFw0y\nMDA1MjgwNTUxNTVaFw0zMDA1MjYwNTUxNTVaMDUxCzAJBgNVBAYTAlVTMQ8wDQYD\nVQQKDAZTUElGRkUxFTATBgNVBAMMDHRlc3Qtcm9vdC1jYTBZMBMGByqGSM49AgEG\nCCqGSM49AwEHA0IABO4U2vNH4ZuiexLCujPFh/r0fydL0Z+4JaVYh1Kx/m8KDFv7\ncaPNTZJwqNpZfvNxDO8YT0TGajLDmYI++/jZyBWjKjAoMBgGA1UdEQQRMA+GDXNw\naWZmZTovL3Jvb3QwDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAz+Pu\nb7yIGRTvWEj/ucQZXNnQc12GbWOPMO2dvA9I/BcCIQD0CeqIvkXunFMDy7SiyhgH\nvQpKl7ELFz1vtklgN2P8cg==\n-----END CERTIFICATE-----"],
    "serial_number": "39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58"
  },
  "auth": null
}`

	testSignIntermediateResponseNoChain = `{
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "certificate": "-----BEGIN CERTIFICATE-----\nMIIBmjCCAUCgAwIBAgIJAJQ2zT1xCwf9MAkGByqGSM49BAEwNTELMAkGA1UEBhMC\nVVMxDzANBgNVBAoMBlNQSUZGRTEVMBMGA1UEAwwMdGVzdC1yb290LWNhMB4XDTIw\nMDUyODA1NTgxOVoXDTMwMDUyNjA1NTgxOVowPTELMAkGA1UEBhMCVVMxDzANBgNV\nBAoMBlNQSUZGRTEdMBsGA1UEAwwUdGVzdC1pbnRlcm1lZGlhdGUtY2EwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAQl25uLXYCtUuC56HBfiuSPRihZh+XZFe1azAt8\nm4JFFQE0MKYBGmuv+dtxbb7S1DWDIWe+/TgnwPlvPZ2fG8H1ozIwMDAgBgNVHREE\nGTAXhhVzcGlmZmU6Ly9pbnRlcm1lZGlhdGUwDAYDVR0TBAUwAwEB/zAJBgcqhkjO\nPQQBA0kAMEYCIQC75fPz270uBP654XhWXTzAv+pEy2i3tUIbeinFXuhhYQIhAJdm\nEt2IvChBiw2vII7Be7LUQq20qF6YIWaZbIYVLwD3\n-----END CERTIFICATE-----",
    "issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIBjDCCATGgAwIBAgIJALZY6FEA9r6kMAoGCCqGSM49BAMCMDUxCzAJBgNVBAYT\nAlVTMQ8wDQYDVQQKDAZTUElGRkUxFTATBgNVBAMMDHRlc3Qtcm9vdC1jYTAeFw0y\nMDA1MjgwNTUxNTVaFw0zMDA1MjYwNTUxNTVaMDUxCzAJBgNVBAYTAlVTMQ8wDQYD\nVQQKDAZTUElGRkUxFTATBgNVBAMMDHRlc3Qtcm9vdC1jYTBZMBMGByqGSM49AgEG\nCCqGSM49AwEHA0IABO4U2vNH4ZuiexLCujPFh/r0fydL0Z+4JaVYh1Kx/m8KDFv7\ncaPNTZJwqNpZfvNxDO8YT0TGajLDmYI++/jZyBWjKjAoMBgGA1UdEQQRMA+GDXNw\naWZmZTovL3Jvb3QwDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAz+Pu\nb7yIGRTvWEj/ucQZXNnQc12GbWOPMO2dvA9I/BcCIQD0CeqIvkXunFMDy7SiyhgH\nvQpKl7ELFz1vtklgN2P8cg==\n-----END CERTIFICATE-----",
    "serial_number": "39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58"
  },
  "auth": null
}`

	testSignMalformedCertificateResponse = `{
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "certificate": "malformed-cert",
    "issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIBjDCCATGgAwIBAgIJALZY6FEA9r6kMAoGCCqGSM49BAMCMDUxCzAJBgNVBAYT\nAlVTMQ8wDQYDVQQKDAZTUElGRkUxFTATBgNVBAMMDHRlc3Qtcm9vdC1jYTAeFw0y\nMDA1MjgwNTUxNTVaFw0zMDA1MjYwNTUxNTVaMDUxCzAJBgNVBAYTAlVTMQ8wDQYD\nVQQKDAZTUElGRkUxFTATBgNVBAMMDHRlc3Qtcm9vdC1jYTBZMBMGByqGSM49AgEG\nCCqGSM49AwEHA0IABO4U2vNH4ZuiexLCujPFh/r0fydL0Z+4JaVYh1Kx/m8KDFv7\ncaPNTZJwqNpZfvNxDO8YT0TGajLDmYI++/jZyBWjKjAoMBgGA1UdEQQRMA+GDXNw\naWZmZTovL3Jvb3QwDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAz+Pu\nb7yIGRTvWEj/ucQZXNnQc12GbWOPMO2dvA9I/BcCIQD0CeqIvkXunFMDy7SiyhgH\nvQpKl7ELFz1vtklgN2P8cg==\n-----END CERTIFICATE-----",
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

	testLookupSelfResponseNeverExpire = `{
  "request_id": "90e4b86a-5c61-1aeb-0fc7-50a05056c3b3",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "accessor": "rQuZeGOEdH4IazavJWqwTCRk",
    "creation_time": 1605502335,
    "creation_ttl": 0,
    "display_name": "root",
    "entity_id": "",
    "expire_time": null,
    "explicit_max_ttl": 0,
    "id": "test-token",
    "meta": null,
    "num_uses": 0,
    "orphan": true,
    "path": "auth/token/root",
    "policies": [
      "root"
    ],
    "ttl": 0,
    "type": "service"
  },
  "warnings": null
}`

	testLookupSelfResponse = `{
  "request_id": "8dc10d02-797d-1c23-f9f3-c7f07be89150",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "accessor": "sB3mNrjoIr2JscfNsAUM1k0A",
    "creation_time": 1605502988,
    "creation_ttl": 2764800,
    "display_name": "approle",
    "entity_id": "0bee5a2d-efe5-6fd3-9c5a-972266ecccf4",
    "expire_time": "2020-12-18T05:03:08.5694729Z",
    "explicit_max_ttl": 0,
    "id": "test-token",
    "issue_time": "2020-11-16T05:03:08.5694807Z",
    "meta": {
      "role_name": "test"
    },
    "num_uses": 0,
    "orphan": true,
    "path": "auth/approle/login",
    "policies": [
      "default"
    ],
    "renewable": true,
    "ttl": 3600,
    "type": "service"
  },
  "warnings": null
}`

	testLookupSelfResponseShortTTL = `{
  "request_id": "8dc10d02-797d-1c23-f9f3-c7f07be89150",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "accessor": "sB3mNrjoIr2JscfNsAUM1k0A",
    "creation_time": 1605502988,
    "creation_ttl": 2764800,
    "display_name": "approle",
    "entity_id": "0bee5a2d-efe5-6fd3-9c5a-972266ecccf4",
    "expire_time": "2020-12-18T05:03:08.5694729Z",
    "explicit_max_ttl": 0,
    "id": "test-token",
    "issue_time": "2020-11-16T05:03:08.5694807Z",
    "meta": {
      "role_name": "test"
    },
    "num_uses": 0,
    "orphan": true,
    "path": "auth/approle/login",
    "policies": [
      "default"
    ],
    "renewable": true,
    "ttl": 1,
    "type": "service"
  },
  "warnings": null
}`

	testLookupSelfResponseNotRenewable = `{
  "request_id": "ac39fad7-02d7-48df-2f8a-7a1872c41a4b",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "accessor": "",
    "creation_time": 1605506361,
    "creation_ttl": 3600,
    "display_name": "approle",
    "entity_id": "0bee5a2d-efe5-6fd3-9c5a-972266ecccf4",
    "expire_time": "2020-11-16T06:59:21Z",
    "explicit_max_ttl": 0,
    "id": "test-token",
    "issue_time": "2020-11-16T05:59:21Z",
    "meta": {
      "role_name": "test"
    },
    "num_uses": 0,
    "orphan": true,
    "path": "auth/approle/login",
    "policies": [
      "default"
    ],
    "renewable": false,
    "ttl": 3517,
    "type": "batch"
  },
  "warnings": null
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
	K8sAuthReqEndpoint           string
	K8sAuthReqHandler            func(code int, resp []byte) func(w http.ResponseWriter, r *http.Request)
	K8sAuthResponseCode          int
	K8sAuthResponse              []byte
	SignIntermediateReqEndpoint  string
	SignIntermediateReqHandler   func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	SignIntermediateResponseCode int
	SignIntermediateResponse     []byte
	RenewReqEndpoint             string
	RenewReqHandler              func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	RenewResponseCode            int
	RenewResponse                []byte
	LookupSelfReqEndpoint        string
	LookupSelfReqHandler         func(code int, resp []byte) func(w http.ResponseWriter, r *http.Request)
	LookupSelfResponseCode       int
	LookupSelfResponse           []byte
}

// NewFakeVaultServerConfig returns VaultServerConfig with default values
func NewFakeVaultServerConfig() *FakeVaultServerConfig {
	return &FakeVaultServerConfig{
		ListenAddr:                  listenAddr,
		CertAuthReqEndpoint:         defaultTLSAuthEndpoint,
		CertAuthReqHandler:          defaultReqHandler,
		AppRoleAuthReqEndpoint:      defaultAppRoleAuthEndpoint,
		AppRoleAuthReqHandler:       defaultReqHandler,
		K8sAuthReqEndpoint:          defaultK8sAuthEndpoint,
		K8sAuthReqHandler:           defaultReqHandler,
		SignIntermediateReqEndpoint: defaultSignIntermediateEndpoint,
		SignIntermediateReqHandler:  defaultReqHandler,
		RenewReqEndpoint:            defaultRenewEndpoint,
		RenewReqHandler:             defaultReqHandler,
		LookupSelfReqEndpoint:       defaultLookupSelfEndpoint,
		LookupSelfReqHandler:        defaultReqHandler,
	}
}

func defaultReqHandler(code int, resp []byte) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write(resp)
	}
}

func (v *FakeVaultServerConfig) NewTLSServer() (srv *httptest.Server, addr string, err error) {
	cert, err := tls.LoadX509KeyPair(testServerCert, testServerKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load key-pair: %w", err)
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	l, err := tls.Listen("tcp", v.ListenAddr, config)
	if err != nil {
		return nil, "", fmt.Errorf("failed to listen test server: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(v.CertAuthReqEndpoint, v.CertAuthReqHandler(v.CertAuthResponseCode, v.CertAuthResponse))
	mux.HandleFunc(v.AppRoleAuthReqEndpoint, v.AppRoleAuthReqHandler(v.AppRoleAuthResponseCode, v.AppRoleAuthResponse))
	mux.HandleFunc(v.K8sAuthReqEndpoint, v.AppRoleAuthReqHandler(v.K8sAuthResponseCode, v.K8sAuthResponse))
	mux.HandleFunc(v.SignIntermediateReqEndpoint, v.SignIntermediateReqHandler(v.SignIntermediateResponseCode, v.SignIntermediateResponse))
	mux.HandleFunc(v.RenewReqEndpoint, v.RenewReqHandler(v.RenewResponseCode, v.RenewResponse))
	mux.HandleFunc(v.LookupSelfReqEndpoint, v.LookupSelfReqHandler(v.LookupSelfResponseCode, v.LookupSelfResponse))

	srv = httptest.NewUnstartedServer(mux)
	srv.Listener = l
	return srv, l.Addr().String(), nil
}
