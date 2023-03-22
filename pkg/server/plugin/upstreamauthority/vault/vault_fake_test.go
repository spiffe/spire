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
    "certificate": "-----BEGIN CERTIFICATE-----\nMIICfDCCAWSgAwIBAgIUNEOM6Ns91tqDtBURAX6naU33pZ4wDQYJKoZIhvcNAQEL\nBQAwKTEnMCUGA1UEAxMeaW50ZXJtZWRpYXRlLXZhdWx0LmV4YW1wbGUub3JnMB4X\nDTIzMDMxMzA5MjQ0NVoXDTIzMDQxNDA5MjUxNVowADBZMBMGByqGSM49AgEGCCqG\nSM49AwEHA0IABA4DozSzqny7jd3IoLr7TqjXha9zx7ScD0F9sidymrWqcvhF/62z\nIx1cdraOfLnRkPxHo0ydNuWQ4aEJ3Rpq2omjgY8wgYwwDgYDVR0PAQH/BAQDAgEG\nMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFM2By3VU8Wk5DDMEYHAoe26/yVdk\nMB8GA1UdIwQYMBaAFCgSvkCAWHGL8XRaDD8IMX0t7jzxMCkGA1UdEQEB/wQfMB2G\nG3NwaWZmZTovL2ludGVybWVkaWF0ZS1zcGlyZTANBgkqhkiG9w0BAQsFAAOCAQEA\nG413sV2mS341pWzV6a/M3Xn1U8DgNj/A6t9B2QlFyj6r6G3ohoNGhO01a3sbUvL9\n5EgDENXzTaBmqL03wi8h1Nt4fraUknA7SvpKMwNZq2DCR9tAN0qk6AO3mU6ffYfH\nwpIy38bwWpd3mYePuFrbOgcT+H3eXgXXzP5kZJ1hGisQS59at7ASy55hO+E9yD++\nTzFnotf4K0UAg7FouuoptRJjRN+hvk/G6WWpDMwwgY9kRafvasUWlakQhUrlVdu2\n6dvWNK/DtFMYZC6gxSSX6YzujNRX2ZqFkZZ5hNWyxa03bZMmO1kWc2SnM8upm8/S\n00YJUfwx7z1eJoMYW1gbCA==\n-----END CERTIFICATE-----",
    "issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIDbTCCAlWgAwIBAgIUKha0jl8Jr8FLCE8X2o0/J64RAxgwDQYJKoZIhvcNAQEL\nBQAwIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNhLmV4YW1wbGUub3JnMB4XDTIzMDMx\nMzA5MTMzN1oXDTI0MDMxMjA5MTQwN1owIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNh\nLmV4YW1wbGUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2cd\n9xNe3L47q1B0zN/c9UAO1RvHQhVdJ3/Ol5WywJH299TFD8h5w4HCz/RA+aZ800f4\ngFMKOjgVw9L23pj+agapCmn0VHmPevsK8GeLVKGcEzV3MxuJYYIG/4pO5FOVCZwQ\nS5bXmUyTYDPTJIHYmyx5DkZn5KguYp4+Rh2V49dOblhCrkjgmBQzELUKAVtBZQOJ\nkdd1360v6apNCuKK8RSND6P4FfqQNs6s++uwJTa9bUJwJOXxVSInhMRpwFwUEwiN\nzB+eKF4kRXptX5WN2MfwNTD8rOW/+5RStO8PpUCf6DFvMmWFNtI7HjC57GNSY3O+\nGGovWPaLs3vC2fpEjQIDAQABo4GYMIGVMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBRwaJ1ditU0lGtVmt2eHdUdqe6QzzAfBgNVHSME\nGDAWgBRwaJ1ditU0lGtVmt2eHdUdqe6QzzAyBgNVHREEKzApghh1cHN0ZXJlYW0t\nY2EuZXhhbXBsZS5vcmeGDXNwaWZmZTovL3Jvb3QwDQYJKoZIhvcNAQELBQADggEB\nAAYKliQ9zsvhj1iXZsR9tcPZLbbcxg3LhUv4/vhshi4dFsw/lnxFJAPztsHjN1UX\nNZEmH6cq0c/IptLF5DHND9f8ARjGmnfYdM1zHc8zWOaFsK7k7ei28LJzVi+hU08L\nGYLzjqqfo8r7pFMP7oA09HxLEKQ8+ClQAdxWXM4YBf6y4j3ITGNEOUJ8qwcgBCKo\n2mqvrtnjK4zIVY6FquKcZ/ad1JiukZJx0dR90kALDSQaMMM7D3j6AfVZnCPdpvlS\nyg1d+h+4BhccORIec1gdLhpqFaw9BL7jurmdW8JrhS2erJgvdBrU0jbbCxjlG0Z5\nuJCD3bCeSbi85pv/50z8Rwc=\n-----END CERTIFICATE-----",
    "ca_chain": ["-----BEGIN CERTIFICATE-----\nMIIDhzCCAm+gAwIBAgIUfewLoLsVae+9sTOCuCn4iFA7qicwDQYJKoZIhvcNAQEL\nBQAwIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNhLmV4YW1wbGUub3JnMB4XDTIzMDMx\nMzA5MjEzMloXDTI0MDMxMjA5MjIwMlowKTEnMCUGA1UEAxMeaW50ZXJtZWRpYXRl\nLXZhdWx0LmV4YW1wbGUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\nAQEAtH8znGP7/pFQpORyS87hhKIEOkjuzqi5W3cPbaRA1xJUObyD6XxAmE1U3avO\nMf0/xrC8gH/akLWcnOpbPrFQIG2inHgQeok1hw5t/g6GYTEB6IOic4NLyEaZQj3w\npp5LpxBwa7BUWvqOUwahYS802WU9UQAANBeN2WBEI11YbWQrmtSwsPt+vh1nB7rO\n/ON80hswxZ6b62Shfs7nEUqEhgs4cyWJ8l5MLr6O8envez/XaA3IYYq9LIGw7fNV\nroy0M3U9a9QgTWKHEyFFIGElFkR9+6RlH3lf5pavXN6zoe0J0O5i/9TwQB6z9JTi\n61kwVXkxtXV9kvikGwqwbrNKnwIDAQABo4GsMIGpMA4GA1UdDwEB/wQEAwIBBjAP\nBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQoEr5AgFhxi/F0Wgw/CDF9Le488TAf\nBgNVHSMEGDAWgBRwaJ1ditU0lGtVmt2eHdUdqe6QzzBGBgNVHREEPzA9gh5pbnRl\ncm1lZGlhdGUtdmF1bHQuZXhhbXBsZS5vcmeGG3NwaWZmZTovL2ludGVybWVkaWF0\nZS12YXVsdDANBgkqhkiG9w0BAQsFAAOCAQEAYaJGi+Tu9GgQuEatuTiWDLH0wFDw\nmMa14MEHOS6jB5y4muvh2NQDMHhPm67MZ1QftmJzE0t9S4BRI1Xdo3CmN8hNe8G9\nd/uz5/nKU4Gs4917q17HixAjv8WXZXzIlirc6bG1hEPpzKO+MBPRSvMkoDQ20v5A\nO3uWNVp0OSttsF29hTwsTn8X+4HQuEKxLcdUklJE19CL1Xb6Rgl9iR09/vCc9pI2\nYCbGUdE+fiEm1H3IvdbWBksCgh70ki4P9WCdpGCHMH3yHKNUh1vVjui3FVCJ+3uM\nuxple8U3JBdy+csIONgrun5OKGvYX1FKzdIingV+k7JrHOnnsfA+YyVTqg==\n-----END CERTIFICATE-----",      "-----BEGIN CERTIFICATE-----\nMIIDbTCCAlWgAwIBAgIUKha0jl8Jr8FLCE8X2o0/J64RAxgwDQYJKoZIhvcNAQEL\nBQAwIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNhLmV4YW1wbGUub3JnMB4XDTIzMDMx\nMzA5MTMzN1oXDTI0MDMxMjA5MTQwN1owIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNh\nLmV4YW1wbGUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2cd\n9xNe3L47q1B0zN/c9UAO1RvHQhVdJ3/Ol5WywJH299TFD8h5w4HCz/RA+aZ800f4\ngFMKOjgVw9L23pj+agapCmn0VHmPevsK8GeLVKGcEzV3MxuJYYIG/4pO5FOVCZwQ\nS5bXmUyTYDPTJIHYmyx5DkZn5KguYp4+Rh2V49dOblhCrkjgmBQzELUKAVtBZQOJ\nkdd1360v6apNCuKK8RSND6P4FfqQNs6s++uwJTa9bUJwJOXxVSInhMRpwFwUEwiN\nzB+eKF4kRXptX5WN2MfwNTD8rOW/+5RStO8PpUCf6DFvMmWFNtI7HjC57GNSY3O+\nGGovWPaLs3vC2fpEjQIDAQABo4GYMIGVMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBRwaJ1ditU0lGtVmt2eHdUdqe6QzzAfBgNVHSME\nGDAWgBRwaJ1ditU0lGtVmt2eHdUdqe6QzzAyBgNVHREEKzApghh1cHN0ZXJlYW0t\nY2EuZXhhbXBsZS5vcmeGDXNwaWZmZTovL3Jvb3QwDQYJKoZIhvcNAQELBQADggEB\nAAYKliQ9zsvhj1iXZsR9tcPZLbbcxg3LhUv4/vhshi4dFsw/lnxFJAPztsHjN1UX\nNZEmH6cq0c/IptLF5DHND9f8ARjGmnfYdM1zHc8zWOaFsK7k7ei28LJzVi+hU08L\nGYLzjqqfo8r7pFMP7oA09HxLEKQ8+ClQAdxWXM4YBf6y4j3ITGNEOUJ8qwcgBCKo\n2mqvrtnjK4zIVY6FquKcZ/ad1JiukZJx0dR90kALDSQaMMM7D3j6AfVZnCPdpvlS\nyg1d+h+4BhccORIec1gdLhpqFaw9BL7jurmdW8JrhS2erJgvdBrU0jbbCxjlG0Z5\nuJCD3bCeSbi85pv/50z8Rwc=\n-----END CERTIFICATE-----"],
    "serial_number": "39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58"
  },
  "auth": null
}`

	testSignIntermediateResponse = `{
  "request_id": "1c51ff06-a027-ce9f-e064-34889d122c18",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "ca_chain": [
      "-----BEGIN CERTIFICATE-----\nMIICfDCCAWSgAwIBAgIUNEOM6Ns91tqDtBURAX6naU33pZ4wDQYJKoZIhvcNAQEL\nBQAwKTEnMCUGA1UEAxMeaW50ZXJtZWRpYXRlLXZhdWx0LmV4YW1wbGUub3JnMB4X\nDTIzMDMxMzA5MjQ0NVoXDTIzMDQxNDA5MjUxNVowADBZMBMGByqGSM49AgEGCCqG\nSM49AwEHA0IABA4DozSzqny7jd3IoLr7TqjXha9zx7ScD0F9sidymrWqcvhF/62z\nIx1cdraOfLnRkPxHo0ydNuWQ4aEJ3Rpq2omjgY8wgYwwDgYDVR0PAQH/BAQDAgEG\nMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFM2By3VU8Wk5DDMEYHAoe26/yVdk\nMB8GA1UdIwQYMBaAFCgSvkCAWHGL8XRaDD8IMX0t7jzxMCkGA1UdEQEB/wQfMB2G\nG3NwaWZmZTovL2ludGVybWVkaWF0ZS1zcGlyZTANBgkqhkiG9w0BAQsFAAOCAQEA\nG413sV2mS341pWzV6a/M3Xn1U8DgNj/A6t9B2QlFyj6r6G3ohoNGhO01a3sbUvL9\n5EgDENXzTaBmqL03wi8h1Nt4fraUknA7SvpKMwNZq2DCR9tAN0qk6AO3mU6ffYfH\nwpIy38bwWpd3mYePuFrbOgcT+H3eXgXXzP5kZJ1hGisQS59at7ASy55hO+E9yD++\nTzFnotf4K0UAg7FouuoptRJjRN+hvk/G6WWpDMwwgY9kRafvasUWlakQhUrlVdu2\n6dvWNK/DtFMYZC6gxSSX6YzujNRX2ZqFkZZ5hNWyxa03bZMmO1kWc2SnM8upm8/S\n00YJUfwx7z1eJoMYW1gbCA==\n-----END CERTIFICATE-----",
      "-----BEGIN CERTIFICATE-----\nMIIDhzCCAm+gAwIBAgIUfewLoLsVae+9sTOCuCn4iFA7qicwDQYJKoZIhvcNAQEL\nBQAwIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNhLmV4YW1wbGUub3JnMB4XDTIzMDMx\nMzA5MjEzMloXDTI0MDMxMjA5MjIwMlowKTEnMCUGA1UEAxMeaW50ZXJtZWRpYXRl\nLXZhdWx0LmV4YW1wbGUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\nAQEAtH8znGP7/pFQpORyS87hhKIEOkjuzqi5W3cPbaRA1xJUObyD6XxAmE1U3avO\nMf0/xrC8gH/akLWcnOpbPrFQIG2inHgQeok1hw5t/g6GYTEB6IOic4NLyEaZQj3w\npp5LpxBwa7BUWvqOUwahYS802WU9UQAANBeN2WBEI11YbWQrmtSwsPt+vh1nB7rO\n/ON80hswxZ6b62Shfs7nEUqEhgs4cyWJ8l5MLr6O8envez/XaA3IYYq9LIGw7fNV\nroy0M3U9a9QgTWKHEyFFIGElFkR9+6RlH3lf5pavXN6zoe0J0O5i/9TwQB6z9JTi\n61kwVXkxtXV9kvikGwqwbrNKnwIDAQABo4GsMIGpMA4GA1UdDwEB/wQEAwIBBjAP\nBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQoEr5AgFhxi/F0Wgw/CDF9Le488TAf\nBgNVHSMEGDAWgBRwaJ1ditU0lGtVmt2eHdUdqe6QzzBGBgNVHREEPzA9gh5pbnRl\ncm1lZGlhdGUtdmF1bHQuZXhhbXBsZS5vcmeGG3NwaWZmZTovL2ludGVybWVkaWF0\nZS12YXVsdDANBgkqhkiG9w0BAQsFAAOCAQEAYaJGi+Tu9GgQuEatuTiWDLH0wFDw\nmMa14MEHOS6jB5y4muvh2NQDMHhPm67MZ1QftmJzE0t9S4BRI1Xdo3CmN8hNe8G9\nd/uz5/nKU4Gs4917q17HixAjv8WXZXzIlirc6bG1hEPpzKO+MBPRSvMkoDQ20v5A\nO3uWNVp0OSttsF29hTwsTn8X+4HQuEKxLcdUklJE19CL1Xb6Rgl9iR09/vCc9pI2\nYCbGUdE+fiEm1H3IvdbWBksCgh70ki4P9WCdpGCHMH3yHKNUh1vVjui3FVCJ+3uM\nuxple8U3JBdy+csIONgrun5OKGvYX1FKzdIingV+k7JrHOnnsfA+YyVTqg==\n-----END CERTIFICATE-----",
      "-----BEGIN CERTIFICATE-----\nMIIDbTCCAlWgAwIBAgIUKha0jl8Jr8FLCE8X2o0/J64RAxgwDQYJKoZIhvcNAQEL\nBQAwIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNhLmV4YW1wbGUub3JnMB4XDTIzMDMx\nMzA5MTMzN1oXDTI0MDMxMjA5MTQwN1owIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNh\nLmV4YW1wbGUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2cd\n9xNe3L47q1B0zN/c9UAO1RvHQhVdJ3/Ol5WywJH299TFD8h5w4HCz/RA+aZ800f4\ngFMKOjgVw9L23pj+agapCmn0VHmPevsK8GeLVKGcEzV3MxuJYYIG/4pO5FOVCZwQ\nS5bXmUyTYDPTJIHYmyx5DkZn5KguYp4+Rh2V49dOblhCrkjgmBQzELUKAVtBZQOJ\nkdd1360v6apNCuKK8RSND6P4FfqQNs6s++uwJTa9bUJwJOXxVSInhMRpwFwUEwiN\nzB+eKF4kRXptX5WN2MfwNTD8rOW/+5RStO8PpUCf6DFvMmWFNtI7HjC57GNSY3O+\nGGovWPaLs3vC2fpEjQIDAQABo4GYMIGVMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBRwaJ1ditU0lGtVmt2eHdUdqe6QzzAfBgNVHSME\nGDAWgBRwaJ1ditU0lGtVmt2eHdUdqe6QzzAyBgNVHREEKzApghh1cHN0ZXJlYW0t\nY2EuZXhhbXBsZS5vcmeGDXNwaWZmZTovL3Jvb3QwDQYJKoZIhvcNAQELBQADggEB\nAAYKliQ9zsvhj1iXZsR9tcPZLbbcxg3LhUv4/vhshi4dFsw/lnxFJAPztsHjN1UX\nNZEmH6cq0c/IptLF5DHND9f8ARjGmnfYdM1zHc8zWOaFsK7k7ei28LJzVi+hU08L\nGYLzjqqfo8r7pFMP7oA09HxLEKQ8+ClQAdxWXM4YBf6y4j3ITGNEOUJ8qwcgBCKo\n2mqvrtnjK4zIVY6FquKcZ/ad1JiukZJx0dR90kALDSQaMMM7D3j6AfVZnCPdpvlS\nyg1d+h+4BhccORIec1gdLhpqFaw9BL7jurmdW8JrhS2erJgvdBrU0jbbCxjlG0Z5\nuJCD3bCeSbi85pv/50z8Rwc=\n-----END CERTIFICATE-----"
    ],
    "certificate": "-----BEGIN CERTIFICATE-----\nMIICfDCCAWSgAwIBAgIUNEOM6Ns91tqDtBURAX6naU33pZ4wDQYJKoZIhvcNAQEL\nBQAwKTEnMCUGA1UEAxMeaW50ZXJtZWRpYXRlLXZhdWx0LmV4YW1wbGUub3JnMB4X\nDTIzMDMxMzA5MjQ0NVoXDTIzMDQxNDA5MjUxNVowADBZMBMGByqGSM49AgEGCCqG\nSM49AwEHA0IABA4DozSzqny7jd3IoLr7TqjXha9zx7ScD0F9sidymrWqcvhF/62z\nIx1cdraOfLnRkPxHo0ydNuWQ4aEJ3Rpq2omjgY8wgYwwDgYDVR0PAQH/BAQDAgEG\nMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFM2By3VU8Wk5DDMEYHAoe26/yVdk\nMB8GA1UdIwQYMBaAFCgSvkCAWHGL8XRaDD8IMX0t7jzxMCkGA1UdEQEB/wQfMB2G\nG3NwaWZmZTovL2ludGVybWVkaWF0ZS1zcGlyZTANBgkqhkiG9w0BAQsFAAOCAQEA\nG413sV2mS341pWzV6a/M3Xn1U8DgNj/A6t9B2QlFyj6r6G3ohoNGhO01a3sbUvL9\n5EgDENXzTaBmqL03wi8h1Nt4fraUknA7SvpKMwNZq2DCR9tAN0qk6AO3mU6ffYfH\nwpIy38bwWpd3mYePuFrbOgcT+H3eXgXXzP5kZJ1hGisQS59at7ASy55hO+E9yD++\nTzFnotf4K0UAg7FouuoptRJjRN+hvk/G6WWpDMwwgY9kRafvasUWlakQhUrlVdu2\n6dvWNK/DtFMYZC6gxSSX6YzujNRX2ZqFkZZ5hNWyxa03bZMmO1kWc2SnM8upm8/S\n00YJUfwx7z1eJoMYW1gbCA==\n-----END CERTIFICATE-----",
    "expiration": 1681464315,
    "issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIDhzCCAm+gAwIBAgIUfewLoLsVae+9sTOCuCn4iFA7qicwDQYJKoZIhvcNAQEL\nBQAwIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNhLmV4YW1wbGUub3JnMB4XDTIzMDMx\nMzA5MjEzMloXDTI0MDMxMjA5MjIwMlowKTEnMCUGA1UEAxMeaW50ZXJtZWRpYXRl\nLXZhdWx0LmV4YW1wbGUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\nAQEAtH8znGP7/pFQpORyS87hhKIEOkjuzqi5W3cPbaRA1xJUObyD6XxAmE1U3avO\nMf0/xrC8gH/akLWcnOpbPrFQIG2inHgQeok1hw5t/g6GYTEB6IOic4NLyEaZQj3w\npp5LpxBwa7BUWvqOUwahYS802WU9UQAANBeN2WBEI11YbWQrmtSwsPt+vh1nB7rO\n/ON80hswxZ6b62Shfs7nEUqEhgs4cyWJ8l5MLr6O8envez/XaA3IYYq9LIGw7fNV\nroy0M3U9a9QgTWKHEyFFIGElFkR9+6RlH3lf5pavXN6zoe0J0O5i/9TwQB6z9JTi\n61kwVXkxtXV9kvikGwqwbrNKnwIDAQABo4GsMIGpMA4GA1UdDwEB/wQEAwIBBjAP\nBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQoEr5AgFhxi/F0Wgw/CDF9Le488TAf\nBgNVHSMEGDAWgBRwaJ1ditU0lGtVmt2eHdUdqe6QzzBGBgNVHREEPzA9gh5pbnRl\ncm1lZGlhdGUtdmF1bHQuZXhhbXBsZS5vcmeGG3NwaWZmZTovL2ludGVybWVkaWF0\nZS12YXVsdDANBgkqhkiG9w0BAQsFAAOCAQEAYaJGi+Tu9GgQuEatuTiWDLH0wFDw\nmMa14MEHOS6jB5y4muvh2NQDMHhPm67MZ1QftmJzE0t9S4BRI1Xdo3CmN8hNe8G9\nd/uz5/nKU4Gs4917q17HixAjv8WXZXzIlirc6bG1hEPpzKO+MBPRSvMkoDQ20v5A\nO3uWNVp0OSttsF29hTwsTn8X+4HQuEKxLcdUklJE19CL1Xb6Rgl9iR09/vCc9pI2\nYCbGUdE+fiEm1H3IvdbWBksCgh70ki4P9WCdpGCHMH3yHKNUh1vVjui3FVCJ+3uM\nuxple8U3JBdy+csIONgrun5OKGvYX1FKzdIingV+k7JrHOnnsfA+YyVTqg==\n-----END CERTIFICATE-----",
    "serial_number": "34:43:8c:e8:db:3d:d6:da:83:b4:15:11:01:7e:a7:69:4d:f7:a5:9e"
  },
  "warnings": null
}`

	testLegacySignIntermediateResponseNoChain = `{
  "request_id": "637dc651-4311-34ab-3739-1e1dac4f4b3e",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "certificate": "-----BEGIN CERTIFICATE-----\nMIICfDCCAWSgAwIBAgIUNEOM6Ns91tqDtBURAX6naU33pZ4wDQYJKoZIhvcNAQEL\nBQAwKTEnMCUGA1UEAxMeaW50ZXJtZWRpYXRlLXZhdWx0LmV4YW1wbGUub3JnMB4X\nDTIzMDMxMzA5MjQ0NVoXDTIzMDQxNDA5MjUxNVowADBZMBMGByqGSM49AgEGCCqG\nSM49AwEHA0IABA4DozSzqny7jd3IoLr7TqjXha9zx7ScD0F9sidymrWqcvhF/62z\nIx1cdraOfLnRkPxHo0ydNuWQ4aEJ3Rpq2omjgY8wgYwwDgYDVR0PAQH/BAQDAgEG\nMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFM2By3VU8Wk5DDMEYHAoe26/yVdk\nMB8GA1UdIwQYMBaAFCgSvkCAWHGL8XRaDD8IMX0t7jzxMCkGA1UdEQEB/wQfMB2G\nG3NwaWZmZTovL2ludGVybWVkaWF0ZS1zcGlyZTANBgkqhkiG9w0BAQsFAAOCAQEA\nG413sV2mS341pWzV6a/M3Xn1U8DgNj/A6t9B2QlFyj6r6G3ohoNGhO01a3sbUvL9\n5EgDENXzTaBmqL03wi8h1Nt4fraUknA7SvpKMwNZq2DCR9tAN0qk6AO3mU6ffYfH\nwpIy38bwWpd3mYePuFrbOgcT+H3eXgXXzP5kZJ1hGisQS59at7ASy55hO+E9yD++\nTzFnotf4K0UAg7FouuoptRJjRN+hvk/G6WWpDMwwgY9kRafvasUWlakQhUrlVdu2\n6dvWNK/DtFMYZC6gxSSX6YzujNRX2ZqFkZZ5hNWyxa03bZMmO1kWc2SnM8upm8/S\n00YJUfwx7z1eJoMYW1gbCA==\n-----END CERTIFICATE-----",
    "expiration": 1710222128,
    "issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIDbTCCAlWgAwIBAgIUKha0jl8Jr8FLCE8X2o0/J64RAxgwDQYJKoZIhvcNAQEL\nBQAwIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNhLmV4YW1wbGUub3JnMB4XDTIzMDMx\nMzA5MTMzN1oXDTI0MDMxMjA5MTQwN1owIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNh\nLmV4YW1wbGUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2cd\n9xNe3L47q1B0zN/c9UAO1RvHQhVdJ3/Ol5WywJH299TFD8h5w4HCz/RA+aZ800f4\ngFMKOjgVw9L23pj+agapCmn0VHmPevsK8GeLVKGcEzV3MxuJYYIG/4pO5FOVCZwQ\nS5bXmUyTYDPTJIHYmyx5DkZn5KguYp4+Rh2V49dOblhCrkjgmBQzELUKAVtBZQOJ\nkdd1360v6apNCuKK8RSND6P4FfqQNs6s++uwJTa9bUJwJOXxVSInhMRpwFwUEwiN\nzB+eKF4kRXptX5WN2MfwNTD8rOW/+5RStO8PpUCf6DFvMmWFNtI7HjC57GNSY3O+\nGGovWPaLs3vC2fpEjQIDAQABo4GYMIGVMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBRwaJ1ditU0lGtVmt2eHdUdqe6QzzAfBgNVHSME\nGDAWgBRwaJ1ditU0lGtVmt2eHdUdqe6QzzAyBgNVHREEKzApghh1cHN0ZXJlYW0t\nY2EuZXhhbXBsZS5vcmeGDXNwaWZmZTovL3Jvb3QwDQYJKoZIhvcNAQELBQADggEB\nAAYKliQ9zsvhj1iXZsR9tcPZLbbcxg3LhUv4/vhshi4dFsw/lnxFJAPztsHjN1UX\nNZEmH6cq0c/IptLF5DHND9f8ARjGmnfYdM1zHc8zWOaFsK7k7ei28LJzVi+hU08L\nGYLzjqqfo8r7pFMP7oA09HxLEKQ8+ClQAdxWXM4YBf6y4j3ITGNEOUJ8qwcgBCKo\n2mqvrtnjK4zIVY6FquKcZ/ad1JiukZJx0dR90kALDSQaMMM7D3j6AfVZnCPdpvlS\nyg1d+h+4BhccORIec1gdLhpqFaw9BL7jurmdW8JrhS2erJgvdBrU0jbbCxjlG0Z5\nuJCD3bCeSbi85pv/50z8Rwc=\n-----END CERTIFICATE-----",
    "serial_number": "48:50:7b:3e:c5:8c:73:7d:34:eb:67:f9:db:fb:87:ac:88:1a:8b:57"
  },
  "auth": null 
}`

	testSignMalformedCertificateResponse = `{
  "request_id": "d66450b5-67e4-88dd-90d6-c50f0f576dce",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "ca_chain": [
      "malformed-cert",
      "-----BEGIN CERTIFICATE-----\nMIIDXjCCAkagAwIBAgIUJgYcK5K+iekHbdcC/uM0KMTUOV0wDQYJKoZIhvcNAQEL\nBQAwIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNhLmV4YW1wbGUub3JnMB4XDTIzMDMx\nMzA4MzQwOFoXDTI0MDMxMjA4MzQzOFowIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNh\nLmV4YW1wbGUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6K2a\nsB4XhQ4Hdvn8OoIh35GdWut2tAVAB9l384RNhkuNbIzwSxHYeSFobFO5S37PLehE\nS0NaIsJL/KXHRpoRo9fHME2FYnNfWH5OmbF4cHUqNsVe/q5If3gNoqcsfF24k58t\nbfrZhi6tZkSyvo7uGnQjvX6yHJaCgTHaAOxPshnflQHF1eK13EtQdW82md4m4IS1\ndyQADwVWeRihd/7CCvWyTdxMb84gS81fyWtKt7e4kHxWL3nO9acVs/W1YXk06BqS\ni/8WjXW31Bp9Th0rYBRvms9RlF5KZ+aJAwuhsZPsQVLGxeCG7vngwtw2/tHOTCaV\ncmQ8yVf9v8mNF/wASQIDAQABo4GJMIGGMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBSS42phwAI2yrON9BINagtzS1wwDTAfBgNVHSME\nGDAWgBSS42phwAI2yrON9BINagtzS1wwDTAjBgNVHREEHDAaghh1cHN0ZXJlYW0t\nY2EuZXhhbXBsZS5vcmcwDQYJKoZIhvcNAQELBQADggEBAJOCCLwqSo8zAt20m3zA\nWpaAaXdhj4NnI5Eq6R58M7nND4wnf3Mx2HgXrWhOr9FY1bxx5w2HBqfDWS/rDzpV\nH+JCq9eyBJtyCs2H96T50Hk1LJ5emyJ+RbhjyuqYIR8yAMji+dR/MO644NcnmWIC\neKJQvOafgutVmiaSTQCE04A3PtZXyFQU03XRu2sVbA/2ss+o0zXpqC39pPosCzmZ\nO01/XwlYFpqqD1mxlrwnO9QPSeIML0Yv3XEitr/1Ip0lgV20HvSewF3BMz6Jn/Ba\nE8totCyx5snSpKnzDSiooICeXgxVwvDboBtbzxAQ032Ix7qja0r5t9B8sMtnmJ1g\nyjc=\n-----END CERTIFICATE-----"
    ],
    "certificate": "malformed-cert",
    "expiration": 1681461388,
    "issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIDXjCCAkagAwIBAgIUJgYcK5K+iekHbdcC/uM0KMTUOV0wDQYJKoZIhvcNAQEL\nBQAwIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNhLmV4YW1wbGUub3JnMB4XDTIzMDMx\nMzA4MzQwOFoXDTI0MDMxMjA4MzQzOFowIzEhMB8GA1UEAxMYdXBzdGVyZWFtLWNh\nLmV4YW1wbGUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6K2a\nsB4XhQ4Hdvn8OoIh35GdWut2tAVAB9l384RNhkuNbIzwSxHYeSFobFO5S37PLehE\nS0NaIsJL/KXHRpoRo9fHME2FYnNfWH5OmbF4cHUqNsVe/q5If3gNoqcsfF24k58t\nbfrZhi6tZkSyvo7uGnQjvX6yHJaCgTHaAOxPshnflQHF1eK13EtQdW82md4m4IS1\ndyQADwVWeRihd/7CCvWyTdxMb84gS81fyWtKt7e4kHxWL3nO9acVs/W1YXk06BqS\ni/8WjXW31Bp9Th0rYBRvms9RlF5KZ+aJAwuhsZPsQVLGxeCG7vngwtw2/tHOTCaV\ncmQ8yVf9v8mNF/wASQIDAQABo4GJMIGGMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBSS42phwAI2yrON9BINagtzS1wwDTAfBgNVHSME\nGDAWgBSS42phwAI2yrON9BINagtzS1wwDTAjBgNVHREEHDAaghh1cHN0ZXJlYW0t\nY2EuZXhhbXBsZS5vcmcwDQYJKoZIhvcNAQELBQADggEBAJOCCLwqSo8zAt20m3zA\nWpaAaXdhj4NnI5Eq6R58M7nND4wnf3Mx2HgXrWhOr9FY1bxx5w2HBqfDWS/rDzpV\nH+JCq9eyBJtyCs2H96T50Hk1LJ5emyJ+RbhjyuqYIR8yAMji+dR/MO644NcnmWIC\neKJQvOafgutVmiaSTQCE04A3PtZXyFQU03XRu2sVbA/2ss+o0zXpqC39pPosCzmZ\nO01/XwlYFpqqD1mxlrwnO9QPSeIML0Yv3XEitr/1Ip0lgV20HvSewF3BMz6Jn/Ba\nE8totCyx5snSpKnzDSiooICeXgxVwvDboBtbzxAQ032Ix7qja0r5t9B8sMtnmJ1g\nyjc=\n-----END CERTIFICATE-----",
    "serial_number": "07:cc:af:eb:e1:86:59:ef:16:2a:1d:af:54:90:e4:49:62:66:f8:71"
  },
  "warnings": null
}`

	testInvalidSignIntermediateResponse = `{
  "request_id": "637dc651-4311-34ab-3739-1e1dac4f4b3e",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "certificate": "invalid-pem",
    "expiration": 1710222128,
    "issuing_ca": "invalid-pem",
    "ca_chain": ["invalid-pem"],
    "serial_number": "48:50:7b:3e:c5:8c:73:7d:34:eb:67:f9:db:fb:87:ac:88:1a:8b:57"
  },
  "warnings":  null
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
