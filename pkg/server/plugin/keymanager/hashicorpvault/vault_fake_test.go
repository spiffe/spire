package hashicorpvault

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
)

const (
	defaultTLSAuthEndpoint     = "PUT /v1/auth/cert/login"
	defaultAppRoleAuthEndpoint = "PUT /v1/auth/approle/login"
	defaultK8sAuthEndpoint     = "PUT /v1/auth/kubernetes/login"
	defaultRenewEndpoint       = "POST /v1/auth/token/renew-self"
	defaultLookupSelfEndpoint  = "GET /v1/auth/token/lookup-self"
	defaultCreateKeyEndpoint   = "PUT /v1/transit/keys/{id}"
	defaultGetKeyEndpoint      = "GET /v1/transit/keys/{id}"
	defaultGetKeysEndpoint     = "GET /v1/transit/keys"
	defaultSignDataEndpoint    = "PUT /v1/transit/sign/{id}/{algo}"

	listenAddr = "127.0.0.1:0"
)

var (
	testTokenAuthConfigTpl = `
key_identifier_file = "{{ .KeyIdentifierFile }}"
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
token_auth {
   token  = "test-token"
}`

	testTokenAuthConfigWithEnvTpl = `
key_identifier_file = "{{ .KeyIdentifierFile }}"
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
token_auth {}`

	testCertAuthConfigTpl = `
key_identifier_file = "{{ .KeyIdentifierFile }}"
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
cert_auth {
   cert_auth_mount_point = "test-cert-auth"
   cert_auth_role_name = "test"
   client_cert_path = "testdata/client-cert.pem"
   client_key_path  = "testdata/client-key.pem"
}`

	testCertAuthConfigWithEnvTpl = `
key_identifier_file = "{{ .KeyIdentifierFile }}"
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
cert_auth {
   cert_auth_mount_point = "test-cert-auth"
}`

	testAppRoleAuthConfigTpl = `
key_identifier_file = "{{ .KeyIdentifierFile }}"
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
approle_auth {
   approle_auth_mount_point = "test-approle-auth"
   approle_id = "test-approle-id"
   approle_secret_id  = "test-approle-secret-id"
}`

	testAppRoleAuthConfigWithEnvTpl = `
key_identifier_file = "{{ .KeyIdentifierFile }}"
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
approle_auth {
   approle_auth_mount_point = "test-approle-auth"
}`

	testK8sAuthConfigTpl = `
key_identifier_file = "{{ .KeyIdentifierFile }}"
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
k8s_auth {
   k8s_auth_mount_point = "test-k8s-auth"
   k8s_auth_role_name = "my-role"
   token_path = "testdata/k8s/token"
}`

	testMultipleAuthConfigsTpl = `
key_identifier_file = "{{ .KeyIdentifierFile }}"
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
cert_auth {}
token_auth {}
approle_auth {
	approle_auth_mount_point = "test-approle-auth"
	approle_id = "test-approle-id"
	approle_secret_id  = "test-approle-secret-id"
}`

	testConfigWithTransitEnginePathTpl = `
key_identifier_file = "{{ .KeyIdentifierFile }}"
transit_engine_path = "test-path"
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
token_auth {
   token  = "test-token"
}`

	testConfigWithTransitEnginePathEnvTpl = `
key_identifier_file = "{{ .KeyIdentifierFile }}"
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
token_auth {
   token  = "test-token"
}`

	testNamespaceConfigTpl = `
key_identifier_file = "{{ .KeyIdentifierFile }}"
namespace = "test-ns"
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
token_auth {
   token  = "test-token"
}`

	testNamespaceEnvTpl = `
key_identifier_file = "{{ .KeyIdentifierFile }}"
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
token_auth {
   token  = "test-token"
}`

	testK8sAuthNoRoleNameTpl = `
key_identifier_file = "{{ .KeyIdentifierFile }}"
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
k8s_auth {
   k8s_auth_mount_point = "test-k8s-auth"
   token_path = "testdata/k8s/token"
}`

	testK8sAuthNoTokenPathTpl = `
key_identifier_file = "{{ .KeyIdentifierFile }}"
vault_addr  = "{{ .Addr }}"
ca_cert_path = "testdata/root-cert.pem"
k8s_auth {
   k8s_auth_mount_point = "test-k8s-auth"
   k8s_auth_role_name = "my-role"
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

	testGetKeysResponseOneKey = `{
  "request_id": "3d02d2cf-baa4-a4ca-90d8-448b6c3ce6b0",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "keys": [
      "x509-CA-A"
    ]
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}`

	testGetKeysResponseNoKeys = `{
  "request_id": "3d02d2cf-baa4-a4ca-90d8-448b6c3ce6b0",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "keys": []
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}`

	testGetKeyResponseP256 = `{
  "request_id": "646eddbd-83fd-0cc1-387b-f1a17fa88c3d",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "allow_plaintext_backup": false,
    "auto_rotate_period": 0,
    "deletion_allowed": false,
    "derived": false,
    "exportable": false,
    "imported_key": false,
    "keys": {
      "1": {
        "creation_time": "2024-09-16T18:18:54.284635756Z",
        "name": "P-256",
        "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV57LFbIQZzyZ2YcKZfB9mGWkUhJv\niRzIZOqV4wRHoUOZjMuhBMR2WviEsy65TYpcBjreAc6pbneiyhlTwPvgmw==\n-----END PUBLIC KEY-----\n"
      }
    },
    "latest_version": 1,
    "min_available_version": 0,
    "min_decryption_version": 1,
    "min_encryption_version": 0,
    "name": "x509-CA-A",
    "supports_decryption": false,
    "supports_derivation": false,
    "supports_encryption": false,
    "supports_signing": true,
    "type": "ecdsa-p256"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}`

	testGetKeyResponseP384 = `{
  "request_id": "a97c3069-1369-dcbb-c687-a431f8d7f324",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "allow_plaintext_backup": false,
    "auto_rotate_period": 0,
    "deletion_allowed": false,
    "derived": false,
    "exportable": false,
    "imported_key": false,
    "keys": {
      "1": {
        "creation_time": "2024-09-17T18:27:19.664989473Z",
        "name": "P-384",
        "public_key": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEXpDQLh6ct/CJuMV2UIXnm/GilDNgy6Qy\ngzGhGsRaGrlYtM8g3sSHoGBIR+wT2hIF0ryY4mqYPtzw39WiHSdK3J985iX/bMXD\npr5xe142+1uHbJdKfSD5LrycBBtIsoEH\n-----END PUBLIC KEY-----\n"
      }
    },
    "latest_version": 1,
    "min_available_version": 0,
    "min_decryption_version": 1,
    "min_encryption_version": 0,
    "name": "x509-CA-A",
    "supports_decryption": false,
    "supports_derivation": false,
    "supports_encryption": false,
    "supports_signing": true,
    "type": "ecdsa-p384"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}`

	testGetKeyResponseRSA2048 = `{
  "request_id": "7a74d33f-2e4b-8f34-48ba-80ff1c0a447c",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "allow_plaintext_backup": false,
    "auto_rotate_period": 0,
    "deletion_allowed": false,
    "derived": false,
    "exportable": false,
    "imported_key": false,
    "keys": {
      "1": {
        "creation_time": "2024-09-17T18:30:26.427076525Z",
        "name": "rsa-2048",
        "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnV4uS61DWBvfbpzuHzIQ\nRbPZfLbe5wolynACSBNB4DxskuAZOg27e9wKUVwg82gOFPM4t1mVMHYee2OqEspZ\n5zL6y5bfwK//F+H8B6egitPKcHIv6WtErCrl3NM7V8jv4JIxmSeLRFNLpsGPp2dc\nZ/Q/SwprFhMfBiskCmOf+FlOrLZXe7a6Wsfe2yTJIwC5zGn+jNPVBmscHqjzttME\n4/xoZxCg13uZa1rskIOW526RT7ccfIMo8qGoZ0KVjnAJGuTwhFvJ+D/jwhHDylsP\n1ngHgJlBnDo23GouQD13TRaRUamTb4sliRAFdrWwK3j9YaOgtJnBYikkG1T/SSsm\nMQIDAQAB\n-----END PUBLIC KEY-----\n"
      }
    },
    "latest_version": 1,
    "min_available_version": 0,
    "min_decryption_version": 1,
    "min_encryption_version": 0,
    "name": "x509-CA-A",
    "supports_decryption": true,
    "supports_derivation": false,
    "supports_encryption": true,
    "supports_signing": true,
    "type": "rsa-2048"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}`

	testGetKeyResponseRSA4096 = `{
  "request_id": "486c49b6-149a-7886-52c6-5d082d4329fc",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "allow_plaintext_backup": false,
    "auto_rotate_period": 0,
    "deletion_allowed": false,
    "derived": false,
    "exportable": false,
    "imported_key": false,
    "keys": {
      "1": {
        "creation_time": "2024-09-17T18:34:21.286589438Z",
        "name": "rsa-4096",
        "public_key": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsmp4dJSfPGDGhmWoBD7G\nYPBQ/KGCR8/huy7/bjNRprKKpnhDl+4y5OaQVUqvFnoJZYfQvowcaGrARwBrsvPw\nkwPe6dB33XZBCWWDIvMORAQhgGeQF0MRjKibxDxlwPLZLARnHF8674gDdbL7Tg/G\nxQqThWNqVk6/GiHnAjkBntyw3V5XI5RtmpdSLDcZOUdqh/Bwi6fGOwtW1kU2NVSG\nalhdQu1O2Pr72sVZ/9+LwMYv1ZI0lFULwr7ZaIo86+vei4BIk+Pd/kkOjn9KKJD1\n84eL1QnN03XPc9ENCt7rF/R+IT7YkoqCDBZawW6VpexrA6QxtxUO0DcAffIFJ61Z\n9N7p3VULjZZIJmpOaMTEu3wFritcTBZweI3gikisg3YMqRDzC97+WqKUGpWUfGcF\ngENRvqIlE05snmmwziGB4Rey3yAqZBHSXRWFWKdDX/X7gMEJ4Av7hAumMxgR34If\ndzEShW6ushnOEtlXQR0/DE814GBWI0+oa+w9m20XkzL60bUIZevP9mOhbSNxuN8m\naCDOjIa7qeX3yg1l4+dnAZ/S8O+K3GEWkqWwq/FXH1EfCGeztp2b0pN8n0r0Tr3S\nHkHMNNEXovlQevgEFEc01Kg8PXBDd1hP31dfMfZ6v+BXygGHg95zR4AFpcRIYJWu\n9dmMkmMWQN5rZeyDO7ZfDQ0CAwEAAQ==\n-----END PUBLIC KEY-----\n"
      }
    },
    "latest_version": 1,
    "min_available_version": 0,
    "min_decryption_version": 1,
    "min_encryption_version": 0,
    "name": "x509-CA-A",
    "supports_decryption": true,
    "supports_derivation": false,
    "supports_encryption": true,
    "supports_signing": true,
    "type": "rsa-4096"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}`

	testGetKeyResponseMalformed = `{
  "request_id": "486c49b6-149a-7886-52c6-5d082d4329fc",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "allow_plaintext_backup": false,
    "auto_rotate_period": 0,
    "deletion_allowed": false,
    "derived": false,
    "exportable": false,
    "imported_key": false,
    "keys": {
      "1": {
        "creation_time": "2024-09-17T18:34:21.286589438Z",
        "name": "rsa-4096",
        "public_key": "-----BEGIN MALFORMED KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsmp4dJSfPGDGhmWoBD7G\nYPBQ/KGCR8/huy7/bjNRprKKpnhDl+4y5OaQVUqvFnoJZYfQvowcaGrARwBrsvPw\nkwPe6dB33XZBCWWDIvMORAQhgGeQF0MRjKibxDxlwPLZLARnHF8674gDdbL7Tg/G\nxQqThWNqVk6/GiHnAjkBntyw3V5XI5RtmpdSLDcZOUdqh/Bwi6fGOwtW1kU2NVSG\nalhdQu1O2Pr72sVZ/9+LwMYv1ZI0lFULwr7ZaIo86+vei4BIk+Pd/kkOjn9KKJD1\n84eL1QnN03XPc9ENCt7rF/R+IT7YkoqCDBZawW6VpexrA6QxtxUO0DcAffIFJ61Z\n9N7p3VULjZZIJmpOaMTEu3wFritcTBZweI3gikisg3YMqRDzC97+WqKUGpWUfGcF\ngENRvqIlE05snmmwziGB4Rey3yAqZBHSXRWFWKdDX/X7gMEJ4Av7hAumMxgR34If\ndzEShW6ushnOEtlXQR0/DE814GBWI0+oa+w9m20XkzL60bUIZevP9mOhbSNxuN8m\naCDOjIa7qeX3yg1l4+dnAZ/S8O+K3GEWkqWwq/FXH1EfCGeztp2b0pN8n0r0Tr3S\nHkHMNNEXovlQevgEFEc01Kg8PXBDd1hP31dfMfZ6v+BXygGHg95zR4AFpcRIYJWu\n9dmMkmMWQN5rZeyDO7ZfDQ0CAwEAAQ==\n-----END MALFORMED KEY-----\n"
      }
    },
    "latest_version": 1,
    "min_available_version": 0,
    "min_decryption_version": 1,
    "min_encryption_version": 0,
    "name": "x509-CA-A",
    "supports_decryption": true,
    "supports_derivation": false,
    "supports_encryption": true,
    "supports_signing": true,
    "type": "rsa-4096"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}`

	testSignDataResponse = `{
  "request_id": "51bb98fa-8da3-8678-64e7-7220bc8b94a6",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "key_version": 1,
    "signature": "vault:v1:MEQCIHw3maFgxsmzAUsUXnw2ahUgPcomjF8+XxflwH4CsouhAiAYL3RhWx8dP2ymm7hjSUvc9EQ8GPXmLrvgacqkEKQPGw=="
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
`
)

type FakeVaultServerConfig struct {
	ListenAddr               string
	ServerCertificatePemPath string
	ServerKeyPemPath         string
	CertAuthReqEndpoint      string
	CertAuthReqHandler       func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	CertAuthResponseCode     int
	CertAuthResponse         []byte
	AppRoleAuthReqEndpoint   string
	AppRoleAuthReqHandler    func(code int, resp []byte) func(w http.ResponseWriter, r *http.Request)
	AppRoleAuthResponseCode  int
	AppRoleAuthResponse      []byte
	K8sAuthReqEndpoint       string
	K8sAuthReqHandler        func(code int, resp []byte) func(w http.ResponseWriter, r *http.Request)
	K8sAuthResponseCode      int
	K8sAuthResponse          []byte
	RenewReqEndpoint         string
	RenewReqHandler          func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	RenewResponseCode        int
	RenewResponse            []byte
	LookupSelfReqEndpoint    string
	LookupSelfReqHandler     func(code int, resp []byte) func(w http.ResponseWriter, r *http.Request)
	LookupSelfResponseCode   int
	LookupSelfResponse       []byte
	CreateKeyReqEndpoint     string
	CreateKeyReqHandler      func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	CreateKeyResponseCode    int
	CreateKeyResponse        []byte
	GetKeyReqEndpoint        string
	GetKeyReqHandler         func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	GetKeyResponseCode       int
	GetKeyResponse           []byte
	GetKeysReqEndpoint       string
	GetKeysReqHandler        func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	GetKeysResponseCode      int
	GetKeysResponse          []byte
	SignDataReqEndpoint      string
	SignDataReqHandler       func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	SignDataResponseCode     int
	SignDataResponse         []byte
}

// NewFakeVaultServerConfig returns VaultServerConfig with default values
func NewFakeVaultServerConfig() *FakeVaultServerConfig {
	return &FakeVaultServerConfig{
		ListenAddr:             listenAddr,
		CertAuthReqEndpoint:    defaultTLSAuthEndpoint,
		CertAuthReqHandler:     defaultReqHandler,
		AppRoleAuthReqEndpoint: defaultAppRoleAuthEndpoint,
		AppRoleAuthReqHandler:  defaultReqHandler,
		K8sAuthReqEndpoint:     defaultK8sAuthEndpoint,
		K8sAuthReqHandler:      defaultReqHandler,
		RenewReqEndpoint:       defaultRenewEndpoint,
		RenewReqHandler:        defaultReqHandler,
		LookupSelfReqEndpoint:  defaultLookupSelfEndpoint,
		LookupSelfReqHandler:   defaultReqHandler,
		CreateKeyReqEndpoint:   defaultCreateKeyEndpoint,
		CreateKeyReqHandler:    defaultReqHandler,
		GetKeyReqEndpoint:      defaultGetKeyEndpoint,
		GetKeyReqHandler:       defaultReqHandler,
		GetKeysReqEndpoint:     defaultGetKeysEndpoint,
		GetKeysReqHandler:      defaultReqHandler,
		SignDataReqEndpoint:    defaultSignDataEndpoint,
		SignDataReqHandler:     defaultReqHandler,
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
	mux.HandleFunc(v.RenewReqEndpoint, v.RenewReqHandler(v.RenewResponseCode, v.RenewResponse))
	mux.HandleFunc(v.LookupSelfReqEndpoint, v.LookupSelfReqHandler(v.LookupSelfResponseCode, v.LookupSelfResponse))
	mux.HandleFunc(v.CreateKeyReqEndpoint, v.CreateKeyReqHandler(v.CreateKeyResponseCode, v.CreateKeyResponse))
	mux.HandleFunc(v.GetKeyReqEndpoint, v.GetKeyReqHandler(v.GetKeyResponseCode, v.GetKeyResponse))
	mux.HandleFunc(v.GetKeysReqEndpoint, v.GetKeysReqHandler(v.GetKeysResponseCode, v.GetKeysResponse))
	mux.HandleFunc(v.SignDataReqEndpoint, v.SignDataReqHandler(v.SignDataResponseCode, v.SignDataResponse))

	srv = httptest.NewUnstartedServer(mux)
	srv.Listener = l
	return srv, l.Addr().String(), nil
}
