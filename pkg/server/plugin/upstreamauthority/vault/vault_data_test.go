package vault

const (
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
)
