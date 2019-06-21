package sshpop

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

var (
	// from testdata/dummy_ssh_cert_authority.pub
	testCertAuthority = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEAWPAsKJ/qMYUIBeH7BLMRCE/bkUvMHX+7OZhANk45S"
	// from testdata/many_ssh_cert_authorities.pub
	testCertAuthority2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIItL+PtmvrTxqrUt3GtgoQEoIFzNb4xpVwtOXa5WLCOQ"
	// from nowhere
	testCertAuthority3 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL9zEd6mtBjOIG+lWt0cxmrE4Sp7LwpLEXLa3CbSuxKu"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		desc          string
		trustDomain   string
		configString  string
		expectErr     string
		requireClient func(*testing.T, *Client)
	}{
		{
			desc:      "missing trust domain",
			expectErr: "sshpop: trust_domain global configuration is required",
		},
		{
			desc:         "bad config",
			trustDomain:  "foo.test",
			configString: "[[]",
			expectErr:    "sshpop: failed to decode configuration",
		},
		{
			desc:         "key file not exists",
			trustDomain:  "foo.test",
			configString: `host_key_path = "something-that-doesnt-exist"`,
			expectErr:    "sshpop: failed to read host key file",
		},
		{
			desc:         "cert file not exists",
			trustDomain:  "foo.test",
			configString: `host_key_path = "./testdata/dummy_agent_ssh_key"`,
			expectErr:    "sshpop: failed to read host cert file",
		},
		{
			desc:        "bad agent path template",
			trustDomain: "foo.test",
			configString: `host_key_path = "./testdata/dummy_agent_ssh_key"
						   host_cert_path = "./testdata/dummy_agent_ssh_key-cert.pub"
						   agent_path_template = "{{"`,
			expectErr: "sshpop: failed to parse agent svid template",
		},
		{
			desc:        "success",
			trustDomain: "foo.test",
			configString: `host_key_path = "./testdata/dummy_agent_ssh_key"
						   host_cert_path = "./testdata/dummy_agent_ssh_key-cert.pub"
						   canonical_domain = "local"
						   agent_path_template = "{{ .PluginName}}/{{ .Fingerprint }}"`,
			requireClient: func(t *testing.T, c *Client) {
				require.NotNil(t, c)
				require.Equal(t, "foo.test", c.trustDomain)
				require.Equal(t, "local", c.canonicalDomain)
				require.Equal(t, DefaultAgentPathTemplate, c.agentPathTemplate)
				require.Equal(t, c.signer.PublicKey(), c.cert.Key)
				require.Equal(t, "foo-host", c.cert.KeyId)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			c, err := NewClient(tt.trustDomain, tt.configString)
			if tt.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectErr)
				return
			}
			require.NoError(t, err)
			tt.requireClient(t, c)
		})
	}
}

func TestNewServer(t *testing.T) {
	tests := []struct {
		desc          string
		trustDomain   string
		configString  string
		expectErr     string
		requireServer func(*testing.T, *Server)
	}{
		{
			desc:      "missing trust domain",
			expectErr: "sshpop: trust_domain global configuration is required",
		},
		{
			desc:         "bad config",
			trustDomain:  "foo.test",
			configString: "[[]",
			expectErr:    "sshpop: failed to decode configuration",
		},
		{
			desc:        "no cert authority",
			trustDomain: "foo.test",
			expectErr:   `sshpop: missing required config value for "cert_authorities"`,
		},
		{
			desc:         "no cert authorities",
			configString: `cert_authorities = []`,
			trustDomain:  "foo.test",
			expectErr:    `sshpop: failed to create cert checker: must provide at least one cert authority`,
		},
		{
			desc:         "bad cert authorities",
			configString: `cert_authorities = ["bad authority"]`,
			trustDomain:  "foo.test",
			expectErr:    `sshpop: failed to create cert checker: failed to parse public key`,
		},
		{
			desc: "success",
			configString: fmt.Sprintf(`cert_authorities = [%q]
									   canonical_domain = "local"
									   agent_path_template = "{{ .PluginName}}/{{ .Fingerprint }}"`, testCertAuthority),
			trustDomain: "foo.test",
			requireServer: func(t *testing.T, s *Server) {
				require.NotNil(t, s)
				require.Equal(t, "foo.test", s.trustDomain)
				require.Equal(t, "local", s.canonicalDomain)
				require.Equal(t, DefaultAgentPathTemplate, s.agentPathTemplate)
				pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testCertAuthority))
				require.NoError(t, err)
				require.True(t, s.certChecker.IsHostAuthority(pubkey, ""))
			},
		},
		{
			desc: "success merge config",
			configString: fmt.Sprintf(`cert_authorities = [%q]
									   cert_authorities_path = "./testdata/many_ssh_cert_authorities.pub"
									   agent_path_template = "{{ .PluginName}}/{{ .Fingerprint }}"`, testCertAuthority),
			trustDomain: "foo.test",
			requireServer: func(t *testing.T, s *Server) {
				require.NotNil(t, s)
				require.Equal(t, "foo.test", s.trustDomain)
				require.Equal(t, DefaultAgentPathTemplate, s.agentPathTemplate)
				pubkey := requireParsePubkey(t, testCertAuthority)
				pubkey2 := requireParsePubkey(t, testCertAuthority2)
				pubkey3 := requireParsePubkey(t, testCertAuthority3)
				require.True(t, s.certChecker.IsHostAuthority(pubkey, ""))
				require.True(t, s.certChecker.IsHostAuthority(pubkey2, ""))
				require.False(t, s.certChecker.IsHostAuthority(pubkey3, ""))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			s, err := NewServer(tt.trustDomain, tt.configString)
			if tt.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectErr)
				return
			}
			require.NoError(t, err)
			tt.requireServer(t, s)
		})
	}
}

func requireParsePubkey(t *testing.T, pubkeyString string) ssh.PublicKey {
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkeyString))
	require.NoError(t, err)
	return pubkey
}

func TestPubkeysFromPath(t *testing.T) {
	tests := []struct {
		desc          string
		pubkeyPath    string
		expectPubkeys []string
		expectErr     string
	}{
		{
			desc:       "nonexistent file",
			pubkeyPath: "blahblahblah",
			expectErr:  "open blahblahblah: no such file or directory",
		},
		{
			desc:       "empty file",
			pubkeyPath: "./testdata/empty_ssh_cert_authority.pub",
			expectErr:  "no data found in file: \"./testdata/empty_ssh_cert_authority.pub\"",
		},
		{
			desc:          "single pubkey",
			pubkeyPath:    "./testdata/dummy_ssh_cert_authority.pub",
			expectPubkeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEAWPAsKJ/qMYUIBeH7BLMRCE/bkUvMHX+7OZhANk45S"},
		},
		{
			desc:       "many pubkeys",
			pubkeyPath: "./testdata/many_ssh_cert_authorities.pub",
			expectPubkeys: []string{
				"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEAWPAsKJ/qMYUIBeH7BLMRCE/bkUvMHX+7OZhANk45S",
				"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIItL+PtmvrTxqrUt3GtgoQEoIFzNb4xpVwtOXa5WLCOQ",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			pubkeys, err := pubkeysFromPath(tt.pubkeyPath)
			if tt.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectPubkeys, pubkeys)
		})
	}
}
