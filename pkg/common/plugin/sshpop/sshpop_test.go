package sshpop

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// from testdata/dummy_ssh_cert_authority.pub
var testCertAuthority = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEAWPAsKJ/qMYUIBeH7BLMRCE/bkUvMHX+7OZhANk45S"

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
						   agent_path_template = "{{ .PluginName}}/{{ .Fingerprint }}"`,
			requireClient: func(t *testing.T, c *Client) {
				require.NotNil(t, c)
				require.Equal(t, "foo.test", c.trustDomain)
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
									   agent_path_template = "{{ .PluginName}}/{{ .Fingerprint }}"`, testCertAuthority),
			trustDomain: "foo.test",
			requireServer: func(t *testing.T, s *Server) {
				require.NotNil(t, s)
				require.Equal(t, "foo.test", s.trustDomain)
				require.Equal(t, DefaultAgentPathTemplate, s.agentPathTemplate)
				pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testCertAuthority))
				require.NoError(t, err)
				require.True(t, s.certChecker.IsHostAuthority(pubkey, ""))
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
