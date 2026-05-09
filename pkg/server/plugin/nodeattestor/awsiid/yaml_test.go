package awsiid

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/common/plugindecode"
	"github.com/stretchr/testify/require"
)

// TestConfigYAMLInline checks that YAML keys of the embedded configuration decode into it.
func TestConfigYAMLInline(t *testing.T) {
	config := new(IIDAttestorConfig)
	require.NoError(t, plugindecode.DecodeYAML("accessKeyId: AKID\n", config))
	require.Equal(t, "AKID", config.AccessKeyID)
}

func TestBuildConfigYAMLCopiesSessionKeys(t *testing.T) {
	var status pluginconf.Status
	p := New()
	config := p.buildConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")},
		"assumeRole: role\npartition: aws-cn\n", catalog.ConfigFormatYAML, &status)
	require.NotNil(t, config)
	require.Equal(t, "role", config.AssumeRole)
	require.Equal(t, "aws-cn", config.Partition)
}
