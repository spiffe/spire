package yamlconfig_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/spiffe/spire/pkg/common/yamlconfig"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

type config struct {
	KeysPath string         `yaml:"keysPath"`
	MaxKeys  int            `yaml:"maxKeys"`
	Plugins  yamlconfig.Raw `yaml:"plugins"`
}

func TestDecode(t *testing.T) {
	var c config
	require.NoError(t, yamlconfig.Decode("keysPath: /tmp/keys\nmaxKeys: 10\n", &c))
	require.Equal(t, "/tmp/keys", c.KeysPath)
	require.Equal(t, 10, c.MaxKeys)

	require.NoError(t, yamlconfig.Decode("", &c))

	require.ErrorContains(t, yamlconfig.Decode("keys_path: /tmp/keys\n", &c), "field keys_path not found")
	require.ErrorContains(t, yamlconfig.Decode(":\n  - bad: [yaml", &c), "yaml:")
	require.EqualError(t, yamlconfig.Decode("maxKeys: 1\n---\nmaxKeys: 2\n", &c), "multiple YAML documents are not supported")
}

func TestDecodeLenient(t *testing.T) {
	var c config
	unknown, err := yamlconfig.DecodeLenient("keysPath: /tmp/keys\nkeys_path: x\nmax_keys: 1\n", &c)
	require.NoError(t, err)
	require.Equal(t, []string{"keys_path (line 2)", "max_keys (line 3)"}, unknown)
	require.Equal(t, "/tmp/keys", c.KeysPath)

	_, err = yamlconfig.DecodeLenient("maxKeys: notanumber\nbogus: 1\n", &c)
	require.ErrorContains(t, err, "cannot unmarshal")
}

func TestAliases(t *testing.T) {
	text := `
base: &base
  keysPath: /tmp/keys
plugins:
  a: *base
  b:
    <<: *base
    maxKeys: 3
`
	var doc struct {
		Base    any            `yaml:"base"`
		Plugins yamlconfig.Raw `yaml:"plugins"`
	}
	require.NoError(t, yamlconfig.Decode(text, &doc))

	// Each plugin's block must decode on its own, without the anchor.
	for i, want := range []config{{KeysPath: "/tmp/keys"}, {KeysPath: "/tmp/keys", MaxKeys: 3}} {
		var got config
		require.NoError(t, yamlconfig.DecodeNode(doc.Plugins.Node.Content[2*i+1], &got))
		require.Equal(t, want.KeysPath, got.KeysPath)
		require.Equal(t, want.MaxKeys, got.MaxKeys)

		data, err := yaml.Marshal(doc.Plugins.Node.Content[2*i+1])
		require.NoError(t, err)
		require.NotContains(t, string(data), "*base")
	}
}

func TestAliasAbuse(t *testing.T) {
	var doc struct {
		Plugins yamlconfig.Raw `yaml:"plugins"`
	}
	err := yamlconfig.Decode("plugins: &a\n  x: *a\n", &doc)
	require.ErrorContains(t, err, "contains itself")

	// Each level refers ten times to the previous one.
	text := "a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n"
	for i := 1; i <= 8; i++ {
		text += fmt.Sprintf("a%d: &a%d [*a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d]\n", i, i, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1)
	}
	err = yamlconfig.Decode("plugins:\n  "+strings.ReplaceAll(text, "\n", "\n  ")+"\n", &doc)
	require.ErrorContains(t, err, "excessive aliasing")

	node := new(yaml.Node)
	require.NoError(t, yaml.Unmarshal([]byte("a: &a\n  x: *a\n"), node))
	require.ErrorContains(t, yamlconfig.DecodeNode(node, new(any)), "contains itself")
}

type cluster struct {
	Name string `yaml:"name"`
}

type clustersConfig struct {
	Clusters map[string]*cluster `yaml:"clusters"`
	List     []*cluster          `yaml:"list"`
	Values   map[string]any      `yaml:"values"`
}

func TestNullEntries(t *testing.T) {
	require.EqualError(t, yamlconfig.Decode("clusters:\n  prod:\n", new(clustersConfig)),
		"clusters.prod must not be null; use {} for an entry without options")
	require.EqualError(t, yamlconfig.Decode("list: [~]\n", new(clustersConfig)),
		"list[0] must not be null; use {} for an entry without options")
	_, err := yamlconfig.DecodeLenient("clusters: {prod: null}\n", new(clustersConfig))
	require.ErrorContains(t, err, "clusters.prod must not be null")

	var c clustersConfig
	require.NoError(t, yamlconfig.Decode("clusters:\n  prod: {}\nvalues:\n  key: null\n", &c))
	require.Equal(t, &cluster{}, c.Clusters["prod"])

	ptr := &cluster{Name: "kept"}
	require.NoError(t, yamlconfig.Decode("", ptr))
	require.Equal(t, "kept", ptr.Name)
}

type nodeWrapper struct {
	Inner cluster
}

func (w *nodeWrapper) UnmarshalYAML(node *yaml.Node) error {
	return yamlconfig.DecodeNode(node, &w.Inner)
}

func TestDecodeNodeLines(t *testing.T) {
	var c struct {
		Wrapped nodeWrapper `yaml:"wrapped"`
	}
	err := yamlconfig.Decode("# comment\n\n\nwrapped:\n  name: a\n\n  bogus: 1\n", &c)
	require.ErrorContains(t, err, "line 7: field bogus not found")
}
