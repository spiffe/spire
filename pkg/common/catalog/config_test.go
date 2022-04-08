package catalog

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePluginConfigsFromHCLFailure(t *testing.T) {
	_, err := ParsePluginConfigsFromHCL(`NOT-VALID-HCL`)
	require.Error(t, err)
}

func TestParsePluginConfigsFromHCLSuccess(t *testing.T) {
	config, err := ParsePluginConfigsFromHCL(`
	TYPE1 "NAME1" {
		plugin_cmd = "CMD1"
		plugin_data = "DATA1"
	}
	TYPE2 "NAME2" {
		plugin_cmd = "CMD2"
		plugin_args = ["foo", "bar", "baz"]
		plugin_checksum = "CHECKSUM2"
		plugin_data = "DATA2"
		enabled = true
	}
	TYPE3 "NAME3" {
		plugin_data = "DATA3"
		enabled = false
	}
	TYPE4 "NAME4" {
	}
`)
	require.NoError(t, err)

	sortPluginConfig(config)
	require.Equal(t, []PluginConfig{
		{
			Name:     "NAME1",
			Type:     "TYPE1",
			Path:     "CMD1",
			Data:     `"DATA1"`,
			Disabled: false,
		},
		{
			Name:     "NAME2",
			Type:     "TYPE2",
			Path:     "CMD2",
			Args:     []string{"foo", "bar", "baz"},
			Checksum: "CHECKSUM2",
			Data:     `"DATA2"`,
			Disabled: false,
		},
		{
			Name:     "NAME3",
			Type:     "TYPE3",
			Data:     `"DATA3"`,
			Disabled: true,
		},
		{
			Name: "NAME4",
			Type: "TYPE4",
		},
	}, config)
}

func sortPluginConfig(c []PluginConfig) {
	sort.Slice(c, func(i, j int) bool {
		a := c[i]
		b := c[j]
		if a.Type > b.Type {
			return false
		}
		if a.Type < b.Type {
			return true
		}
		return a.Name < b.Name
	})
}
