package plugindecode

import (
	"fmt"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/yamlconfig"
)

// DecodeConfig decodes a plugin configuration in the given format into out.
// YAML configurations are decoded using yaml tags and reject unknown keys.
func DecodeConfig(text string, format catalog.ConfigFormat, out any) error {
	switch format {
	case catalog.ConfigFormatHCL:
		return hcl.Decode(out, text)
	case catalog.ConfigFormatYAML:
		return yamlconfig.Decode(text, out)
	default:
		return fmt.Errorf("unsupported configuration format %d", format)
	}
}
