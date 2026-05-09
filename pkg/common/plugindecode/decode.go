package plugindecode

import (
	"errors"
	"io"
	"strings"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"go.yaml.in/yaml/v3"
)

// DecodeConfig decodes text into out using the given format.
func DecodeConfig(text string, format catalog.ConfigFormat, out any) error {
	if format == catalog.ConfigFormatYAML {
		return DecodeYAML(text, out)
	}
	return hcl.Decode(out, text)
}

// DecodeYAML decodes YAML text into out using its yaml struct tags. Unknown
// keys are rejected so that misspelled options are not silently ignored.
func DecodeYAML(text string, out any) error {
	dec := yaml.NewDecoder(strings.NewReader(text))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// DecodeYAMLNode strictly decodes a YAML node into out. Use it from custom
// UnmarshalYAML methods, where yaml.Node.Decode would accept unknown keys.
func DecodeYAMLNode(node *yaml.Node, out any) error {
	data, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	return DecodeYAML(string(data), out)
}
