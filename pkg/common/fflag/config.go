package fflag

import (
	"bytes"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
)

type RawConfig ast.Node

func parseRawConfig(rc RawConfig) (map[string]bool, error) {
	resp := make(map[string]bool)

	str, err := rawConfigToStr(rc)
	if err != nil {
		return nil, err
	}

	err = hcl.Decode(&resp, str)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func rawConfigToStr(rc RawConfig) (string, error) {
	buf := new(bytes.Buffer)
	err := printer.DefaultConfig.Fprint(buf, rc)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
