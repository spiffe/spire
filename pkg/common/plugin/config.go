package plugin

import (
	"fmt"

	"github.com/hashicorp/hcl"
)

// StringConfigOrDefault returns config if its non-empty, and ddefault otherwise.
func StringConfigOrDefault(config, ddefault string) string {
	if config != "" {
		return config
	}
	return ddefault
}

// ParseConfig parses the HCL config into ifc, which is a pointer to a config struct.
func ParseConfig(cfg string, ifc interface{}) error {
	hclTree, err := hcl.Parse(cfg)
	if err != nil {
		return fmt.Errorf("parse error: %v", err)
	}
	err = hcl.DecodeObject(ifc, hclTree)
	if err != nil {
		return fmt.Errorf("decode error: %v", err)
	}
	return nil
}
