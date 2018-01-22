package config

import (
	"io/ioutil"

	"github.com/hashicorp/hcl"
)

// ParseHCLFile takes a file path and a pointer to a struct with HCL
// anchors. It reads the file and populates the struct accordingly
func ParseHCLConfigFile(path string, s interface{}) error {
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	hclText := string(dat)
	err = ParseHCLConfigString(hclText, s)
	if err != nil {
		return err
	}

	return nil
}

// ParseHCLFile takes a file path and a pointer to a struct with HCL
// anchors. It reads the file and populates the struct accordingly
func ParseHCLConfigString(hclText string, s interface{}) error {
	// Parse HCL
	hclParseTree, err := hcl.Parse(hclText)
	if err != nil {
		return err
	}

	if err := hcl.DecodeObject(s, hclParseTree); err != nil {
		return err
	}

	return nil
}
