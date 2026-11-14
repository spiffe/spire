// Package yamlconfig decodes YAML configuration into structs using their yaml
// tags.
package yamlconfig

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Decode decodes text into out, rejecting unknown keys so that misspelled
// options are not silently ignored.
func Decode(text string, out any) error {
	return decode(text, out, true)
}

// DecodeLenient decodes text into out, ignoring unknown keys, and returns the
// unknown keys it found.
func DecodeLenient(text string, out any) (unknownKeys []string, err error) {
	strict := reflect.New(reflect.TypeOf(out).Elem()).Interface()
	if err := decode(text, strict, true); err != nil {
		var typeErr *yaml.TypeError
		if !errors.As(err, &typeErr) {
			return nil, err
		}
		for _, msg := range typeErr.Errors {
			m := unknownFieldRe.FindStringSubmatch(msg)
			if m == nil {
				return nil, err
			}
			unknownKeys = append(unknownKeys, fmt.Sprintf("%s (line %s)", m[2], m[1]))
		}
	}
	return unknownKeys, decode(text, out, false)
}

var unknownFieldRe = regexp.MustCompile(`^line (\d+): field (\S+) not found in type `)

// DecodeNode strictly decodes node into out. Use it from UnmarshalYAML
// methods, since yaml.Node.Decode accepts unknown keys.
func DecodeNode(node *yaml.Node, out any) error {
	if err := checkAliases(node); err != nil {
		return err
	}
	data, err := yaml.Marshal(resolveAliases(node))
	if err != nil {
		return err
	}
	return Decode(string(data), out)
}

// Raw captures a YAML value without decoding it. A *yaml.Node field would
// instead be subject to the decoder's unknown-key checks.
type Raw struct {
	Node *yaml.Node
}

// UnmarshalYAML keeps a copy of node with aliases replaced by their targets,
// so that the value can be re-marshaled on its own.
func (r *Raw) UnmarshalYAML(node *yaml.Node) error {
	if err := checkAliases(node); err != nil {
		return err
	}
	r.Node = resolveAliases(node)
	return nil
}

// checkAliases decodes node to run yaml.v3's checks against aliases that
// contain themselves or expand excessively, which resolveAliases relies on.
func checkAliases(node *yaml.Node) error {
	var v any
	return node.Decode(&v)
}

func decode(text string, out any, strict bool) error {
	dec := yaml.NewDecoder(strings.NewReader(text))
	dec.KnownFields(strict)
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return errors.New("multiple YAML documents are not supported")
	}
	return nil
}

// resolveAliases returns a copy of node in which every alias is replaced by a
// copy of the node it refers to.
func resolveAliases(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode {
		return resolveAliases(node.Alias)
	}
	c := *node
	c.Anchor = ""
	c.Content = make([]*yaml.Node, len(node.Content))
	for i, child := range node.Content {
		c.Content[i] = resolveAliases(child)
	}
	return &c
}
