// Package yamlconfig decodes YAML configuration into structs using their yaml
// tags.
package yamlconfig

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
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
	resolved := resolveAliases(node)
	data, err := yaml.Marshal(resolved)
	if err != nil {
		return err
	}
	if err := Decode(string(data), out); err != nil {
		return remapLines(err, data, resolved)
	}
	return nil
}

var errLineRe = regexp.MustCompile(`^line (\d+): `)

// remapLines rewrites the line numbers of err, which refer to the re-marshaled
// data, to the lines of the original node.
func remapLines(err error, data []byte, original *yaml.Node) error {
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		return err
	}
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil || len(doc.Content) == 0 {
		return err
	}
	lines := make(map[int]int)
	mapLines(doc.Content[0], original, lines)

	msgs := make([]string, len(typeErr.Errors))
	for i, msg := range typeErr.Errors {
		msgs[i] = errLineRe.ReplaceAllStringFunc(msg, func(prefix string) string {
			n, _ := strconv.Atoi(errLineRe.FindStringSubmatch(prefix)[1])
			if line, ok := lines[n]; ok {
				return fmt.Sprintf("line %d: ", line)
			}
			return ""
		})
	}
	return &yaml.TypeError{Errors: msgs}
}

// mapLines records the line of each node in original, keyed by the line of the
// corresponding node in remarshaled.
func mapLines(remarshaled, original *yaml.Node, lines map[int]int) {
	if _, ok := lines[remarshaled.Line]; !ok {
		lines[remarshaled.Line] = original.Line
	}
	for i := 0; i < len(remarshaled.Content) && i < len(original.Content); i++ {
		mapLines(remarshaled.Content[i], original.Content[i], lines)
	}
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
	return checkNullEntries(reflect.ValueOf(out), "")
}

// checkNullEntries rejects map and list entries left nil by a null value,
// since configuration code expects every entry to be set.
func checkNullEntries(v reflect.Value, path string) error {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			return checkNullEntries(v.Elem(), path)
		}
	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if name == "-" {
				continue
			}
			fieldPath := path
			if opts != "inline" {
				if name == "" {
					name = strings.ToLower(f.Name)
				}
				fieldPath = joinPath(path, name)
			}
			if err := checkNullEntries(v.Field(i), fieldPath); err != nil {
				return err
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if err := checkEntry(iter.Value(), joinPath(path, fmt.Sprint(iter.Key()))); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			if err := checkEntry(v.Index(i), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkEntry(v reflect.Value, path string) error {
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return fmt.Errorf("%s must not be null; use {} for an entry without options", path)
	}
	return checkNullEntries(v, path)
}

func joinPath(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
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
