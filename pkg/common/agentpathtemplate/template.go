package agentpathtemplate

import (
	"bytes"
	"text/template"
)

// Parse parses an agent path template. It changes the behavior for missing
// keys to return an error instead of the default behavior, which renders a
// value that requires percent-encoding to include in a URI, which is against
// the SPIFFE specification.
func Parse(text string) (*Template, error) {
	tmpl, err := template.New("agent-path").Option("missingkey=error").Parse(text)
	if err != nil {
		return nil, err
	}
	return &Template{tmpl: tmpl}, nil
}

// MustParse parses an agent path template. It changes the behavior for missing
// keys to return an error instead of the default behavior, which renders a
// value that requires percent-encoding to include in a URI, which is against
// the SPIFFE specification. If parsing fails, the function panics.
func MustParse(text string) *Template {
	tmpl, err := Parse(text)
	if err != nil {
		panic(err)
	}
	return tmpl
}

type Template struct {
	tmpl *template.Template
}

func (t *Template) Execute(args interface{}) (string, error) {
	buf := new(bytes.Buffer)
	if err := t.tmpl.Execute(buf, args); err != nil {
		return "", err
	}
	return buf.String(), nil
}
