package agentpathtemplate_test

import (
	"errors"
	"testing"
	"text/template"

	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/stretchr/testify/require"
)

var errSentinel = errors.New("sentinel")

func TestExecute(t *testing.T) {
	tmpl, err := agentpathtemplate.Parse("{{ .key }}")
	require.NoError(t, err)

	t.Run("lookup ok", func(t *testing.T) {
		path, err := tmpl.Execute(map[string]string{
			"key": "/value",
		})
		require.NoError(t, err)
		require.Equal(t, "/value", path)
	})

	t.Run("lookup fails", func(t *testing.T) {
		_, err := tmpl.Execute(nil)
		require.Error(t, err)
	})
}

func TestMustParse(t *testing.T) {
	t.Run("parse ok", func(t *testing.T) {
		require.NotPanics(t, func() {
			tmpl := agentpathtemplate.MustParse("{{ .key }}")
			require.NotNil(t, tmpl)
		})
	})
	t.Run("parse fails", func(t *testing.T) {
		require.Panics(t, func() {
			agentpathtemplate.MustParse("{{ .key ")
		})
	})
}

func TestParseWithFuncs(t *testing.T) {
	t.Run("json funcs are not in the default set", func(t *testing.T) {
		_, err := agentpathtemplate.Parse(`{{ list "a" "b" | toJson }}`)
		require.ErrorContains(t, err, `function "toJson" not defined`)
	})

	t.Run("json funcs can be opted into", func(t *testing.T) {
		tmpl, err := agentpathtemplate.ParseWithFuncs(`{{ list "a" "b" | toJson }}`, agentpathtemplate.JSONFuncMap())
		require.NoError(t, err)

		out, err := tmpl.Execute(nil)
		require.NoError(t, err)
		require.Equal(t, `["a","b"]`, out)
	})

	t.Run("only toJson is exposed", func(t *testing.T) {
		for _, name := range []string{"mustToJson", "toRawJson", "toPrettyJson", "fromJson"} {
			_, err := agentpathtemplate.ParseWithFuncs("{{ "+name+" . }}", agentpathtemplate.JSONFuncMap())
			require.ErrorContains(t, err, `function "`+name+`" not defined`)
		}
	})

	t.Run("toJson reports values it can not encode", func(t *testing.T) {
		tmpl, err := agentpathtemplate.ParseWithFuncs("{{ toJson .key }}", agentpathtemplate.JSONFuncMap())
		require.NoError(t, err)

		_, err = tmpl.Execute(map[string]any{"key": func() {}})
		require.ErrorContains(t, err, "unsupported type")
	})

	t.Run("default funcs remain available", func(t *testing.T) {
		tmpl, err := agentpathtemplate.ParseWithFuncs(`{{ upper .key }}`, agentpathtemplate.JSONFuncMap())
		require.NoError(t, err)

		out, err := tmpl.Execute(map[string]string{"key": "value"})
		require.NoError(t, err)
		require.Equal(t, "VALUE", out)
	})

	t.Run("extra funcs override the default set", func(t *testing.T) {
		tmpl, err := agentpathtemplate.ParseWithFuncs(`{{ fail "boom" }}`, template.FuncMap{
			"fail": func(string) (string, error) { return "", errSentinel },
		})
		require.NoError(t, err)

		_, err = tmpl.Execute(nil)
		require.ErrorIs(t, err, errSentinel)
	})

	t.Run("nil extra funcs behaves like Parse", func(t *testing.T) {
		tmpl, err := agentpathtemplate.ParseWithFuncs("{{ .key }}", nil)
		require.NoError(t, err)

		out, err := tmpl.Execute(map[string]string{"key": "/value"})
		require.NoError(t, err)
		require.Equal(t, "/value", out)
	})

	t.Run("extra funcs do not leak into other templates", func(t *testing.T) {
		_, err := agentpathtemplate.ParseWithFuncs(`{{ list "a" | toJson }}`, agentpathtemplate.JSONFuncMap())
		require.NoError(t, err)

		_, err = agentpathtemplate.Parse(`{{ list "a" | toJson }}`)
		require.ErrorContains(t, err, `function "toJson" not defined`)
	})
}

// TestPanickingFuncIsAnError documents that a template function that panics,
// such as urlParse on input it cannot parse, surfaces as an execution error
// rather than taking down the process.
func TestPanickingFuncIsAnError(t *testing.T) {
	tmpl, err := agentpathtemplate.Parse(`{{ (urlParse .key).path }}`)
	require.NoError(t, err)

	_, err = tmpl.Execute(map[string]string{"key": "://\x7f"})
	require.ErrorContains(t, err, "unable to parse url")
}
