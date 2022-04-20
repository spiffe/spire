package agentpathtemplate_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/stretchr/testify/require"
)

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
