package cgroup

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerIDFinders(t *testing.T) {
	type match struct {
		cgroup string
		id     string
	}
	tests := []struct {
		msg           string
		matchers      []string
		expectErr     string
		expectNoMatch []string
		expectMatches []match
	}{
		{
			msg: "single matcher",
			matchers: []string{
				"/docker/<id>",
			},
			expectMatches: []match{
				{
					cgroup: "/docker/",
					id:     "",
				},
				{
					cgroup: "/docker/foo",
					id:     "foo",
				},
			},
			expectNoMatch: []string{
				"",
				"/",
				"/docker",
				"/dockerfoo",
				"/docker/foo/",
				"/docker/foo/bar",
				"/docker/foo/docker/foo",
			},
		},
		{
			msg: "multiple wildcards",
			matchers: []string{
				"/long.slice/*/*/<id>/*",
			},
			expectMatches: []match{
				{
					cgroup: "/long.slice/foo/bar//qux",
					id:     "",
				},
				{
					cgroup: "/long.slice/foo/bar/baz/",
					id:     "baz",
				},
				{
					cgroup: "/long.slice/foo/bar/baz/qux",
					id:     "baz",
				},
			},
			expectNoMatch: []string{
				"",
				"/",
				"/long.slice",
				"/long.slicefoo",
				"/long.slice/foo",
				"/long.slice/foo/",
				"/long.slice/foo/bar",
				"/long.slice/foo/long.slice/foo",
				"/long.slice/foo/bar/baz",
				"/long.slice/foo/bar/baz/qux/qax",
			},
		},
		{
			msg: "no id token",
			matchers: []string{
				"/noid",
			},
			expectErr: `pattern "/noid" must contain the container id token "<id>" exactly once`,
		},
		{
			msg: "extra id token",
			matchers: []string{
				"/<id>/<id>",
			},
			expectErr: `pattern "/<id>/<id>" must contain the container id token "<id>" exactly once`,
		},
		{
			msg: "ambiguous patterns",
			matchers: []string{
				"/docker/<id>",
				"/*/<id>",
			},
			expectErr: "dockerfinder: patterns must not be ambiguous:",
		},
		{
			msg: "identical patterns",
			matchers: []string{
				"/docker/<id>",
				"/docker/<id>",
			},
			expectErr: "dockerfinder: patterns must not be ambiguous:",
		},
		{
			msg: "many ambiguous patterns",
			matchers: []string{
				"/docker/<id>",
				"/*/<id>",
				"/a/b/*/d/<id>",
				"/<id>/*/*/*/*",
			},
			expectErr: "dockerfinder: patterns must not be ambiguous:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.msg, func(t *testing.T) {
			cf, err := NewContainerIDFinder(tt.matchers)
			if tt.expectErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cf)
			for _, noMatch := range tt.expectNoMatch {
				id, ok := cf.FindContainerID(noMatch)
				assert.False(t, ok, "expected to not find %q but did", noMatch)
				assert.Equal(t, "", id)
			}

			for _, m := range tt.expectMatches {
				id, ok := cf.FindContainerID(m.cgroup)
				assert.True(t, ok, "expected to find %q but did not", m.cgroup)
				assert.Equal(t, m.id, id)
			}
		})
	}
}
