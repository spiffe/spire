package run

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/fflag"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
)

func TestJWTRequestCoalescingConfiguration(t *testing.T) {
	for _, value := range []string{"true", "false", ""} {
		t.Run(value, func(t *testing.T) {
			cfg := defaultValidConfig()
			text := "agent { experimental {"
			if value != "" {
				text += "jwt_svid_request_coalescing = " + value
			}
			text += "} }"
			require.NoError(t, hcl.Decode(cfg, text))
			ac, err := NewAgentConfig(cfg, []log.Option{log.WithOutputFile(os.DevNull)}, false)
			require.NoError(t, err)
			f := reflect.ValueOf(ac).Elem().FieldByName("JWTSVIDRequestCoalescing")
			require.True(t, f.IsValid(), "Agent config must expose JWTSVIDRequestCoalescing")
			require.Equal(t, reflect.Bool, f.Kind())
			require.Equal(t, value == "true", f.Bool())
			mf := reflect.TypeFor[manager.Config]()
			field, ok := mf.FieldByName("JWTSVIDRequestCoalescing")
			require.True(t, ok)
			require.Equal(t, reflect.Bool, field.Type.Kind())
		})
	}
}

func TestJWTRequestCoalescingDocumentation(t *testing.T) {
	root := util.ProjectRoot()
	guide, err := os.ReadFile(filepath.Join(root, "doc/spire_agent.md"))
	require.NoError(t, err)
	guideText := regexp.MustCompile(`(?s)<!--.*?-->`).ReplaceAllString(string(guide), "")
	option := "jwt_svid_request_coalescing"
	defaultFalse := regexp.MustCompile(`(?i)(default(?:s|ing)?(?:\s+(?:is|to|of))?\s*[:=]?\s*(?:false|off|disabled)|(?:false|off|disabled)\s+by\s+default)`)
	behavior := regexp.MustCompile(`(?i)\b(coalesc\w*|concurren\w*|coordinat\w*|deduplicat\w*|shar(?:e|ed|ing)|group\w*|merg\w*|combin\w*)\b`)
	documented := false
	for paragraph := range strings.SplitSeq(guideText, "\n\n") {
		if !strings.Contains(paragraph, option) {
			continue
		}
		for line := range strings.SplitSeq(paragraph, "\n") {
			cells := strings.Split(line, "|")
			if len(cells) >= 5 && strings.Contains(cells[1], option) {
				documented = documented || (behavior.MatchString(cells[2]) && strings.EqualFold(strings.Trim(cells[3], " `*\t"), "false"))
			}
		}
		if !strings.Contains(paragraph, "|") {
			prose := strings.NewReplacer(option, "", "`", "", "*", "").Replace(paragraph)
			documented = documented || (behavior.MatchString(prose) && defaultFalse.MatchString(prose))
		}
	}
	require.True(t, documented, "Agent guide must describe the option's behavior and its false default")
	sample, err := os.ReadFile(filepath.Join(root, "conf/agent/agent_full.conf"))
	require.NoError(t, err)
	file, err := hcl.Parse(string(sample))
	require.NoError(t, err)
	code := regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z_0-9]*(?:\s+"[^"]*")*\s*(?:=|\{)|[\}\]\[\{"])`)
	commentedOption := regexp.MustCompile(`^(?:(?:#|//)\s*)+(jwt_svid_request_coalescing\s*=.*)$`)
	uncomment := func(source string) string {
		lines := strings.Split(source, "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(trimmed, "#"):
				trimmed = strings.TrimSpace(trimmed[1:])
			case strings.HasPrefix(trimmed, "//"):
				trimmed = strings.TrimSpace(trimmed[2:])
			default:
				continue
			}
			trimmed = commentedOption.ReplaceAllString(trimmed, "$1")
			if code.MatchString(trimmed) {
				lines[i] = trimmed
			}
		}
		return strings.Join(lines, "\n")
	}
	hasOption := func(list *ast.ObjectList, source string) bool {
		for _, item := range list.Filter("experimental").Items {
			block, ok := item.Val.(*ast.ObjectType)
			if !ok {
				continue
			}
			if len(block.List.Filter("jwt_svid_request_coalescing").Items) > 0 {
				return true
			}
			body := source[block.Lbrace.Offset+1 : block.Rbrace.Offset]
			parsed, err := hcl.Parse(uncomment(body))
			if err == nil && len(parsed.Node.(*ast.ObjectList).Filter("jwt_svid_request_coalescing").Items) > 0 {
				return true
			}
		}
		return false
	}
	start := regexp.MustCompile(`(?m)^\s*(?:#|//)\s*experimental(?:\s|=|\{)`)
	found := false
	for _, item := range file.Node.(*ast.ObjectList).Filter("agent").Items {
		agent, ok := item.Val.(*ast.ObjectType)
		if !ok {
			continue
		}
		if hasOption(agent.List, string(sample)) {
			found = true
			continue
		}
		body := string(sample[agent.Lbrace.Offset+1 : agent.Rbrace.Offset])
		for _, position := range start.FindAllStringIndex(body, -1) {
			source := uncomment(body[position[0]:])
			example, err := hcl.Parse(source)
			if err == nil && hasOption(example.Node.(*ast.ObjectList), source) {
				found = true
			}
		}
	}

	require.True(t, found, "full configuration example must place the option in agent.experimental")
}

func TestJWTRequestCoalescingConfigFile(t *testing.T) {
	t.Cleanup(func() { _ = fflag.Unload() })
	file := filepath.Join(t.TempDir(), "agent.conf")
	require.NoError(t, os.WriteFile(file, []byte(`agent {
 trust_domain = "example.org"
 server_address = "127.0.0.1"
 server_port = 8081
 data_dir = "."
 insecure_bootstrap = true
 experimental { jwt_svid_request_coalescing = true }
}
plugins {}`), 0600))
	cfg, err := LoadConfig("run", []string{"-config", file}, []log.Option{log.WithOutputFile(os.DevNull)}, os.Stderr, false)
	require.NoError(t, err)
	f := reflect.ValueOf(cfg).Elem().FieldByName("JWTSVIDRequestCoalescing")
	require.True(t, f.IsValid())
	require.True(t, f.Bool())
}
