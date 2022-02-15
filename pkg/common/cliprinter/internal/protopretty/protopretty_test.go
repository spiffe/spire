package protopretty

import (
	"bytes"
	"regexp"
	"testing"

	agentapi "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestPrint(t *testing.T) {
	cases := []struct {
		name         string
		protoFunc    func(*testing.T) []proto.Message
		stdoutRegexp *regexp.Regexp
		stderrRegexp *regexp.Regexp
	}{
		{
			name:         "normal_protobuf_message",
			protoFunc:    normalCountAgentsResponseMessage,
			stdoutRegexp: regexp.MustCompile(`count:\s+42\n\n`),
			stderrRegexp: regexp.MustCompile(`^$`),
		},
		{
			name:         "double_protobuf_message",
			protoFunc:    doubleCountAgentsResponseMessage,
			stdoutRegexp: regexp.MustCompile(`count:\s+42\n\ncount:\s+42\n\n`),
			stderrRegexp: regexp.MustCompile(`^$`),
		},
		{
			name:         "nil_message",
			protoFunc:    nilMessage,
			stdoutRegexp: regexp.MustCompile(`^$`),
			stderrRegexp: regexp.MustCompile(`^$`),
		},
		{
			name:         "no_message",
			protoFunc:    noMessage,
			stdoutRegexp: regexp.MustCompile(`^$`),
			stderrRegexp: regexp.MustCompile(`^$`),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}
			err := Print(c.protoFunc(t), stdout, stderr)

			assert.Nil(t, err)
			assert.True(t, c.stdoutRegexp.Match(stdout.Bytes()))
			assert.True(t, c.stderrRegexp.Match(stderr.Bytes()))
		})
	}
}

func normalCountAgentsResponseMessage(_ *testing.T) []proto.Message {
	return []proto.Message{
		&agentapi.CountAgentsResponse{
			Count: int32(42),
		},
	}
}

func doubleCountAgentsResponseMessage(t *testing.T) []proto.Message {
	return []proto.Message{
		normalCountAgentsResponseMessage(t)[0],
		normalCountAgentsResponseMessage(t)[0],
	}
}

func nilMessage(_ *testing.T) []proto.Message { return nil }
func noMessage(_ *testing.T) []proto.Message  { return []proto.Message{} }
