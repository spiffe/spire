package protojson

import (
	"bytes"
	"testing"

	agentapi "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestPrint(t *testing.T) {
	cases := []struct {
		name      string
		protoFunc func(*testing.T) []proto.Message
		stdout    string
		stderr    string
	}{
		{
			name:      "normal_protobuf_message",
			protoFunc: normalCountAgentsResponseMessage,
			stdout:    "{\"count\":42}\n",
			stderr:    "",
		},
		{
			name:      "double_protobuf_message",
			protoFunc: doubleCountAgentsResponseMessage,
			stdout:    "[{\"count\":42},{\"count\":42}]\n",
			stderr:    "",
		},
		{
			name:      "nil_message",
			protoFunc: nilMessage,
			stdout:    "",
			stderr:    "",
		},
		{
			name:      "no_message",
			protoFunc: noMessage,
			stdout:    "",
			stderr:    "",
		},
		{
			name:      "message_with_unpopulated_fields",
			protoFunc: unpopulatedFieldsMessage,
			stdout:    "{\"count\":0}\n",
			stderr:    "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}
			err := Print(c.protoFunc(t), stdout, stderr)

			assert.Nil(t, err)
			assert.Equal(t, c.stdout, stdout.String())
			assert.Equal(t, c.stderr, stderr.String())
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

func unpopulatedFieldsMessage(_ *testing.T) []proto.Message {
	return []proto.Message{
		&agentapi.CountAgentsResponse{
			Count: int32(0),
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
