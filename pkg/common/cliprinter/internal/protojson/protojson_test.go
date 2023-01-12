package protojson

import (
	"bytes"
	"encoding/json"
	"testing"

	agentapi "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			stdout:    `{"count":42}` + "\n",
			stderr:    "",
		},
		{
			name:      "double_protobuf_message",
			protoFunc: doubleCountAgentsResponseMessage,
			stdout:    `[{"count":42},{"count":42}]` + "\n",
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
			name:      "message_with_zeroed_values",
			protoFunc: zeroedValuesMessage,
			stdout:    `{"count":0}` + "\n",
			stderr:    "",
		},
		{
			name:      "message_with_null_pointers",
			protoFunc: nullPointerMessage,
			stdout:    `{"federation_relationships":[{"bundle_endpoint_url":"https://example.org/bundle","trust_domain":"example.org"}],"next_page_token":""}` + "\n",
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

func TestRemoveNulls(t *testing.T) {
	cases := []struct {
		name   string
		input  []byte
		output []byte
	}{
		{
			name:   "remove null values",
			input:  []byte(`{"nullField":null,"int":1,"string":"value","bool":true,"array":[1,2,3],"object":{"key":"value"}}`),
			output: []byte(`{"int":1,"string":"value","bool":true,"array":[1,2,3],"object":{"key":"value"}}`),
		},
		{
			name:   "remove nested null values",
			input:  []byte(`{"someField":{"nestedField1":{"nestedField2": null}}}`),
			output: []byte(`{"someField":{"nestedField1":{}}}`),
		},
		{
			name:   "remove null values from array",
			input:  []byte(`{"someFieldArray":[null,{"nestedField1":null},null,{"nestedField2":"value"},null]}`),
			output: []byte(`{"someFieldArray":[{},{"nestedField2":"value"}]}`),
		},
		{
			name:   "remove null values from nested arrays",
			input:  []byte(`{"someFieldArray":[[null,1,null,2,[null,null,null,3]],[null,{"nestedField2":"value"}]]}`),
			output: []byte(`{"someFieldArray":[[1,2,[3]],[{"nestedField2":"value"}]]}`),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var input, output map[string]interface{}
			err := json.Unmarshal(c.input, &input)
			require.NoError(t, err)
			err = json.Unmarshal(c.output, &output)
			require.NoError(t, err)

			removeNulls(input)

			assert.Equal(t, output, input)
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

func zeroedValuesMessage(_ *testing.T) []proto.Message {
	return []proto.Message{
		&agentapi.CountAgentsResponse{},
	}
}

func nullPointerMessage(_ *testing.T) []proto.Message {
	return []proto.Message{
		&trustdomain.ListFederationRelationshipsResponse{
			FederationRelationships: []*types.FederationRelationship{
				{
					TrustDomain:       "example.org",
					BundleEndpointUrl: "https://example.org/bundle",
				},
			},
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
