package protojson

import (
	"encoding/json"
	"io"

	"github.com/spiffe/spire/pkg/common/cliprinter/internal/errorjson"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Print prints one or more protobuf messages formatted as JSON
func Print(msgs []proto.Message, stdout, stderr io.Writer) error {
	if len(msgs) == 0 {
		return nil
	}

	jms := []json.RawMessage{}
	m := &protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}

	// Unfortunately, we can only marshal one message at a time, so
	// we need to build up an array of marshaled messages. We do this
	// before printing them to reduce our chances of printing an
	// unterminated result
	for _, msg := range msgs {
		jb, err := m.Marshal(msg)
		if err != nil {
			_ = errorjson.Print(err, stdout, stderr)
			return err
		}

		jms = append(jms, jb)
	}
	var err error

	parsedJms, err := parseJSONMessages(jms)
	if err != nil {
		_ = errorjson.Print(err, stdout, stderr)
		return err
	}

	if len(parsedJms) == 1 {
		err = json.NewEncoder(stdout).Encode(parsedJms[0])
	} else {
		err = json.NewEncoder(stdout).Encode(parsedJms)
	}

	return err
}

func parseJSONMessages(jms []json.RawMessage) ([]json.RawMessage, error) {
	var parsedJms []json.RawMessage
	for _, jm := range jms {
		parsedJm, err := parseJSONMessage(jm)
		if err != nil {
			return nil, err
		}
		parsedJms = append(parsedJms, parsedJm)
	}

	return parsedJms, nil
}

func parseJSONMessage(jm json.RawMessage) (json.RawMessage, error) {
	var jmMap map[string]any
	if err := json.Unmarshal(jm, &jmMap); err != nil {
		return nil, err
	}

	removeNulls(jmMap)

	return json.Marshal(jmMap)
}

func removeNulls(jsonMap map[string]any) {
	for key, val := range jsonMap {
		switch v := val.(type) {
		case nil:
			delete(jsonMap, key)
		case map[string]any:
			removeNulls(v)
		case []any:
			jsonMap[key] = removeNullsFromSlice(v)
		}
	}
}

func removeNullsFromSlice(slice []any) []any {
	var newSlice = make([]any, 0)
	for _, val := range slice {
		switch v := val.(type) {
		case nil:
			continue
		case map[string]any:
			removeNulls(v)
			newSlice = append(newSlice, v)
		case []any:
			newSlice = append(newSlice, removeNullsFromSlice(v))
		default:
			newSlice = append(newSlice, v)
		}
	}

	return newSlice
}
