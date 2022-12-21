package protojson

import (
	"encoding/json"
	"io"
	"reflect"

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
	}

	if len(parsedJms) == 1 {
		err = json.NewEncoder(stdout).Encode(parsedJms[0])
	} else {
		err = json.NewEncoder(stdout).Encode(parsedJms)
	}

	return err
}

func parseJSONMessages(jms []json.RawMessage) ([]json.RawMessage, error) {
	parsedJms := []json.RawMessage{}

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
	var jmMap map[string]interface{}
	if err := json.Unmarshal(jm, &jmMap); err != nil {
		return nil, err
	}
	removeNulls(jmMap)
	parsedJm, err := json.Marshal(jmMap)
	if err != nil {
		return nil, err
	}
	return parsedJm, nil
}

func removeNulls(m map[string]interface{}) {
	val := reflect.ValueOf(m)
	for _, e := range val.MapKeys() {
		v := val.MapIndex(e)
		if v.IsNil() {
			delete(m, e.String())
			continue
		}
		switch t := v.Interface().(type) {
		case map[string]interface{}:
			removeNulls(t)
		case []interface{}:
			for _, j := range t {
				if n, ok := j.(map[string]interface{}); ok {
					removeNulls(n)
				}
			}
		}
	}
}
