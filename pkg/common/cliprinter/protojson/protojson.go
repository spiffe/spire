package protojson

import (
	"encoding/json"
	"io"

	"github.com/spiffe/spire/pkg/common/cliprinter/errorjson"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Print prints one or more protobuf messages formatted as JSON
func Print(msgs []proto.Message, stdout, stderr io.Writer) bool {
	if len(msgs) == 0 {
		return true
	}

	jms := []json.RawMessage{}
	m := &protojson.MarshalOptions{
		UseProtoNames: true,
	}

	// Unfortunately, we can only marshal one message at a time, so
	// we need to build up an array of marshaled messages. We do this
	// before printing them to reduce our chances of printing an
	// unterminated result
	for _, msg := range msgs {
		jb, err := m.Marshal(msg)
		if err != nil {
			errorjson.Print(err, stdout, stderr)
			return false
		}

		jms = append(jms, jb)
	}

	if len(jms) == 1 {
		json.NewEncoder(stdout).Encode(jms[0])
	} else {
		json.NewEncoder(stdout).Encode(jms)
	}

	return true
}
