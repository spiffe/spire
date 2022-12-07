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
	if len(jms) == 1 {
		err = json.NewEncoder(stdout).Encode(jms[0])
	} else {
		err = json.NewEncoder(stdout).Encode(jms)
	}

	return err
}
