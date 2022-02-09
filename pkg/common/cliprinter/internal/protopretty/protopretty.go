package protopretty

import (
	"fmt"
	"io"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

func Print(msgs []proto.Message, stdout, stderr io.Writer) error {
	if len(msgs) == 0 {
		return nil
	}

	tm := &prototext.MarshalOptions{
		Multiline: true,
	}
	for _, msg := range msgs {
		s := tm.Format(msg)
		_, err := fmt.Fprintf(stdout, "%s\n", s)
		if err != nil {
			return err
		}
	}

	return nil
}
