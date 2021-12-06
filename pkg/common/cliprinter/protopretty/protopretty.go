package protopretty

import (
	"fmt"
	"io"

	"github.com/spiffe/spire/pkg/common/cliprinter/errorpretty"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

func Print(msgs []proto.Message, stdout, stderr io.Writer) bool {
	if msgs == nil || len(msgs) == 0 {
		return true
	}

	tm := &prototext.MarshalOptions{
		Multiline: true,
	}
	for _, msg := range msgs {
		s := tm.Format(msg)
		_, err := fmt.Fprintf(stdout, "%s\n", s)
		if err != nil {
			errorpretty.Print(err, stdout, stderr)
			return false
		}
	}

	return true
}
