package structjson

import (
	"encoding/json"
	"fmt"
	"io"
)

func Print(msgs []any, stdout, _ io.Writer) error {
	var jb []byte
	var err error

	if len(msgs) == 0 {
		return nil
	}

	if len(msgs) == 1 {
		jb, err = json.Marshal(msgs[0])
	} else {
		jb, err = json.Marshal(msgs)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "{\"error\": %q}\n", err.Error())
		return err
	}

	_, err = fmt.Fprintln(stdout, string(jb))
	return err
}
