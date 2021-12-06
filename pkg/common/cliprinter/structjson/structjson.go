package structjson

import (
	"encoding/json"
	"fmt"
	"io"
)

func Print(msgs []interface{}, stdout, stderr io.Writer) bool {
	var jb []byte
	var err error

	if len(msgs) == 0 {
		return true
	}

	if len(msgs) == 1 {
		jb, err = json.Marshal(msgs[0])
	} else {
		jb, err = json.Marshal(msgs)
	}
	if err != nil {
		fmt.Fprintf(stderr, "{\"error\": %q}\n", err.Error())
		return false
	}

	_, err = fmt.Fprintln(stdout, string(jb))
	if err != nil {
		fmt.Fprintf(stderr, "{\"error\": %q}\n", err.Error())
		return false
	}

	return true
}
