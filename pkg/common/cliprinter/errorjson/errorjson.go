package errorjson

import (
	"io"

	"github.com/spiffe/spire/pkg/common/cliprinter/structjson"
)

func Print(err error, stdout, stderr io.Writer) bool {
	if err == nil {
		return true
	}

	s := struct {
		E string `json:"error"`
	}{
		E: err.Error(),
	}

	structjson.Print([]interface{}{s}, stdout, stderr)
	return true
}
