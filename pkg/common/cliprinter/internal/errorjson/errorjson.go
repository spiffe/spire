package errorjson

import (
	"io"

	"github.com/spiffe/spire/pkg/common/cliprinter/internal/structjson"
)

func Print(err error, stdout, stderr io.Writer) error {
	if err == nil {
		return nil
	}

	s := struct {
		E string `json:"error"`
	}{
		E: err.Error(),
	}

	return structjson.Print([]any{s}, stdout, stderr)
}
