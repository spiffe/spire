package cliprinter

import (
	"fmt"
	"strings"
)

const (
	_ formatType = iota
	json
	pretty

	defaultFormatType = pretty
)

type formatType int64

func strToFormatType(f string) (formatType, error) {
	switch strings.ToLower(f) {
	case "json":
		return json, nil
	case "pretty", "prettyprint":
		return pretty, nil
	default:
		return 0, fmt.Errorf("unknown format option: %q", f)
	}
}

func formatTypeToStr(f formatType) string {
	switch f {
	case json:
		return "json"
	case pretty:
		return "pretty"
	default:
		return "unknown"
	}
}
