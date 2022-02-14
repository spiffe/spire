package agentpathtemplate

import (
	"bytes"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"golang.org/x/time/rate"
)

var (
	ensureLeadingSlashLog        logrus.FieldLogger
	ensureLeadingSlashLogLimiter = rate.NewLimiter(rate.Every(time.Minute), 1)
)

// Parse parses an agent path template. It changes the behavior for missing
// keys to return an error instead of the default behavior, which renders a
// value that requires percent-encoding to include in a URI, which is against
// the SPIFFE specification.
func Parse(text string) (*Template, error) {
	tmpl, err := template.New("agent-path").Option("missingkey=error").Parse(text)
	if err != nil {
		return nil, err
	}
	return &Template{tmpl: tmpl}, nil
}

// MustParse parses an agent path template. It changes the behavior for missing
// keys to return an error instead of the default behavior, which renders a
// value that requires percent-encoding to include in a URI, which is against
// the SPIFFE specification. If parsing fails, the function panics.
func MustParse(text string) *Template {
	tmpl, err := Parse(text)
	if err != nil {
		panic(err)
	}
	return tmpl
}

type Template struct {
	tmpl *template.Template
}

func (t *Template) Execute(args interface{}) (string, error) {
	buf := new(bytes.Buffer)
	if err := t.tmpl.Execute(buf, args); err != nil {
		return "", err
	}
	path := buf.String()

	// Deprecated: remove in SPIRE 1.3
	ensuredPath, modified := idutil.EnsureLeadingSlashForBackcompat(path)
	if modified && ensureLeadingSlashLog != nil && ensureLeadingSlashLogLimiter.Allow() {
		ensureLeadingSlashLog.WithField(telemetry.Path, path).
			Warn("Support for agent path templates which produce paths without leading slashes are deprecated and will be removed in a future release")
	}

	return ensuredPath, nil
}

// SetEnsureLeadingSlashLog sets the logger used to report "ensure leading slash"
// related deprecation warnings. Called by server/server.go. This is a hack.
// Deprecated: remove in SPIRE 1.3
func SetEnsureLeadingSlashLog(log logrus.FieldLogger) {
	ensureLeadingSlashLog = log
}
