package pluginconf

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/hcl/token"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ReportUnusedKeys reports an error on s listing any keys present in
// unused. If unused is empty, no error is reported.
func ReportUnusedKeys(s *Status, unused map[string][]token.Pos) {
	if len(unused) == 0 {
		return
	}
	keys := make([]string, 0, len(unused))
	for k := range unused {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s.ReportErrorf("unknown configurations detected: %s", strings.Join(keys, ","))
}

type Status struct {
	notes []string
	err   error
}

func (s *Status) ReportInfo(message string) {
	s.notes = append(s.notes, message)
}

func (s *Status) ReportInfof(format string, args ...any) {
	s.ReportInfo(fmt.Sprintf(format, args...))
}

func (s *Status) ReportError(message string) {
	if s.err == nil {
		s.err = status.Error(codes.InvalidArgument, message)
	}
	s.notes = append(s.notes, message)
}

func (s *Status) ReportErrorf(format string, args ...any) {
	s.ReportError(fmt.Sprintf(format, args...))
}

type Request interface {
	GetCoreConfiguration() *configv1.CoreConfiguration
	GetHclConfiguration() string
	GetConfiguration() string
	GetConfigFormat() configv1.ConfigFormat
}

// Config returns the configuration text and format of a request. The text is
// taken from the Configuration field, falling back to HclConfiguration for
// requests from SPIRE versions that only set the latter.
func Config(req Request) (string, catalog.ConfigFormat, error) {
	format, err := catalog.ConfigFormatFromProto(req.GetConfigFormat())
	if err != nil {
		return "", 0, err
	}
	if text := req.GetConfiguration(); text != "" {
		return text, format, nil
	}
	return req.GetHclConfiguration(), format, nil
}

func Build[C any](req Request, build func(coreConfig catalog.CoreConfig, text string, format catalog.ConfigFormat, s *Status) *C) (*C, []string, error) {
	var s Status
	var coreConfig catalog.CoreConfig

	requestCoreConfig := req.GetCoreConfiguration()

	switch {
	case requestCoreConfig == nil:
		s.ReportError("server core configuration is required")
	case requestCoreConfig.TrustDomain == "":
		s.ReportError("server core configuration must contain trust_domain")
	default:
		var err error
		coreConfig.TrustDomain, err = spiffeid.TrustDomainFromString(requestCoreConfig.TrustDomain)
		if err != nil {
			s.ReportErrorf("server core configuration trust_domain is malformed: %v", err)
		}
	}

	text, format, err := Config(req)
	if err != nil {
		s.ReportError(err.Error())
		return nil, s.notes, s.err
	}
	config := build(coreConfig, text, format, &s)
	return config, s.notes, s.err
}
