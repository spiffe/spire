package pluginconf

import (
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/hcl/token"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ReportUnusedKeys reports an error on s listing any keys present in unused.
func ReportUnusedKeys(s *Status, unused map[string][]token.Pos) {
	if len(unused) == 0 {
		return
	}
	keys := make([]string, 0, len(unused))
	for k := range unused {
		keys = append(keys, k)
	}
	slices.Sort(keys)
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

// configText returns the configuration text from the request, preferring
// the new Configuration field over the legacy HclConfiguration field.
func configText(req Request) string {
	if c := req.GetConfiguration(); c != "" {
		return c
	}
	return req.GetHclConfiguration()
}

// configFormat returns the ConfigFormat from the request, defaulting to HCL
// when the new field is unset (old SPIRE sending only hcl_configuration).
func configFormat(req Request) catalog.ConfigFormat {
	if req.GetConfigFormat() == configv1.ConfigFormat_CONFIG_FORMAT_YAML {
		return catalog.ConfigFormatYAML
	}
	return catalog.ConfigFormatHCL
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

	config := build(coreConfig, configText(req), configFormat(req), &s)
	return config, s.notes, s.err
}
