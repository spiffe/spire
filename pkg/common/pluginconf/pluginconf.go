package pluginconf

import (
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
}

func Build[C any](req Request, build func(coreConfig catalog.CoreConfig, hclText string, s *Status) *C) (*C, []string, error) {
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

	config := build(coreConfig, req.GetHclConfiguration(), &s)
	return config, s.notes, s.err
}
