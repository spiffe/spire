package logger

import (
	"context"

	"github.com/sirupsen/logrus"
	loggerv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/logger/v1"
	apitype "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	commonlogger "github.com/spiffe/spire/pkg/common/api/logger"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type Logger interface {
	logrus.FieldLogger

	GetLevel() logrus.Level
	SetLevel(level logrus.Level)
}

func RegisterService(s grpc.ServiceRegistrar, service *Service) {
	loggerv1.RegisterLoggerServer(s, service)
}

type Config struct {
	Log Logger
}

type Service struct {
	loggerv1.UnsafeLoggerServer

	log         Logger
	launchLevel logrus.Level
}

func New(c Config) *Service {
	launchLogLevel := c.Log.GetLevel()
	c.Log.WithFields(logrus.Fields{
		telemetry.LaunchLogLevel: launchLogLevel.String(),
	}).Info("Logger service configured")

	return &Service{
		log:         c.Log,
		launchLevel: launchLogLevel,
	}
}

func (s *Service) GetLogger(ctx context.Context, _ *loggerv1.GetLoggerRequest) (*apitype.Logger, error) {
	log := rpccontext.Logger(ctx)
	log.Info("GetLogger Called")

	return s.createAPILogger(), nil
}

func (s *Service) SetLogLevel(ctx context.Context, req *loggerv1.SetLogLevelRequest) (*apitype.Logger, error) {
	log := rpccontext.Logger(ctx)

	if req.NewLevel == apitype.LogLevel_UNSPECIFIED {
		return nil, api.MakeErr(log, codes.InvalidArgument, "newLevel value cannot be LogLevel_UNSPECIFIED", nil)
	}

	newLogLevel, ok := commonlogger.LogrusLevel[req.NewLevel]
	if !ok {
		return nil, api.MakeErr(log, codes.InvalidArgument, "unsupported log level", nil)
	}

	log.WithFields(logrus.Fields{
		telemetry.NewLogLevel: newLogLevel.String(),
	}).Info("SetLogLevel Called")
	s.log.SetLevel(newLogLevel)

	return s.createAPILogger(), nil
}

func (s *Service) ResetLogLevel(ctx context.Context, _ *loggerv1.ResetLogLevelRequest) (*apitype.Logger, error) {
	log := rpccontext.Logger(ctx)
	log.WithField(telemetry.LaunchLogLevel, s.launchLevel.String()).Info("ResetLogLevel Called")

	s.log.SetLevel(s.launchLevel)

	return s.createAPILogger(), nil
}

func (s *Service) createAPILogger() *apitype.Logger {
	return &apitype.Logger{
		CurrentLevel: commonlogger.APILevel[s.log.GetLevel()],
		LaunchLevel:  commonlogger.APILevel[s.launchLevel],
	}
}
