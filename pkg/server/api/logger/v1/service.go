package logger

import (
	"context"

	"github.com/sirupsen/logrus"
	loggerv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	apitype "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
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
		telemetry.LaunchLogLevel: launchLogLevel,
	}).Info("Logger service configured")

	return &Service{
		log:         c.Log,
		launchLevel: launchLogLevel,
	}
}

func (s *Service) GetLogger(ctx context.Context, _ *loggerv1.GetLoggerRequest) (*apitype.Logger, error) {
	log := rpccontext.Logger(ctx)
	log.Info("GetLogger Called")

	rpccontext.AuditRPC(ctx)
	return s.createAPILogger(), nil
}

func (s *Service) SetLogLevel(ctx context.Context, req *loggerv1.SetLogLevelRequest) (*apitype.Logger, error) {
	rpccontext.AddRPCAuditFields(ctx, logrus.Fields{telemetry.NewLogLevel: req.NewLevel})
	log := rpccontext.Logger(ctx)

	if req.NewLevel == apitype.LogLevel_UNSPECIFIED {
		return nil, api.MakeErr(log, codes.InvalidArgument, "newLevel value cannot be LogLevel_UNSPECIFIED", nil)
	}

	newLogLevel, ok := LogrusLevel[req.NewLevel]
	if !ok {
		return nil, api.MakeErr(log, codes.InvalidArgument, "unsupported log level", nil)
	}

	log.WithFields(logrus.Fields{
		telemetry.NewLogLevel: newLogLevel.String(),
	}).Info("SetLogLevel Called")
	s.log.SetLevel(newLogLevel)

	rpccontext.AuditRPC(ctx)
	return s.createAPILogger(), nil
}

func (s *Service) ResetLogLevel(ctx context.Context, _ *loggerv1.ResetLogLevelRequest) (*apitype.Logger, error) {
	log := rpccontext.Logger(ctx)
	log.WithField(telemetry.LaunchLogLevel, s.launchLevel).Info("ResetLogLevel Called")

	s.log.SetLevel(s.launchLevel)

	rpccontext.AuditRPC(ctx)
	return s.createAPILogger(), nil
}

func (s *Service) createAPILogger() *apitype.Logger {
	return &apitype.Logger{
		CurrentLevel: APILevel[s.log.GetLevel()],
		LaunchLevel:  APILevel[s.launchLevel],
	}
}
