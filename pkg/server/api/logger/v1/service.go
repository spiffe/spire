package logger

import (
	"context"
	"fmt"

	loggerv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	apitype "github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type Logger interface {
	logrus.FieldLogger
	GetLevel() logrus.Level
	SetLevel(level logrus.Level)
}

type Config struct {
	Log         Logger
	LaunchLevel logrus.Level
}

type Service struct {
	loggerv1.UnsafeLoggerServer

	log         Logger
	launchLevel logrus.Level
}

func New(config Config) *Service {
	config.Log.WithFields(logrus.Fields{
		"LaunchLevel": config.LaunchLevel,
	}).Info("Logger service configured")
	return &Service{
		log:         config.Log,
		launchLevel: config.LaunchLevel,
	}
}

func RegisterService(s grpc.ServiceRegistrar, service *Service) {
	loggerv1.RegisterLoggerServer(s, service)
}

func (service *Service) GetLogger(_ context.Context, _ *loggerv1.GetLoggerRequest) (*apitype.Logger, error) {
	service.log.Info("GetLogger Called")
	logger := &apitype.Logger{
		CurrentLevel: APILevel[service.log.GetLevel()],
		LaunchLevel:  APILevel[service.launchLevel],
	}
	return logger, nil
}

func (service *Service) SetLogLevel(_ context.Context, req *loggerv1.SetLogLevelRequest) (*apitype.Logger, error) {
	if req.NewLevel == apitype.LogLevel_UNSPECIFIED {
		return nil, fmt.Errorf("Invalid request, NewLevel value cannot be LogLevel_UNSPECIFIED")
	}
	service.log.WithFields(logrus.Fields{
		"NewLevel": LogrusLevel[req.NewLevel].String(),
	}).Info("SetLogLevel Called")
	service.log.SetLevel(LogrusLevel[req.NewLevel])
	logger := &apitype.Logger{
		CurrentLevel: APILevel[service.log.GetLevel()],
		LaunchLevel:  APILevel[service.launchLevel],
	}
	return logger, nil
}

func (service *Service) ResetLogLevel(_ context.Context, _ *loggerv1.ResetLogLevelRequest) (*apitype.Logger, error) {
	service.log.Info("ResetLogLevel Called")
	service.log.SetLevel(service.launchLevel)
	logger := &apitype.Logger{
		CurrentLevel: APILevel[service.log.GetLevel()],
		LaunchLevel:  APILevel[service.launchLevel],
	}
	return logger, nil
}
