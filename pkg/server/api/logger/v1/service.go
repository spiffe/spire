package logger

import (
	"fmt"
	"context"
	"strings"

	loggerv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	apitype "github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type Config struct {
	LaunchLevel logrus.Level
}

type Service struct {
	loggerv1.UnsafeLoggerServer

	LaunchLevel logrus.Level
}

func New(config Config) *Service {
	logrus.WithFields(logrus.Fields{
		"LaunchLevel": config.LaunchLevel,
	}).Info("logger service Configured")
	return &Service{
		LaunchLevel: config.LaunchLevel,
	}
}

func RegisterService(server *grpc.Server, service *Service) {
	loggerv1.RegisterLoggerServer(server, service)
}

func (service *Service) GetLogger(ctx context.Context, req *loggerv1.GetLoggerRequest) (*apitype.Logger, error) {
	logrus.Info("GetLogger Called")
	logger := &apitype.Logger{
		CurrentLevel: ApiLevel[logrus.GetLevel()],
		LaunchLevel: ApiLevel[service.LaunchLevel],
	}
	return logger, nil
}

func (service *Service) SetLogLevel(ctx context.Context, req *loggerv1.SetLogLevelRequest) (*apitype.Logger, error) {
	if req.NewLevel == apitype.LogLevel_UNSPECIFIED {
		return nil, fmt.Errorf("Invalid request NewLevel value cannot be LogLevel_UNSPECIFIED")
	}
	logrus.WithFields(logrus.Fields{
		"ApiLogLevel": strings.ToLower(apitype.LogLevel_name[int32(req.NewLevel)]),
		"LogrusLevel": LogrusLevel[req.NewLevel].String(),
	}).Info("SetLogLevel Called")
	logrus.SetLevel(LogrusLevel[req.NewLevel])
	logger := &apitype.Logger{
		CurrentLevel: ApiLevel[logrus.GetLevel()],
		LaunchLevel: ApiLevel[service.LaunchLevel],
	}
	return logger, nil
}

func (service *Service) ResetLogLevel(ctx context.Context, req *loggerv1.ResetLogLevelRequest) (*apitype.Logger, error) {
	logrus.Info("ResetLogLevel Called")
	logrus.SetLevel(service.LaunchLevel)
	logger := &apitype.Logger{
		CurrentLevel: ApiLevel[logrus.GetLevel()],
		LaunchLevel: ApiLevel[service.LaunchLevel],
	}
	return logger, nil
}
