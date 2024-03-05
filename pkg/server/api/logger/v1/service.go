package logger

import (
	"context"
	"fmt"
	"strings"

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
	Log Logger
	LaunchLevel logrus.Level
}

type Service struct {
	loggerv1.UnsafeLoggerServer

	log Logger
	launchLevel logrus.Level
}

func New(config Config) *Service {
	config.Log.WithFields(logrus.Fields{
		"LaunchLevel": config.LaunchLevel,
	}).Info("Logger service Configured")
	return &Service{
		log:         config.Log,
		launchLevel: config.LaunchLevel,
	}
}

func RegisterService(server *grpc.Server, service *Service) {
	loggerv1.RegisterLoggerServer(server, service)
}

func (service *Service) GetLogger(ctx context.Context, req *loggerv1.GetLoggerRequest) (*apitype.Logger, error) {
	service.log.Info("GetLogger Called")
	logger := &apitype.Logger{
		CurrentLevel: ApiLevel[service.log.GetLevel()],
		LaunchLevel: ApiLevel[service.launchLevel],
	}
	return logger, nil
}

func (service *Service) SetLogLevel(ctx context.Context, req *loggerv1.SetLogLevelRequest) (*apitype.Logger, error) {
	if req.NewLevel == apitype.LogLevel_UNSPECIFIED {
		return nil, fmt.Errorf("Invalid request NewLevel value cannot be LogLevel_UNSPECIFIED")
	}
	service.log.WithFields(logrus.Fields{
		"ApiLogLevel": strings.ToLower(apitype.LogLevel_name[int32(req.NewLevel)]),
		"LogrusLevel": LogrusLevel[req.NewLevel].String(),
	}).Info("SetLogLevel Called")
	service.log.SetLevel(LogrusLevel[req.NewLevel])
	logger := &apitype.Logger{
		CurrentLevel: ApiLevel[service.log.GetLevel()],
		LaunchLevel: ApiLevel[service.launchLevel],
	}
	return logger, nil
}

func (service *Service) ResetLogLevel(ctx context.Context, req *loggerv1.ResetLogLevelRequest) (*apitype.Logger, error) {
	service.log.Info("ResetLogLevel Called")
	service.log.SetLevel(service.launchLevel)
	logger := &apitype.Logger{
		CurrentLevel: ApiLevel[service.log.GetLevel()],
		LaunchLevel: ApiLevel[service.launchLevel],
	}
	return logger, nil
}
