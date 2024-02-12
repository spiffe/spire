package logger

import (
	"context"

	loggerv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type Config struct {
	DefaultLevel logrus.Level
}

type Service struct {
	loggerv1.UnsafeLoggerServer

	DefaultLevel logrus.Level
}

func New(config Config) *Service {
	logrus.WithFields(logrus.Fields{
		"DefaultLevel": config.DefaultLevel,
	}).Info("logger service Configured")
	return &Service{
		DefaultLevel: config.DefaultLevel,
	}
}

func RegisterService(server *grpc.Server, service *Service) {
	loggerv1.RegisterLoggerServer(server, service)
}

func (service *Service) GetLogger(ctx context.Context, req *loggerv1.GetLoggerRequest) (*types.Logger, error) {
	logrus.Info("GetLogger Called")
	logger := &types.Logger{
		CurrentLevel: types.Logger_LogLevel(logrus.GetLevel()),
		DefaultLevel: types.Logger_LogLevel(service.DefaultLevel),
	}
	return logger, nil
}

func (service *Service) SetLogLevel(ctx context.Context, req *loggerv1.SetLogLevelRequest) (*types.Logger, error) {
	logrus.WithFields(logrus.Fields{
		"RequestLevel": loggerv1.SetLogLevelRequest_SetValue_name[int32(req.LogLevel)],
	}).Info("SetLogger Called")
	setLevel := loggerv1.SetLogLevelRequest_SetValue(req.LogLevel)
	if setLevel == loggerv1.SetLogLevelRequest_DEFAULT {
		logrus.SetLevel(service.DefaultLevel)
	} else {
		logrus.SetLevel(logrus.Level(req.LogLevel))
	}
	logger := &types.Logger{
		CurrentLevel: types.Logger_LogLevel(logrus.GetLevel()),
		DefaultLevel: types.Logger_LogLevel(service.DefaultLevel),
	}
	return logger, nil
}
