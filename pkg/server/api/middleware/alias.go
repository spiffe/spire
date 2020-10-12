package middleware

import (
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc"
)

type Middleware = middleware.Middleware
type PreprocessFunc = middleware.PreprocessFunc
type PostprocessFunc = middleware.PostprocessFunc

func Preprocess(fn PreprocessFunc) Middleware {
	return middleware.Preprocess(fn)
}

func Postprocess(fn PostprocessFunc) Middleware {
	return middleware.Postprocess(fn)
}

func Funcs(preprocess PreprocessFunc, postprocess PostprocessFunc) Middleware {
	return middleware.Funcs(preprocess, postprocess)
}

func Chain(ms ...Middleware) Middleware {
	return middleware.Chain(ms...)
}

func WithLogger(log logrus.FieldLogger) Middleware {
	return middleware.WithLogger(log)
}

func WithMetrics(metrics telemetry.Metrics) Middleware {
	return middleware.WithMetrics(metrics)
}

func Interceptors(m Middleware) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	return middleware.Interceptors(m)
}

func UnaryInterceptor(m Middleware) grpc.UnaryServerInterceptor {
	return middleware.UnaryInterceptor(m)
}

func StreamInterceptor(m Middleware) grpc.StreamServerInterceptor {
	return middleware.StreamInterceptor(m)
}
