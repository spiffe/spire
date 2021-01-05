package endpoints

import (
	"strings"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var (
	deprecationLogMtx   sync.Mutex
	deprecationLogTimes = make(map[string]time.Time)
	deprecationClk      = clock.New()
)

const deprecationLogEvery = time.Hour

func wrapWithDeprecationLogging(log logrus.FieldLogger, unary grpc.UnaryServerInterceptor, stream grpc.StreamServerInterceptor) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
			maybeLogDeprecation(log, info.FullMethod)
			return unary(ctx, req, info, handler)
		},
		func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			maybeLogDeprecation(log, info.FullMethod)
			return stream(srv, ss, info, handler)
		}
}

func maybeLogDeprecation(log logrus.FieldLogger, fullMethod string) {
	if shouldLogDeprecation(fullMethod) {
		msg := "This API is deprecated and will be removed in a future release"
		if strings.HasPrefix(fullMethod, "/spire.api.registration.Registration/") {
			msg += " (see https://github.com/spiffe/spire/blob/master/doc/migrating_registration_api_clients.md)"
		}
		log.WithFields(logrus.Fields{"method": fullMethod}).Warn(msg)
	}
}

func shouldLogDeprecation(fullMethod string) bool {
	now := deprecationClk.Now()

	deprecationLogMtx.Lock()
	defer deprecationLogMtx.Unlock()
	last, ok := deprecationLogTimes[fullMethod]
	if !ok || now.Sub(last) >= deprecationLogEvery {
		deprecationLogTimes[fullMethod] = now
		return true
	}
	return false
}
