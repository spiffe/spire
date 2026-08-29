package brokercontext

import (
	"context"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc/metadata"
)

const callerIDMetadataKey = "spire-agent-broker-caller-id"

type callerIDKey struct{}

func WithCallerID(ctx context.Context, id spiffeid.ID) context.Context {
	return context.WithValue(ctx, callerIDKey{}, id)
}

func CallerIDFromContext(ctx context.Context) (spiffeid.ID, bool, error) {
	if id, ok := ctx.Value(callerIDKey{}).(spiffeid.ID); ok {
		return id, true, nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return spiffeid.ID{}, false, nil
	}
	values := md.Get(callerIDMetadataKey)
	switch len(values) {
	case 0:
		return spiffeid.ID{}, false, nil
	case 1:
		id, err := spiffeid.FromString(values[0])
		if err != nil {
			return spiffeid.ID{}, false, fmt.Errorf("invalid broker caller SPIFFE ID: %w", err)
		}
		return id, true, nil
	default:
		return spiffeid.ID{}, false, errors.New("multiple broker caller SPIFFE IDs provided")
	}
}

func AppendCallerIDToOutgoingContext(ctx context.Context) context.Context {
	id, ok := ctx.Value(callerIDKey{}).(spiffeid.ID)
	if !ok {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, callerIDMetadataKey, id.String())
}
