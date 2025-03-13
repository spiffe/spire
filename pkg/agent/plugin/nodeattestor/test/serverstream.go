package nodeattestortest

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ServerStreamHandler is a function used to handle payloads or challenge
// responses sent to the stream.
type ServerStreamHandler = func(payloadOrChallengeResponse []byte) (challenge []byte, err error)

// ServerStreamBuilder is used to build server streams for testing.
type ServerStreamBuilder struct {
	pluginName string
	handlers   []ServerStreamHandler
}

// ServerStream initializes a new server stream builder for the given plugin
// name. Attestation data received by the stream will have its type validated
// against the plugin name.
func ServerStream(pluginName string) *ServerStreamBuilder {
	return &ServerStreamBuilder{
		pluginName: pluginName,
	}
}

// Build builds a stream with the configured handlers
func (b *ServerStreamBuilder) Build() nodeattestor.ServerStream {
	return &serverStream{
		pluginName: b.pluginName,
		handlers:   b.handlers,
	}
}

// Handle adds an arbitrary handler. If the handler returns a challenge then it
// is expected that the stream will be called again.
func (b *ServerStreamBuilder) Handle(handler ServerStreamHandler) *ServerStreamBuilder {
	return b.addHandler(handler)
}

// ExpectThenChallenge adds an intermediate handler that asserts that the given
// payload or challenge response is received and then issues the given
// challenge. It returns a new builder with that handler added.
func (b *ServerStreamBuilder) ExpectThenChallenge(payloadOrChallengeResponse, challenge []byte) *ServerStreamBuilder {
	return b.Handle(func(actual []byte) ([]byte, error) {
		if string(actual) != string(payloadOrChallengeResponse) {
			return nil, status.Errorf(codes.InvalidArgument, "expected attestation payload %q; got %q", string(payloadOrChallengeResponse), string(actual))
		}
		return challenge, nil
	})
}

// IgnoreThenChallenge adds an intermediate handler that ignores the payload or
// challenge response and then issues the given challenge. It returns a new
// builder with that handler added.
func (b *ServerStreamBuilder) IgnoreThenChallenge(challenge []byte) *ServerStreamBuilder {
	return b.Handle(func(actual []byte) ([]byte, error) {
		return challenge, nil
	})
}

// ExpectAndBuild adds a final handler wherein the server stream expects to
// receive the given payload or challenge response. It returns a built server
// stream, since the stream does not issue another challenge at this point and
// will fail if invoked again.
func (b *ServerStreamBuilder) ExpectAndBuild(payloadOrChallengeResponse []byte) nodeattestor.ServerStream {
	return b.ExpectThenChallenge(payloadOrChallengeResponse, nil).Build()
}

// FailAndBuild adds a final handler wherein the server stream fails with the
// given error.  It returns a built server stream, since the stream does not
// issue another challenge at this point and will fail if invoked again.
func (b *ServerStreamBuilder) FailAndBuild(err error) nodeattestor.ServerStream {
	return b.addHandler(func([]byte) ([]byte, error) {
		return nil, err
	}).Build()
}

func (b *ServerStreamBuilder) addHandler(handler ServerStreamHandler) *ServerStreamBuilder {
	handlers := slices.Clone(b.handlers)
	handlers = append(handlers, handler)
	return &ServerStreamBuilder{
		pluginName: b.pluginName,
		handlers:   handlers,
	}
}

type serverStream struct {
	pluginName string
	handlers   []ServerStreamHandler
}

func (ss *serverStream) SendAttestationData(_ context.Context, attestationData nodeattestor.AttestationData) ([]byte, error) {
	if attestationData.Type != ss.pluginName {
		return nil, fmt.Errorf("expected attestation type %q; got %q", ss.pluginName, attestationData.Type)
	}
	if len(ss.handlers) == 0 {
		return nil, errors.New("stream received unexpected attestation data")
	}
	return ss.handle(attestationData.Payload)
}

func (ss *serverStream) SendChallengeResponse(_ context.Context, challengeResponse []byte) ([]byte, error) {
	if len(ss.handlers) == 0 {
		return nil, errors.New("stream received unexpected challenge response")
	}
	return ss.handle(challengeResponse)
}

func (ss *serverStream) handle(payloadOrChallengeResponse []byte) (challenge []byte, err error) {
	handler := ss.handlers[0]
	ss.handlers = ss.handlers[1:]
	return handler(payloadOrChallengeResponse)
}
