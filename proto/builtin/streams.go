package builtin

import (
	"context"
	"errors"
	"io"

	"github.com/golang/protobuf/proto"
)

var (
	ErrPipeClosed = errors.New("pipe closed")
)

type SendStreamClient interface {
	Context() context.Context
	Send(proto.Message) error
	CloseAndRecv() (proto.Message, error)
}

type SendStreamServer interface {
	Context() context.Context
	SendAndClose(proto.Message) error
	Recv() (proto.Message, error)
	Close(err error)
}

func SendStreamPipe(ctx context.Context) (SendStreamClient, SendStreamServer) {
	return newStreamPipe(ctx)
}

type RecvStreamClient interface {
	Context() context.Context
	Recv() (proto.Message, error)
}

type RecvStreamServer interface {
	Context() context.Context
	Send(proto.Message) error
	Close(err error)
}

func RecvStreamPipe(ctx context.Context) (RecvStreamClient, RecvStreamServer) {
	return newStreamPipe(ctx)
}

type BidiStreamClient interface {
	Context() context.Context
	Send(proto.Message) error
	Recv() (proto.Message, error)
	CloseSend() error
}

type BidiStreamServer interface {
	Context() context.Context
	Send(proto.Message) error
	Recv() (proto.Message, error)
	Close(err error)
}

func BidiStreamPipe(ctx context.Context) (BidiStreamClient, BidiStreamServer) {
	return newStreamPipe(ctx)
}

type clientStream struct {
	ctx  context.Context
	send chan<- proto.Message
	recv <-chan proto.Message
	pipe chan error
}

func newClientStream(ctx context.Context,
	send chan<- proto.Message, recv <-chan proto.Message,
	pipe chan error) *clientStream {
	return &clientStream{
		ctx:  ctx,
		send: send,
		recv: recv,
		pipe: pipe,
	}
}

func (s *clientStream) Context() context.Context {
	return s.ctx
}

func (s *clientStream) Send(m proto.Message) error {
	if s.send == nil {
		return io.EOF
	}
	select {
	// If the stream has been closed (by an error or otherwise), then Send()
	// returns io.EOF. The client will discover the error when doing a Recv().
	case err := <-s.pipe:
		// prevent sends on this stream
		s.send = nil
		// reinsert the pipe error back into the channel so it can be piped up
		// by subsequent calls to Send() or Recv()
		s.pipe <- err
		return io.EOF
	case s.send <- proto.Clone(m):
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *clientStream) Recv() (proto.Message, error) {
	select {
	// "pipe" errors are communicated during Recv(). If the server closed
	// without an error, Recv() should return an io.EOF. The server stream
	// disallows sending after being closed, so the recv channel case won't
	// compete with this one.
	case err := <-s.pipe:
		// prevent receives on this stream
		s.recv = nil
		// reinsert the pipe error back into the channel so it can be piped up
		// by subsequent calls to Send() or Recv()
		s.pipe <- err
		if err == nil {
			err = io.EOF
		}
		return nil, err
	case m := <-s.recv:
		return m, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *clientStream) CloseSend() error {
	if s.send != nil {
		close(s.send)
		s.send = nil
	}
	return nil
}

func (s *clientStream) SendAndClose(m proto.Message) error {
	if err := s.Send(m); err != nil {
		return err
	}
	return s.CloseSend()
}

func (s *clientStream) CloseAndRecv() (proto.Message, error) {
	if err := s.CloseSend(); err != nil {
		return nil, err
	}
	return s.Recv()
}

type serverStream struct {
	ctx  context.Context
	send chan<- proto.Message
	recv <-chan proto.Message
	pipe chan error
	done chan struct{}
}

func newServerStream(ctx context.Context,
	send chan<- proto.Message, recv <-chan proto.Message,
	pipe chan error) *serverStream {
	return &serverStream{
		ctx:  ctx,
		send: send,
		recv: recv,
		pipe: pipe,
		done: make(chan struct{}),
	}
}

func (s *serverStream) Context() context.Context {
	return s.ctx
}

func (s *serverStream) Send(m proto.Message) error {
	select {
	// When the stream is closed by the server (by an error or otherwise),
	// the pipe channel receives the result and is then nil'd out. The send
	// channel is also nil'd out, which means this case should be the only
	// contender for selection.
	case <-s.done:
		return ErrPipeClosed
	case s.send <- proto.Clone(m):
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *serverStream) Recv() (proto.Message, error) {
	select {
	// See Send(). This case should only be selected if the server has already
	// closed the pipe.
	case <-s.done:
		return nil, ErrPipeClosed
	// If this case is selected, then either the pipe has been closed by the
	// server (recv channel is set to nil) or the client has closed its "send"
	// pipe.
	case m := <-s.recv:
		if m == nil {
			return nil, io.EOF
		}
		return m, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *serverStream) SendAndClose(m proto.Message) error {
	if err := s.Send(m); err != nil {
		return err
	}
	s.Close(nil)
	return nil
}

// Close should only be called when the server is finished with the stream. No
// calls should be made to the server stream methods after calling close.
func (s *serverStream) Close(err error) {
	if s.pipe != nil {
		s.pipe <- err
		close(s.done)
		// prevent these channels from being selected in the server
		// Recv() and Send()
		s.send = nil
		s.recv = nil
	}
}

func newStreamPipe(ctx context.Context) (*clientStream, *serverStream) {
	clientToServer := make(chan proto.Message)
	serverToClient := make(chan proto.Message)
	pipe := make(chan error, 1)

	client := newClientStream(ctx, clientToServer, serverToClient, pipe)
	server := newServerStream(ctx, serverToClient, clientToServer, pipe)
	return client, server
}
