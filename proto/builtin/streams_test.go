package builtin

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/stretchr/testify/require"
)

func TestClientSend(t *testing.T) {
	test := NewTest(t)
	defer test.Close()

	clientSend := test.StartClientSend(1)
	value, err := test.ServerRecv()
	test.NoError(err)
	test.NotNil(value)
	test.Equal(int32(1), *value)
	test.NoError(clientSend())
}

func TestClientSendAfterCancellation(t *testing.T) {
	test := NewTest(t)
	defer test.Close()

	test.Cancel()
	test.Equal(context.Canceled, test.ClientSend(1))
}

func TestClientSendAfterClientCloseSend(t *testing.T) {
	test := NewTest(t)
	defer test.Close()

	test.NoError(test.ClientCloseSend())
	test.Equal(io.EOF, test.ClientSend(1))
}

func TestClientSendAfterServerClosed(t *testing.T) {
	test := NewTest(t)
	defer test.Close()

	test.ServerClose(nil)
	test.Equal(io.EOF, test.ClientSend(1))
}

func TestClientSendAndClose(t *testing.T) {
	test := NewTest(t)
	defer test.Close()

	clientSend := test.StartClientSendAndClose(1)
	value, err := test.ServerRecv()
	test.NoError(err)
	test.NotNil(value)
	test.Equal(int32(1), *value)
	test.NoError(clientSend())

	value, err = test.ServerRecv()
	test.Equal(io.EOF, err)
	test.Nil(value)

}

func TestClientRecv(t *testing.T) {
	test := NewTest(t)
	defer test.Close()

	clientRecv := test.StartClientRecv()
	test.NoError(test.ServerSendAndClose(1))
	resp, err := clientRecv()
	test.NotNil(resp)
	test.Equal(int32(1), *resp)
	test.NoError(err)
}

func TestClientRecvAfterCancellation(t *testing.T) {
	test := NewTest(t)
	defer test.Close()

	test.Cancel()
	resp, err := test.ClientCloseAndRecv()
	test.Equal(context.Canceled, err)
	test.Nil(resp)
}

func TestClientRecvAfterServerClosed(t *testing.T) {
	test := NewTest(t)
	defer test.Close()

	test.ServerClose(nil)
	resp, err := test.ClientRecv()
	test.Equal(io.EOF, err)
	test.Nil(resp)
}

func TestServerSendAfterCancellation(t *testing.T) {
	test := NewTest(t)
	defer test.Close()

	test.Cancel()
	test.Equal(context.Canceled, test.ServerSend(1))
}

func TestServerSendAfterClose(t *testing.T) {
	test := NewTest(t)
	defer test.Close()

	test.ServerClose(nil)
	test.Equal(ErrPipeClosed, test.ServerSend(1))
}

func TestServerRecvAfterCancellation(t *testing.T) {
	test := NewTest(t)
	defer test.Close()

	test.Cancel()
	resp, err := test.ServerRecv()
	test.Equal(context.Canceled, err)
	test.Nil(resp)
}

func TestServerRecvAfterClose(t *testing.T) {
	test := NewTest(t)
	defer test.Close()

	test.ServerClose(nil)
	resp, err := test.ServerRecv()
	test.Equal(ErrPipeClosed, err)
	test.Nil(resp)
}

/////////////////////////////////////////////////////////////////////////////
// Helpers
/////////////////////////////////////////////////////////////////////////////

type Test struct {
	*require.Assertions
	cancel     func()
	done       chan struct{}
	clientDone chan struct{}
	serverDone chan struct{}

	clientSend         chan sendRequest
	clientSendAndClose chan sendRequest
	clientRecv         chan recvRequest
	clientCloseAndRecv chan recvRequest
	clientCloseSend    chan closeSendRequest

	serverSend         chan sendRequest
	serverSendAndClose chan sendRequest
	serverRecv         chan recvRequest
	serverClose        chan closeRequest
}

func NewTest(tb testing.TB) *Test {
	ctx, cancel := context.WithCancel(context.Background())

	t := &Test{
		Assertions: require.New(tb),
		cancel:     cancel,
		done:       make(chan struct{}),
		clientDone: make(chan struct{}),
		serverDone: make(chan struct{}),

		clientSend:         make(chan sendRequest),
		clientSendAndClose: make(chan sendRequest),
		clientRecv:         make(chan recvRequest),
		clientCloseAndRecv: make(chan recvRequest),
		clientCloseSend:    make(chan closeSendRequest),

		serverSend:         make(chan sendRequest),
		serverSendAndClose: make(chan sendRequest),
		serverRecv:         make(chan recvRequest),
		serverClose:        make(chan closeRequest),
	}

	client, server := newStreamPipe(ctx)

	go t.client(client)
	go t.server(server)
	return t
}

func (t *Test) client(client *clientStream) {
	defer close(t.clientDone)
	for {
		select {
		case req := <-t.clientSend:
			err := client.Send(valueToProto(req.value))
			req.result <- sendResponse{err: err}
		case req := <-t.clientSendAndClose:
			err := client.SendAndClose(valueToProto(req.value))
			req.result <- sendResponse{err: err}
		case req := <-t.clientRecv:
			value, err := client.Recv()
			req.result <- recvResponse{value: valueFromProto(value), err: err}
		case req := <-t.clientCloseAndRecv:
			value, err := client.CloseAndRecv()
			req.result <- recvResponse{value: valueFromProto(value), err: err}
		case req := <-t.clientCloseSend:
			err := client.CloseSend()
			req.result <- closeSendResponse{err: err}
		case <-t.done:
			return
		}
	}
}

func (t *Test) server(server *serverStream) {
	defer close(t.serverDone)
	for {
		select {
		case req := <-t.serverSend:
			err := server.Send(valueToProto(req.value))
			req.result <- sendResponse{err: err}
		case req := <-t.serverSendAndClose:
			err := server.SendAndClose(valueToProto(req.value))
			req.result <- sendResponse{err: err}
		case req := <-t.serverRecv:
			value, err := server.Recv()
			req.result <- recvResponse{value: valueFromProto(value), err: err}
		case req := <-t.serverClose:
			server.Close(req.err)
			req.result <- closeResponse{}
		case <-t.done:
			return
		}
	}
}

func (t *Test) Cancel() {
	t.cancel()
}

func (t *Test) Close() {
	t.cancel()
	close(t.done)
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-t.clientDone:
	case <-timer.C:
		t.FailNow("timed out", "waiting for test to shut down")
	}
	select {
	case <-t.serverDone:
	case <-timer.C:
		t.FailNow("timed out", "waiting for test to shut down")
	}
}

func (t *Test) ClientSend(value int32) error {
	return t.StartClientSend(value)()
}

func (t *Test) StartClientSend(value int32) func() error {
	return t.startSend(t.clientSend, "client send", value)
}

func (t *Test) ClientSendAndClose(value int32) error {
	return t.StartClientSendAndClose(value)()
}

func (t *Test) StartClientSendAndClose(value int32) func() error {
	return t.startSend(t.clientSendAndClose, "client send-and-close", value)
}

func (t *Test) ClientRecv() (*int32, error) {
	return t.StartClientRecv()()
}

func (t *Test) StartClientRecv() func() (*int32, error) {
	return t.startRecv(t.clientRecv, "client recv")
}

func (t *Test) ClientCloseAndRecv() (*int32, error) {
	return t.StartClientCloseAndRecv()()
}

func (t *Test) StartClientCloseAndRecv() func() (*int32, error) {
	return t.startRecv(t.clientCloseAndRecv, "client close-and-recv")
}

func (t *Test) ClientCloseSend() error {
	return t.StartClientCloseSend()()
}

func (t *Test) StartClientCloseSend() func() error {
	timer := time.NewTimer(5 * time.Second)

	req := closeSendRequest{result: make(chan closeSendResponse, 1)}
	select {
	case t.clientCloseSend <- req:
	case <-timer.C:
		t.FailNow("timed out", "waiting to issue client close-send")
	}

	called := false
	return func() error {
		defer timer.Stop()
		if called {
			t.FailNow("client close-send already completed")
		}
		called = true
		select {
		case resp := <-req.result:
			return resp.err
		case <-timer.C:
			t.FailNow("timed out", "waiting for client close-send result")
			panic("unreachable")
		}
	}
}

func (t *Test) ServerSend(value int32) error {
	return t.startSend(t.serverSend, "server send", value)()
}

func (t *Test) ServerSendAndClose(value int32) error {
	return t.startSend(t.serverSendAndClose, "server send-and-close", value)()
}

func (t *Test) ServerRecv() (*int32, error) {
	return t.startRecv(t.serverRecv, "server recv")()
}

func (t *Test) ServerClose(err error) {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	req := closeRequest{result: make(chan closeResponse, 1), err: err}
	select {
	case t.serverClose <- req:
	case <-timer.C:
		t.FailNow("timed out", "waiting to issue server close")
	}

	select {
	case <-req.result:
	case <-timer.C:
		t.FailNow("timed out", "waiting for server close result")
	}
}

func (t *Test) startSend(send chan sendRequest, desc string, value int32) func() error {
	timer := time.NewTimer(5 * time.Second)

	req := sendRequest{result: make(chan sendResponse, 1), value: value}
	select {
	case send <- req:
	case <-timer.C:
		t.FailNowf("timed out", "waiting to issue %s", desc)
	}

	called := false
	return func() error {
		defer timer.Stop()
		if called {
			t.FailNowf("%s already completed", desc)
		}
		called = true
		select {
		case resp := <-req.result:
			return resp.err
		case <-timer.C:
			t.FailNowf("timed out", "waiting for %s result", desc)
			panic("unreachable")
		}
	}
}

func (t *Test) startRecv(recv chan recvRequest, desc string) func() (*int32, error) {
	timer := time.NewTimer(5 * time.Second)

	req := recvRequest{result: make(chan recvResponse, 1)}
	select {
	case recv <- req:
	case <-timer.C:
		t.FailNowf("timed out", "waiting to issue %s", desc)
	}

	called := false
	return func() (*int32, error) {
		defer timer.Stop()
		if called {
			t.FailNowf("%s already completed", desc)
		}
		called = true
		select {
		case resp := <-req.result:
			return resp.value, resp.err
		case <-timer.C:
			t.FailNowf("timed out", "waiting for %s result", desc)
			panic("unreachable")
		}
	}
}

type sendRequest struct {
	result chan sendResponse
	value  int32
}

type sendResponse struct {
	err error
}

type recvRequest struct {
	result chan recvResponse
}

type recvResponse struct {
	value *int32
	err   error
}

type closeSendRequest struct {
	result chan closeSendResponse
}

type closeSendResponse struct {
	err error
}

type closeRequest struct {
	result chan closeResponse
	err    error
}

type closeResponse struct {
}

func valueToProto(value int32) proto.Message {
	return &wrappers.Int32Value{Value: value}
}

func valueFromProto(value proto.Message) *int32 {
	if value == nil {
		return nil
	}
	return &value.(*wrappers.Int32Value).Value
}
