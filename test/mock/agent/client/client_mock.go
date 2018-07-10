// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/spiffe/spire/pkg/agent/client (interfaces: Client)

// Package mock_client is a generated GoMock package.
package mock_client

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	client "github.com/spiffe/spire/pkg/agent/client"
	node "github.com/spiffe/spire/proto/api/node"
	reflect "reflect"
)

// MockClient is a mock of Client interface
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// FetchJWTASVID mocks base method
func (m *MockClient) FetchJWTASVID(arg0 context.Context, arg1 *node.JSR) (*client.JWTASVID, error) {
	ret := m.ctrl.Call(m, "FetchJWTASVID", arg0, arg1)
	ret0, _ := ret[0].(*client.JWTASVID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FetchJWTASVID indicates an expected call of FetchJWTASVID
func (mr *MockClientMockRecorder) FetchJWTASVID(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FetchJWTASVID", reflect.TypeOf((*MockClient)(nil).FetchJWTASVID), arg0, arg1)
}

// FetchUpdates mocks base method
func (m *MockClient) FetchUpdates(arg0 context.Context, arg1 *node.FetchX509SVIDRequest) (*client.Update, error) {
	ret := m.ctrl.Call(m, "FetchUpdates", arg0, arg1)
	ret0, _ := ret[0].(*client.Update)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FetchUpdates indicates an expected call of FetchUpdates
func (mr *MockClientMockRecorder) FetchUpdates(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FetchUpdates", reflect.TypeOf((*MockClient)(nil).FetchUpdates), arg0, arg1)
}

// Release mocks base method
func (m *MockClient) Release() {
	m.ctrl.Call(m, "Release")
}

// Release indicates an expected call of Release
func (mr *MockClientMockRecorder) Release() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Release", reflect.TypeOf((*MockClient)(nil).Release))
}
