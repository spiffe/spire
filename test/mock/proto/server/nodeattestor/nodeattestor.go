// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/spiffe/spire/proto/server/nodeattestor (interfaces: NodeAttestor,NodeAttestorPlugin,NodeAttestor_Attest_Stream)

// Package mock_nodeattestor is a generated GoMock package.
package mock_nodeattestor

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	plugin "github.com/spiffe/spire/proto/common/plugin"
	nodeattestor "github.com/spiffe/spire/proto/server/nodeattestor"
	reflect "reflect"
)

// MockNodeAttestor is a mock of NodeAttestor interface
type MockNodeAttestor struct {
	ctrl     *gomock.Controller
	recorder *MockNodeAttestorMockRecorder
}

// MockNodeAttestorMockRecorder is the mock recorder for MockNodeAttestor
type MockNodeAttestorMockRecorder struct {
	mock *MockNodeAttestor
}

// NewMockNodeAttestor creates a new mock instance
func NewMockNodeAttestor(ctrl *gomock.Controller) *MockNodeAttestor {
	mock := &MockNodeAttestor{ctrl: ctrl}
	mock.recorder = &MockNodeAttestorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockNodeAttestor) EXPECT() *MockNodeAttestorMockRecorder {
	return m.recorder
}

// Attest mocks base method
func (m *MockNodeAttestor) Attest(arg0 context.Context) (nodeattestor.Attest_Stream, error) {
	ret := m.ctrl.Call(m, "Attest", arg0)
	ret0, _ := ret[0].(nodeattestor.Attest_Stream)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Attest indicates an expected call of Attest
func (mr *MockNodeAttestorMockRecorder) Attest(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Attest", reflect.TypeOf((*MockNodeAttestor)(nil).Attest), arg0)
}

// MockNodeAttestorPlugin is a mock of NodeAttestorPlugin interface
type MockNodeAttestorPlugin struct {
	ctrl     *gomock.Controller
	recorder *MockNodeAttestorPluginMockRecorder
}

// MockNodeAttestorPluginMockRecorder is the mock recorder for MockNodeAttestorPlugin
type MockNodeAttestorPluginMockRecorder struct {
	mock *MockNodeAttestorPlugin
}

// NewMockNodeAttestorPlugin creates a new mock instance
func NewMockNodeAttestorPlugin(ctrl *gomock.Controller) *MockNodeAttestorPlugin {
	mock := &MockNodeAttestorPlugin{ctrl: ctrl}
	mock.recorder = &MockNodeAttestorPluginMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockNodeAttestorPlugin) EXPECT() *MockNodeAttestorPluginMockRecorder {
	return m.recorder
}

// Attest mocks base method
func (m *MockNodeAttestorPlugin) Attest(arg0 nodeattestor.Attest_PluginStream) error {
	ret := m.ctrl.Call(m, "Attest", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Attest indicates an expected call of Attest
func (mr *MockNodeAttestorPluginMockRecorder) Attest(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Attest", reflect.TypeOf((*MockNodeAttestorPlugin)(nil).Attest), arg0)
}

// Configure mocks base method
func (m *MockNodeAttestorPlugin) Configure(arg0 context.Context, arg1 *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	ret := m.ctrl.Call(m, "Configure", arg0, arg1)
	ret0, _ := ret[0].(*plugin.ConfigureResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Configure indicates an expected call of Configure
func (mr *MockNodeAttestorPluginMockRecorder) Configure(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Configure", reflect.TypeOf((*MockNodeAttestorPlugin)(nil).Configure), arg0, arg1)
}

// GetPluginInfo mocks base method
func (m *MockNodeAttestorPlugin) GetPluginInfo(arg0 context.Context, arg1 *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	ret := m.ctrl.Call(m, "GetPluginInfo", arg0, arg1)
	ret0, _ := ret[0].(*plugin.GetPluginInfoResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPluginInfo indicates an expected call of GetPluginInfo
func (mr *MockNodeAttestorPluginMockRecorder) GetPluginInfo(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPluginInfo", reflect.TypeOf((*MockNodeAttestorPlugin)(nil).GetPluginInfo), arg0, arg1)
}

// MockNodeAttestor_Attest_Stream is a mock of NodeAttestor_Attest_Stream interface
type MockNodeAttestor_Attest_Stream struct {
	ctrl     *gomock.Controller
	recorder *MockNodeAttestor_Attest_StreamMockRecorder
}

// MockNodeAttestor_Attest_StreamMockRecorder is the mock recorder for MockNodeAttestor_Attest_Stream
type MockNodeAttestor_Attest_StreamMockRecorder struct {
	mock *MockNodeAttestor_Attest_Stream
}

// NewMockNodeAttestor_Attest_Stream creates a new mock instance
func NewMockNodeAttestor_Attest_Stream(ctrl *gomock.Controller) *MockNodeAttestor_Attest_Stream {
	mock := &MockNodeAttestor_Attest_Stream{ctrl: ctrl}
	mock.recorder = &MockNodeAttestor_Attest_StreamMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockNodeAttestor_Attest_Stream) EXPECT() *MockNodeAttestor_Attest_StreamMockRecorder {
	return m.recorder
}

// CloseSend mocks base method
func (m *MockNodeAttestor_Attest_Stream) CloseSend() error {
	ret := m.ctrl.Call(m, "CloseSend")
	ret0, _ := ret[0].(error)
	return ret0
}

// CloseSend indicates an expected call of CloseSend
func (mr *MockNodeAttestor_Attest_StreamMockRecorder) CloseSend() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloseSend", reflect.TypeOf((*MockNodeAttestor_Attest_Stream)(nil).CloseSend))
}

// Context mocks base method
func (m *MockNodeAttestor_Attest_Stream) Context() context.Context {
	ret := m.ctrl.Call(m, "Context")
	ret0, _ := ret[0].(context.Context)
	return ret0
}

// Context indicates an expected call of Context
func (mr *MockNodeAttestor_Attest_StreamMockRecorder) Context() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Context", reflect.TypeOf((*MockNodeAttestor_Attest_Stream)(nil).Context))
}

// Recv mocks base method
func (m *MockNodeAttestor_Attest_Stream) Recv() (*nodeattestor.AttestResponse, error) {
	ret := m.ctrl.Call(m, "Recv")
	ret0, _ := ret[0].(*nodeattestor.AttestResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Recv indicates an expected call of Recv
func (mr *MockNodeAttestor_Attest_StreamMockRecorder) Recv() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Recv", reflect.TypeOf((*MockNodeAttestor_Attest_Stream)(nil).Recv))
}

// Send mocks base method
func (m *MockNodeAttestor_Attest_Stream) Send(arg0 *nodeattestor.AttestRequest) error {
	ret := m.ctrl.Call(m, "Send", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Send indicates an expected call of Send
func (mr *MockNodeAttestor_Attest_StreamMockRecorder) Send(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Send", reflect.TypeOf((*MockNodeAttestor_Attest_Stream)(nil).Send), arg0)
}
