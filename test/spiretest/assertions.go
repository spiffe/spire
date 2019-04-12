package spiretest

import (
	"reflect"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	protoMessageType = reflect.TypeOf((*proto.Message)(nil)).Elem()
)

func RequireErrorContains(tb testing.TB, err error, contains string) {
	tb.Helper()
	if !AssertErrorContains(tb, err, contains) {
		tb.FailNow()
	}
}

func AssertErrorContains(tb testing.TB, err error, contains string) bool {
	tb.Helper()
	if !assert.Error(tb, err) {
		return false
	}
	if !assert.Contains(tb, err.Error(), contains) {
		return false
	}
	return true
}

func RequireGRPCStatus(tb testing.TB, err error, code codes.Code, message string) {
	tb.Helper()
	if !AssertGRPCStatus(tb, err, code, message) {
		tb.FailNow()
	}
}

func AssertGRPCStatus(tb testing.TB, err error, code codes.Code, message string) bool {
	tb.Helper()
	st := status.Convert(err)
	if !assert.Equal(tb, code, st.Code(), "GRPC status code does not match") {
		return false
	}
	if !assert.Equal(tb, message, st.Message(), "GRPC status message does not match") {
		return false
	}
	return true
}

func RequireGRPCStatusContains(tb testing.TB, err error, code codes.Code, contains string) {
	tb.Helper()
	if !AssertGRPCStatusContains(tb, err, code, contains) {
		tb.FailNow()
	}
}

func AssertGRPCStatusContains(tb testing.TB, err error, code codes.Code, contains string) bool {
	tb.Helper()
	st := status.Convert(err)
	if !assert.Equal(tb, code, st.Code(), "GRPC status code does not match") {
		return false
	}
	if !assert.Contains(tb, st.Message(), contains, "GRPC status message does not contain substring") {
		return false
	}
	return true
}

func RequireProtoListEqual(tb testing.TB, expected, actual interface{}) {
	tb.Helper()
	if !AssertProtoListEqual(tb, expected, actual) {
		tb.FailNow()
	}
}

func AssertProtoListEqual(tb testing.TB, expected, actual interface{}) bool {
	tb.Helper()
	ev := reflect.ValueOf(expected)
	et := ev.Type()
	av := reflect.ValueOf(actual)
	at := av.Type()

	if et.Kind() != reflect.Slice {
		return assert.Fail(tb, "expected value is not a slice")
	}
	if !et.Elem().Implements(protoMessageType) {
		return assert.Fail(tb, "expected value is not a slice of elements that implement proto.Message")
	}

	if at.Kind() != reflect.Slice {
		return assert.Fail(tb, "actual value is not a slice")
	}
	if !at.Elem().Implements(protoMessageType) {
		return assert.Fail(tb, "actual value is not a slice of elements that implement proto.Message")
	}

	if !assert.Equal(tb, ev.Len(), av.Len(), "slice lengths are not equal") {
		return false
	}
	for i := 0; i < ev.Len(); i++ {
		e := ev.Index(i).Interface().(proto.Message)
		a := av.Index(i).Interface().(proto.Message)
		if !AssertProtoEqual(tb, e, a) {
			return false
		}
	}

	return true
}

func RequireProtoEqual(tb testing.TB, expected, actual proto.Message) {
	tb.Helper()
	if !AssertProtoEqual(tb, expected, actual) {
		tb.FailNow()
	}
}

func AssertProtoEqual(tb testing.TB, expected, actual proto.Message) bool {
	tb.Helper()
	if !proto.Equal(expected, actual) {
		// we've already determined they are not equal, but this will give
		// us nice output with the contents.
		return assert.Equal(tb, expected, actual)
	}
	return true
}
