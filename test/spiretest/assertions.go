package spiretest

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
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
	if code != st.Code() || message != st.Message() {
		return assert.Fail(tb, fmt.Sprintf("Status code=%q msg=%q does not match code=%q msg=%q", st.Code(), st.Message(), code, message))
	}
	return true
}

func RequireGRPCStatusContains(tb testing.TB, err error, code codes.Code, contains string, msgAndArgs ...any) {
	tb.Helper()
	if !AssertGRPCStatusContains(tb, err, code, contains, msgAndArgs...) {
		tb.FailNow()
	}
}

func AssertGRPCStatusContains(tb testing.TB, err error, code codes.Code, contains string, msgAndArgs ...any) bool {
	tb.Helper()

	if code == codes.OK {
		if contains != "" {
			return assert.Fail(tb, "cannot assert that an OK status has message %q", contains)
		}
		return AssertGRPCStatus(tb, err, code, "")
	}

	st := status.Convert(err)
	if code != st.Code() || !strings.Contains(st.Message(), contains) {
		return assert.Fail(tb, fmt.Sprintf("Status code=%q msg=%q does not match code=%q with message containing %q", st.Code(), st.Message(), code, contains), msgAndArgs...)
	}
	return true
}

func RequireGRPCStatusHasPrefix(tb testing.TB, err error, code codes.Code, prefix string) {
	tb.Helper()
	if !AssertGRPCStatusHasPrefix(tb, err, code, prefix) {
		tb.FailNow()
	}
}

func AssertGRPCStatusHasPrefix(tb testing.TB, err error, code codes.Code, prefix string) bool {
	tb.Helper()
	st := status.Convert(err)
	if code != st.Code() || !strings.HasPrefix(st.Message(), prefix) {
		return assert.Fail(tb, fmt.Sprintf("Status code=%q msg=%q does not match code=%q with message prefix %q", st.Code(), st.Message(), code, prefix))
	}
	return true
}

func RequireProtoListEqual(tb testing.TB, expected, actual any) {
	tb.Helper()
	if !AssertProtoListEqual(tb, expected, actual) {
		tb.FailNow()
	}
}

func AssertProtoListEqual(tb testing.TB, expected, actual any) bool {
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

	if !assert.Equal(tb, ev.Len(), av.Len(), "expected %d elements in list; got %d", ev.Len(), av.Len()) {
		return false
	}
	for i := 0; i < ev.Len(); i++ {
		e := ev.Index(i).Interface().(proto.Message)
		a := av.Index(i).Interface().(proto.Message)
		if !AssertProtoEqual(tb, e, a, "proto %d in list is not equal", i) {
			return false
		}
	}

	return true
}

func RequireProtoEqual(tb testing.TB, expected, actual proto.Message, msgAndArgs ...any) {
	tb.Helper()
	if !AssertProtoEqual(tb, expected, actual, msgAndArgs...) {
		tb.FailNow()
	}
}

func AssertProtoEqual(tb testing.TB, expected, actual proto.Message, msgAndArgs ...any) bool {
	tb.Helper()
	return assert.Empty(tb, cmp.Diff(expected, actual, protocmp.Transform()), msgAndArgs...)
}

func RequireErrorPrefix(tb testing.TB, err error, prefix string) {
	tb.Helper()
	if !AssertErrorPrefix(tb, err, prefix) {
		tb.FailNow()
	}
}

func AssertErrorPrefix(tb testing.TB, err error, prefix string) bool {
	tb.Helper()
	if err == nil || !strings.HasPrefix(err.Error(), prefix) {
		return assert.Fail(tb, fmt.Sprintf("error %v does not have prefix %q", err, prefix))
	}
	return true
}

func AssertHasPrefix(tb testing.TB, msg string, prefix string) bool {
	tb.Helper()
	if !strings.HasPrefix(msg, prefix) {
		return assert.Fail(tb, fmt.Sprintf("string %q does not have prefix %q", msg, prefix))
	}
	return true
}
