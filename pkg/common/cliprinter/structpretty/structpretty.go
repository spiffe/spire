package structpretty

import (
	"fmt"
	"io"
	"reflect"
	"strings"
)

// Print prints a struct prettily.
// It will print only easily printable types, and only to one
// level of depth. It will print arrays, slices, and maps if
// their keys and elements are also easily printable types.
func Print(msgs []interface{}, stdout, stderr io.Writer) bool {
	if msgs == nil || len(msgs) == 0 {
		return true
	}

	for _, msg := range msgs {
		if msg == nil {
			continue
		}

		printStruct(msg, stdout, stderr)
	}

	return true
}

func printStruct(msg interface{}, stdout, _ io.Writer) {
	msgType := reflect.TypeOf(msg)
	msgValue := reflect.ValueOf(msg)

	// We also want to accept pointers to structs
	if reflect.TypeOf(msg).Kind() == reflect.Ptr {
		if reflect.TypeOf(msg).Elem().Kind() != reflect.Struct {
			return
		}

		msgType = msgType.Elem()
		msgValue = msgValue.Elem()
	}

	if msgType.Kind() != reflect.Struct {
		return
	}

	builder := new(strings.Builder)
	for i := 0; i < msgType.NumField(); i++ {
		fieldType := msgType.Field(i)
		fieldValue := msgValue.Field(i)

		if !fieldType.IsExported() {
			continue
		}

		if !isFieldTypePrintable(fieldType.Type) {
			continue
		}

		n := fieldType.Name
		v := fieldValue.Interface()
		line := fmt.Sprintf("%s: %v\n", n, v)
		builder.WriteString(line)
	}

	if builder.Len() > 0 {
		fmt.Fprint(stdout, builder.String())
		fmt.Fprintf(stdout, "\n")
	}
}

func isFieldTypePrintable(t reflect.Type) bool {
	if isUnprintableType(t) {
		return false
	}

	switch t.Kind() {
	case reflect.Array, reflect.Slice:
		return isArrayPrintable(t)
	case reflect.Map:
		return isMapPrintable(t)
	}

	return true
}

func isArrayPrintable(t reflect.Type) bool {
	return isCompositeTypePrintable(t.Elem())
}

func isMapPrintable(t reflect.Type) bool {
	keyOk := isCompositeTypePrintable(t.Key())
	elemOk := isCompositeTypePrintable(t.Elem())
	return keyOk && elemOk
}

func isCompositeTypePrintable(t reflect.Type) bool {
	return !isUnprintableType(t) && !isListType(t)
}

func isUnprintableType(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Invalid, reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Ptr, reflect.Struct, reflect.UnsafePointer:

		return true
	default:
		return false
	}
}

func isListType(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Array, reflect.Slice, reflect.Map:
		return true
	default:
		return false
	}
}
