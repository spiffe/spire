package structpretty

import (
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/spiffe/spire/pkg/common/cliprinter/internal/errorpretty"
)

// Print prints a struct prettily.
// It will print only easily printable types, and only to one
// level of depth. It will print arrays, slices, and maps if
// their keys and elements are also easily printable types.
func Print(msgs []any, stdout, stderr io.Writer) error {
	if len(msgs) == 0 {
		return nil
	}

	for _, msg := range msgs {
		if msg == nil {
			continue
		}

		err := printStruct(msg, stdout, stderr)
		if err != nil {
			return err
		}
	}

	return nil
}

func printStruct(msg any, stdout, stderr io.Writer) error {
	msgType := reflect.TypeOf(msg)
	msgValue := reflect.ValueOf(msg)

	// We also want to accept pointers to structs
	if msgType.Kind() == reflect.Ptr {
		if msgType.Elem().Kind() != reflect.Struct {
			err := fmt.Errorf("cannot print unsupported type %q", msgType.Elem().Kind().String())
			_ = errorpretty.Print(err, stdout, stderr)
			return err
		}

		msgType = msgType.Elem()
		msgValue = msgValue.Elem()
	}

	if msgType.Kind() != reflect.Struct {
		err := fmt.Errorf("cannot print unsupported type %q", msgType.Kind().String())
		_ = errorpretty.Print(err, stdout, stderr)
		return err
	}

	builder := new(strings.Builder)
	for i := range msgType.NumField() {
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
		_, err := fmt.Fprint(stdout, builder.String())
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(stdout, "\n")
		if err != nil {
			return err
		}
	}

	return nil
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
