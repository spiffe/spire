package structpretty

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrint(t *testing.T) {
	cases := []struct {
		name   string
		s      []interface{}
		stdout string
		stderr string
	}{
		{
			name: "pointer_to_struct_with_bool",
			s: []interface{}{
				&friendlyBool{Foo: true},
			},
			stdout: "Foo: true\n\n",
			stderr: "",
		},
		{
			name: "struct_with_int",
			s: []interface{}{
				friendlyInt{Foo: 42},
			},
			stdout: "Foo: 42\n\n",
			stderr: "",
		},
		{
			name: "struct_with_string",
			s: []interface{}{
				friendlyString{Foo: "bar"},
			},
			stdout: "Foo: bar\n\n",
			stderr: "",
		},
		{
			name: "struct_with_array",
			s: []interface{}{
				friendlyArray{Foo: [1]string{"bar"}},
			},
			stdout: "Foo: [bar]\n\n",
			stderr: "",
		},
		{
			name: "struct_with_slice",
			s: []interface{}{
				friendlySlice{Foo: []string{"bar"}},
			},
			stdout: "Foo: [bar]\n\n",
			stderr: "",
		},
		{
			name: "multiple_structs_different_friendly_types",
			s: []interface{}{
				friendlyBool{Foo: true},
				bigFriendly{
					Foo: "bar",
					Bar: 42,
				},
			},
			stdout: "Foo: true\n\nFoo: bar\nBar: 42\n\n",
			stderr: "",
		},
		{
			name: "struct_with_chan",
			s: []interface{}{
				angryChan{Foo: make(chan string)},
			},
			stdout: "",
			stderr: "",
		},
		{
			name: "struct_with_struct",
			s: []interface{}{
				angryStruct{Foo: struct{}{}},
			},
			stdout: "",
			stderr: "",
		},
		{
			name: "struct_with_Func",
			s: []interface{}{
				angryFunc{Foo: func() {}},
			},
			stdout: "",
			stderr: "",
		},
		{
			name: "multiple_structs_different_angry_types",
			s: []interface{}{
				angryChan{Foo: make(chan string)},
				bigAngry{
					Friendly: false,
				},
			},
			stdout: "Friendly: false\n\n",
			stderr: "",
		},
		{
			name:   "nil_slice",
			s:      nil,
			stdout: "",
			stderr: "",
		},
		{
			name:   "nil_struct",
			s:      []interface{}{nil},
			stdout: "",
			stderr: "",
		},
		{
			name: "empty_struct",
			s: []interface{}{
				struct{}{},
			},
			stdout: "",
			stderr: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}
			err := Print(c.s, stdout, stderr)

			assert.Nil(t, err)
			assert.Equal(t, c.stdout, stdout.String())
			assert.Equal(t, c.stderr, stderr.String())
		})
	}
}

type friendlyBool struct{ Foo bool }
type friendlyInt struct{ Foo int }
type friendlyString struct{ Foo string }
type friendlyArray struct{ Foo [1]string }
type friendlySlice struct{ Foo []string }

type bigFriendly struct {
	Foo string
	Bar int
}

type angryChan struct{ Foo chan (string) }
type angryStruct struct{ Foo struct{} }
type angryFunc struct{ Foo func() }

type bigAngry struct {
	Friendly bool

	AngryChan      chan (string)
	AngryInterface interface{}
}
