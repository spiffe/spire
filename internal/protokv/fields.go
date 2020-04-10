package protokv

import (
	"bytes"

	"github.com/gogo/protobuf/proto"
	"github.com/zeebo/errs"
)

type Field interface {
	Num() uint64
	Key(data []byte) (Key, error)
	Encode(keys []Key) ([][]byte, error)
}

// StringField represents a string field
func StringField(num uint64) Field {
	return makeBytesField(num)
}

// Int32Field represents a int32 field
func Int32Field(num uint64) Field {
	return makeBytesField(num)
}

// Uint32Field represents a uint32 field
func Uint32Field(num uint64) Field {
	return makeBytesField(num)
}

// Int64Field represents a int64 field
func Int64Field(num uint64) Field {
	return makeBytesField(num)
}

// Uint64Field represents a uint64 field
func Uint64Field(num uint64) Field {
	return makeBytesField(num)
}

// BoolField represents a bool field
func BoolField(num uint64) Field {
	return makeBytesField(num)
}

// EnumField represents an enum field
func EnumField(num uint64) Field {
	return makeBytesField(num)
}

// MessageField represents a message field
func MessageField(num uint64, field Field, fields ...Field) Field {
	return messageField{
		bytesField: makeBytesField(num),
		fields:     append([]Field{field}, fields...),
	}
}

// RepeatedList represents a repeated field treated as a list
func RepeatedList(field Field) Field {
	return repeatedField{
		Field: field,
		set:   false,
	}
}

// RepeatedSet represents a repeated field treated as a set
func RepeatedSet(field Field) Field {
	return repeatedField{
		Field: field,
		set:   true,
	}
}

type bytesField struct {
	num  uint64
	base []byte
}

func makeBytesField(num uint64) bytesField {
	return bytesField{
		num:  num,
		base: proto.EncodeVarint(num),
	}
}

func (f bytesField) Num() uint64 { return f.num }

func (f bytesField) Key(data []byte) (Key, error) {
	return [][]byte{f.base, data}, nil
}

func (f bytesField) Encode(keys []Key) ([][]byte, error) {
	// Protobuf decoding rules mandate that the last instance of a field
	// be accepted for non-repeated fields. We'll mimic that behavior here.
	if len(keys) == 0 {
		return nil, errs.New("no keys for field %d", f.num)
	}
	return [][]byte{keys[len(keys)-1].Encode(0xff)}, nil
}

type varintField = bytesField

type messageField struct {
	bytesField
	fields []Field
}

func (f messageField) Key(data []byte) (Key, error) {
	messageKey := [][]byte{f.base}

	fieldKeys, err := getFieldKeys(data, f.fields...)
	if err != nil {
		return nil, err
	}
	for _, fieldKey := range fieldKeys {
		for _, key := range fieldKey {
			messageKey = append(messageKey, key...)
		}
	}

	return messageKey, nil
}

func (f messageField) Encode(keys []Key) ([][]byte, error) {
	// Protobuf decoding rules mandate that the last instance of a field
	// be accepted for non-repeated fields. We'll mimic that behavior here.
	if len(keys) == 0 {
		return nil, errs.New("no keys for field %d", f.num)
	}
	key := keys[len(keys)-1]

	buf := bytes.NewBuffer(key[:1].Encode(0xff))
	buf.WriteByte(0xff)
	buf.Write(key[1:].Encode(0xfe))
	return [][]byte{buf.Bytes()}, nil
}

type repeatedField struct {
	Field
	set bool
}

func (f repeatedField) Encode(keys []Key) ([][]byte, error) {
	if f.set {
		// Each key on the field is distinct
		encodedKeys := make([][]byte, 0, len(keys))
		for _, key := range keys {
			encodedKeys = append(encodedKeys, key.Encode(0xff))
		}
		return encodedKeys, nil
	}

	aggregated := Key{
		[]byte{0xfe},
	}
	for _, key := range keys {
		aggregated = append(aggregated, key...)
	}
	return [][]byte{aggregated.Encode(0xff)}, nil
}

type Message struct {
	ID         uint64
	PrimaryKey Field
	Indices    []Field
}

// Key is a slice of bytes. Each element in the slice is a "segment" of the
// key. Before use with the KV, keys are encoded by joining each segment with
// a distinct separator. Bytes matching the separator are escaped.
type Key [][]byte

func (k Key) Encode(sep byte) []byte {
	buf := new(bytes.Buffer)
	for i, segment := range k {
		if i > 0 {
			buf.WriteByte(sep)
		}
		for _, b := range segment {
			if b&0xf0 == 0xf0 {
				buf.WriteByte(0xf0)
				b &= 0x0f
			}
			buf.WriteByte(b)
		}
	}
	return buf.Bytes()
}

type Keys []Key

func EncodeFieldPrefix(msgID uint64, field Field) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, 10+1+10+1))
	buf.Write(proto.EncodeVarint(msgID))
	buf.WriteByte(0xff)
	buf.Write(proto.EncodeVarint(field.Num()))
	buf.WriteByte(0xff)
	return buf.Bytes()
}

func EncodeKeys(msgID uint64, field Field, keys Keys) ([][]byte, error) {
	return encodeKeys(msgID, field, keys, false, nil)
}

func EncodeIndexKeys(msgID uint64, field Field, keys Keys, suffix []byte) ([][]byte, error) {
	return encodeKeys(msgID, field, keys, true, suffix)
}

func encodeKeys(msgID uint64, field Field, keys Keys, index bool, suffix []byte) ([][]byte, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	fieldKeys, err := field.Encode(keys)
	if err != nil {
		return nil, err
	}
	encoded := make([][]byte, 0, len(fieldKeys))
	for _, fieldKey := range fieldKeys {
		// msgid | index key | suffix
		buf := bytes.NewBuffer(make([]byte, 0, 10+1+len(fieldKey)+1+len(suffix)))
		buf.Write(proto.EncodeVarint(msgID))
		buf.WriteByte(0xff)
		buf.Write(fieldKey)
		if index {
			buf.WriteByte(0xff)
			buf.Write(suffix)
		}
		encoded = append(encoded, buf.Bytes())
	}
	return encoded, nil
}

func getFieldKeys(value []byte, fields ...Field) ([]Keys, error) {
	fieldKeys := make([]Keys, len(fields))

	err := enumFields(value, func(num uint64, data []byte) error {
		for i, field := range fields {
			if field.Num() != num {
				continue
			}
			key, err := field.Key(data)
			if err != nil {
				return errs.New("unable to parse key for field %d value: %v", num, err)
			}
			fieldKeys[i] = append(fieldKeys[i], key)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fieldKeys, nil
}

func enumFields(value []byte, cb func(uint64, []byte) error) error {
	left := value
	for len(left) > 0 {
		// pull out the tag
		tag, n := proto.DecodeVarint(left)
		if n == 0 {
			return errs.New("unable to decode tag")
		}
		left = left[n:]

		// determine field number and type
		num := (tag >> 3)
		typ := (tag & 0x02)

		var data []byte

		// map payload
		switch typ {
		// varint
		case 0:
			_, n := proto.DecodeVarint(left)
			if n == 0 {
				return errs.New("unable to decode varint field %d", num)
			}
			data = left[:n]
			left = left[n:]

		// 64-bit
		case 1:
			if len(left) < 8 {
				return errs.New("unable to parse 64-bit field %d", num)
			}
			data = left[:8]
			left = left[8:]

		// length delimited
		case 2:
			ln, n := proto.DecodeVarint(left)
			if n == 0 {
				return errs.New("unable to parse field %d length", num)
			}
			left = left[n:]
			if uint64(len(left)) < ln {
				return errs.New("unable to parse field %d data", num)
			}
			data = left[:ln]
			left = left[ln:]

		// start/end group
		case 3, 4:
			return errs.New("unsupported field %d type %d", num, typ)

		// 32-bit
		case 5:
			if len(left) < 4 {
				return errs.New("unable to parse 32-bit field %d", num)
			}
			data = left[:4]
			left = left[4:]

		default:
			return errs.New("unkown field %d type %d", num, typ)
		}

		if err := cb(num, data); err != nil {
			return err
		}
	}
	return nil
}
