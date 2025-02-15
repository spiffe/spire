package util

import "fmt"

type Int interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

func CheckedCast[To, From Int](v From) (To, error) {
	result := To(v)
	// Check sign is unchanged. This is violated e.g. by int8(-3) -> uint8.
	// Check converting back gives original value. This is violated e.g. by uint16(300) -> uint8.
	if (v < 0) != (result < 0) || From(result) != v {
		return 0, fmt.Errorf("overflow converting %T(%v) to %T", v, v, result)
	}
	// If we got here, then the value can correctly be represented as the 'To' type: success.
	return result, nil
}

func MustCast[To, From Int](v From) To {
	x, err := CheckedCast[To](v)
	if err != nil {
		panic(err)
	}
	return x
}
