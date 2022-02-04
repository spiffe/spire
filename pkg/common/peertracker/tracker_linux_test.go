//go:build linux

package peertracker

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseTaskStat(t *testing.T) {
	tests := []struct {
		data   string
		fields []string
		err    error
	}{
		{
			data:   "1 (cmd) S 0 1 1 0 -1 4194560 30901 1011224 96 1826 185 2546 3273 2402 20 0 1 0 24 170409984 2900 18446744073709551615 1 1 0 0 0 0 671173123 4096 1260 0 0 0 17 7 0 0 12 0 0 0 0 0 0 0 0 0 0",
			fields: []string{"1", "cmd", "S", "0", "1", "1", "0", "-1", "4194560", "30901", "1011224", "96", "1826", "185", "2546", "3273", "2402", "20", "0", "1", "0", "24", "170409984", "2900", "18446744073709551615", "1", "1", "0", "0", "0", "0", "671173123", "4096", "1260", "0", "0", "0", "17", "7", "0", "0", "12", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
			err:    nil,
		},
		{
			data:   "1 (the cmd) S 0 1 1 0 -1 4194560 30901 1011224 96 1826 185 2546 3273 2402 20 0 1 0 24 170409984 2900 18446744073709551615 1 1 0 0 0 0 671173123 4096 1260 0 0 0 17 7 0 0 12 0 0 0 0 0 0 0 0 0 0",
			fields: []string{"1", "the cmd", "S", "0", "1", "1", "0", "-1", "4194560", "30901", "1011224", "96", "1826", "185", "2546", "3273", "2402", "20", "0", "1", "0", "24", "170409984", "2900", "18446744073709551615", "1", "1", "0", "0", "0", "0", "671173123", "4096", "1260", "0", "0", "0", "17", "7", "0", "0", "12", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
			err:    nil,
		},
		{
			data:   "1 cmd S 0 1 1 0 -1 4194560 30901 1011224 96 1826 185 2546 3273 2402 20 0 1 0 24 170409984 2900 18446744073709551615 1 1 0 0 0 0 671173123 4096 1260 0 0 0 17 7 0 0 12 0 0 0 0 0 0 0 0 0 0",
			fields: nil,
			err:    errors.New("task name is not parenthesized"),
		},
	}

	assert := assert.New(t)
	for _, tt := range tests {
		fields, err := parseTaskStat(tt.data)
		assert.Equal(fields, tt.fields)
		assert.Equal(err, tt.err)
	}
}
