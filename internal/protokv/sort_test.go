package protokv

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyOrder(t *testing.T) {
	start := "\x00\xff\x01\xff"
	end := "\x00\xff\x01\xff\xff"

	a := "\x00\xff\x06\xff414b6ffc-c7d7-4f85-bfbe-3622069a2382"
	b := "\x00\xff\x06\xff0134230e-0400-41ac-b700-93026df87057"
	c := "\x00\xff\x01\xff\x01\xfeTYPE\xfe\x02\xfeVALUE:8\xff\x00\xff\x06\xffab9efb0a-1eaf-47c7-b268-2aa080d2b36c"
	d := "\x00\xff\x07\xff\x01\xfeTYPE\xfe\x02\xfeVALUE:8\xff\x00\xff\x06\xffab9efb0a-1eaf-47c7-b268-2aa080d2b36c"
	e := "\x00\xff\x06\xff"
	f := "\x00\xff\x06\xff\xff"

	require.True(t, a > start, "a=%x start=%x", a, start)
	require.False(t, a <= end, "a=%x end=%x", a, end)

	require.True(t, b > start, "b=%x start=%x", b, start)
	require.False(t, b <= end, "b=%x end=%x", b, end)

	require.True(t, c > start, "c=%x start=%x", c, start)
	require.True(t, c <= end, "c=%x end=%x", c, end)

	require.True(t, d > start, "d=%x start=%x", d, start)
	require.False(t, d <= end, "d=%x end=%x", d, end)

	require.True(t, e > start, "e=%x start=%x", e, start)
	require.False(t, e <= end, "e=%x end=%x", e, end)

	require.True(t, f > start, "f=%x start=%x", f, start)
	require.False(t, f <= end, "f=%x end=%x", f, end)

}
