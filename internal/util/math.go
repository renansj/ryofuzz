// Package util holds small, dependency-free helpers shared across ryofuzz.
package util

// Signed is any signed integer type.
type Signed interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

// Abs returns the absolute value of x. Unlike math.Abs (float64 only), this
// works for signed integers used throughout the detection modules.
func Abs[T Signed](x T) T {
	if x < 0 {
		return -x
	}
	return x
}
