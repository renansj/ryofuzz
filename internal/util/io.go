package util

import "io"

// DefaultMaxBodyBytes bounds how much of an HTTP response body ryofuzz reads
// into memory per request. Without this, a hostile or misconfigured endpoint
// returning a huge (or infinite) body can exhaust memory, and under high
// concurrency that means OOM. 10 MiB is generous for detection purposes.
const DefaultMaxBodyBytes int64 = 10 << 20 // 10 MiB

// ReadBodyLimited reads up to maxBytes from r using io.LimitReader. If maxBytes
// is <= 0, DefaultMaxBodyBytes is applied. It returns whatever was read even
// when an error occurs, mirroring io.ReadAll semantics for partial reads.
//
// Detection modules only need substring/regex matches over the response, so a
// bounded read is sufficient; the tail of an oversized body is discarded.
func ReadBodyLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBodyBytes
	}
	return io.ReadAll(io.LimitReader(r, maxBytes))
}
