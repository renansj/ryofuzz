package engine

import (
	"net/http"

	"github.com/renansj/ryofuzz/internal/httpx"
)

// NewAuthedClient builds an *http.Client that injects the given headers and
// cookies into every request. Headers are "Name: value" strings (same format
// as the engine Config). Pass an empty proxy to skip it.
//
// This now delegates to internal/httpx (review D1) so auth-bearing subsystems
// (workflow, authz, taint) inherit the same proxy/TLS/pooling/timeout policy as
// the main engine instead of a divergent hand-rolled client.
func NewAuthedClient(timeoutSec int, headers []string, cookies, proxy string, followRedir bool) *http.Client {
	return httpx.New(httpx.Options{
		TimeoutSec:      timeoutSec,
		Proxy:           proxy,
		Headers:         headers,
		Cookies:         cookies,
		FollowRedirects: followRedir,
		// Auth-bearing clients keep skip-verify for pentest targets; callers can
		// tighten this later once VerifyTLS is threaded through their configs.
		InsecureSkipVerify: true,
	})
}
