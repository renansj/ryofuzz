package engine

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// authTransport injects fixed headers (auth/session/cookies) into every request.
// This lets subsystems that only receive an *http.Client (workflow, authz, taint)
// inherit the global --auth and --cookie settings without signature changes.
type authTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range t.headers {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
	return t.base.RoundTrip(req)
}

// NewAuthedClient builds an *http.Client that injects the given headers and
// cookies into every request. Headers are "Name: value" strings (same format
// as the engine Config). Pass an empty proxy to skip it.
func NewAuthedClient(timeoutSec int, headers []string, cookies, proxy string, followRedir bool) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 100,
	}
	if proxy != "" {
		if pu, err := url.Parse(proxy); err == nil {
			transport.Proxy = http.ProxyURL(pu)
		}
	}

	hdrMap := make(map[string]string)
	for _, h := range headers {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			hdrMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	if cookies != "" {
		hdrMap["Cookie"] = cookies
	}

	client := &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: &authTransport{base: transport, headers: hdrMap},
	}
	if !followRedir {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}
