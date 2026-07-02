// Package httpx centralizes creation of *http.Client for every ryofuzz
// subsystem. Before this package, 15 call sites built clients with divergent
// timeouts, some without a Transport (silently ignoring --proxy and TLS
// settings). A single factory (review D1/D2) guarantees that proxy routing,
// TLS verification (F3), connection pooling and granular timeouts behave
// identically everywhere.
package httpx

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Options configures a client built by New. The zero value is usable and
// yields sane defaults via normalize().
type Options struct {
	// TimeoutSec is the overall per-request timeout (http.Client.Timeout).
	TimeoutSec int
	// Proxy is an optional proxy URL (e.g. http://127.0.0.1:8080). Empty skips.
	Proxy string
	// InsecureSkipVerify disables TLS certificate verification. For pentesting
	// this defaults to true, but it is now explicit and configurable (F3) so a
	// user can turn verification on with --verify-tls.
	InsecureSkipVerify bool
	// FollowRedirects controls whether redirects are followed. When false the
	// client returns the first response (http.ErrUseLastResponse).
	FollowRedirects bool
	// MaxConnsPerHost bounds simultaneous connections to a single host. 0 lets
	// the default (derived from concurrency by the caller) apply.
	MaxConnsPerHost int
	// Headers are "Name: value" strings injected into every request when set.
	Headers []string
	// Cookies is a raw Cookie header value injected into every request.
	Cookies string
}

// Default timeouts for the granular transport phases (D2). Without these, a
// slow or malicious target holds connections open until the global timeout and
// exhausts the pool under concurrency.
const (
	defaultDialTimeout           = 10 * time.Second
	defaultTLSHandshakeTimeout   = 10 * time.Second
	defaultResponseHeaderTimeout = 15 * time.Second
	defaultExpectContinueTimeout = 1 * time.Second
	defaultIdleConnTimeout       = 90 * time.Second
	defaultKeepAlive             = 30 * time.Second
	defaultMaxIdleConns          = 100
	defaultMaxIdleConnsPerHost   = 100
)

func (o Options) normalize() Options {
	if o.TimeoutSec <= 0 {
		o.TimeoutSec = 15
	}
	return o
}

// NewTransport builds a fully-configured *http.Transport with granular
// timeouts, connection pooling and proxy/TLS wiring (D2).
func NewTransport(o Options) *http.Transport {
	o = o.normalize()
	tr := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   defaultDialTimeout,
			KeepAlive: defaultKeepAlive,
		}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: o.InsecureSkipVerify},
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: defaultResponseHeaderTimeout,
		ExpectContinueTimeout: defaultExpectContinueTimeout,
		IdleConnTimeout:       defaultIdleConnTimeout,
		MaxIdleConns:          defaultMaxIdleConns,
		MaxIdleConnsPerHost:   defaultMaxIdleConnsPerHost,
		MaxConnsPerHost:       o.MaxConnsPerHost,
		ForceAttemptHTTP2:     true,
	}
	if o.Proxy != "" {
		if pu, err := url.Parse(o.Proxy); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return tr
}

// headerTransport injects fixed headers/cookies into every outgoing request,
// letting subsystems that only hold an *http.Client inherit global auth.
type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range t.headers {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
	return t.base.RoundTrip(req)
}

// New builds an *http.Client from Options: single source of truth for proxy,
// TLS, pooling and timeouts across every subsystem (D1).
func New(o Options) *http.Client {
	o = o.normalize()
	var rt http.RoundTripper = NewTransport(o)

	hdrMap := make(map[string]string)
	for _, h := range o.Headers {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			hdrMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	if o.Cookies != "" {
		hdrMap["Cookie"] = o.Cookies
	}
	if len(hdrMap) > 0 {
		rt = &headerTransport{base: rt, headers: hdrMap}
	}

	client := &http.Client{
		Transport: rt,
		Timeout:   time.Duration(o.TimeoutSec) * time.Second,
	}
	if !o.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}
