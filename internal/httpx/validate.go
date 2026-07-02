package httpx

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateTarget checks that a target URL is well-formed and usable before a
// scan starts, so a malformed URL fails loudly at config time instead of
// producing a broken request deep inside the fuzzing loop (review D3).
func ValidateTarget(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("target URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid target URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("target URL %q must use http or https (got %q)", raw, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("target URL %q has no host", raw)
	}
	return nil
}

// ValidateProxy checks that a proxy URL is parseable and uses a supported
// scheme. Empty is allowed (no proxy). Previously a malformed proxy was
// swallowed and traffic silently bypassed it (review D3).
func ValidateProxy(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid proxy URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return fmt.Errorf("proxy URL %q has unsupported scheme %q (use http, https or socks5)", raw, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("proxy URL %q has no host", raw)
	}
	return nil
}
