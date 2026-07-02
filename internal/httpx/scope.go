package httpx

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Scope decides whether a request to a given URL is allowed to leave the tool.
// It enforces an allowlist of hosts/domains and always denies known-dangerous
// internal ranges (RFC1918, loopback, link-local, cloud metadata) unless the
// operator explicitly allowlists them. This keeps a crawler/redirect/OOB flow
// from wandering off-scope or into SSRF-by-accident (review F4).
type Scope struct {
	allow       []string // host suffixes; empty means "any host allowed"
	allowIntern bool     // permit RFC1918/loopback/metadata
}

// NewScope builds a scope from allow entries. An entry may be a host
// (api.example.com) or a domain suffix (example.com, matching subdomains).
// allowInternal permits private/loopback/metadata targets (e.g. for local labs).
func NewScope(allow []string, allowInternal bool) *Scope {
	cleaned := make([]string, 0, len(allow))
	for _, a := range allow {
		a = strings.TrimSpace(strings.ToLower(a))
		if a != "" {
			cleaned = append(cleaned, a)
		}
	}
	return &Scope{allow: cleaned, allowIntern: allowInternal}
}

// metadataHosts are cloud metadata endpoints that must never be hit unless
// explicitly allowed.
var metadataHosts = map[string]bool{
	"169.254.169.254":          true, // AWS/GCP/Azure IMDS
	"metadata.google.internal": true,
	"100.100.100.200":          true, // Alibaba
}

// Allowed reports whether the URL is in scope. It returns an error describing
// why when it is not, for logging.
func (s *Scope) Allowed(raw string) (bool, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return false, fmt.Errorf("unparseable URL %q", raw)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false, fmt.Errorf("URL %q has no host", raw)
	}

	if !s.allowIntern && isInternalHost(host) {
		return false, fmt.Errorf("host %q is internal/metadata and not allowlisted", host)
	}

	if len(s.allow) == 0 {
		return true, nil // no allowlist configured: any (non-internal) host is fine
	}
	for _, a := range s.allow {
		if host == a || strings.HasSuffix(host, "."+a) {
			return true, nil
		}
	}
	return false, fmt.Errorf("host %q is not in scope", host)
}

// isInternalHost reports whether a host is loopback, private, link-local or a
// known cloud metadata endpoint.
func isInternalHost(host string) bool {
	if metadataHosts[host] {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Not an IP literal; treat common local names as internal.
		return host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal")
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
