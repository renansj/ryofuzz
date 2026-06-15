package vulns

import (
	"net/url"
	"strings"
)

// indicatorConfirmed reports whether an indicator represents a genuine signal
// in the response rather than an echo of the payload. Returns true only if the
// indicator is present in respBody, absent from baseBody, and NOT merely a
// substring of the payload value that the application reflected back.
//
// This is the core false-positive guard: endpoints that echo input (error
// pages, JSON that includes the submitted value) would otherwise match any
// indicator string that happens to be part of the payload.
func indicatorConfirmed(respBody, baseBody, payloadValue, indicator string) bool {
	rb := strings.ToLower(respBody)
	bb := strings.ToLower(baseBody)
	ind := strings.ToLower(indicator)
	pv := strings.ToLower(payloadValue)

	if !strings.Contains(rb, ind) {
		return false
	}
	if strings.Contains(bb, ind) {
		return false // already present in baseline
	}
	if pv != "" && strings.Contains(pv, ind) {
		return false // indicator is just the echoed payload, not genuine output
	}
	return true
}

// hostInLocationEquals parses Location headers and reports whether any redirect
// target's HOST exactly equals wantHost. Substring matching ("evil.com" in
// "evil.com.target.com") is a classic open-redirect false positive; host
// equality avoids it.
func hostInLocationEquals(respHeaders map[string][]string, wantHost string) (string, bool) {
	for key, vals := range respHeaders {
		if !strings.EqualFold(key, "Location") {
			continue
		}
		for _, loc := range vals {
			u, err := url.Parse(strings.TrimSpace(loc))
			if err != nil {
				continue
			}
			h := u.Hostname()
			if strings.EqualFold(h, wantHost) {
				return loc, true
			}
		}
	}
	return "", false
}

// headerKeyPresent reports whether a header key actually exists in the parsed
// response headers (used by CRLF injection to confirm a header was injected as
// a real header, not just reflected as body text).
func headerKeyPresent(respHeaders map[string][]string, key string) bool {
	for k := range respHeaders {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}
