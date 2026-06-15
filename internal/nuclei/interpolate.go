package nuclei

import (
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var interpRe = regexp.MustCompile(`\{\{(.*?)\}\}`)
var randstrRe = regexp.MustCompile(`^randstr(_\w+)?$`)

// builtinVars derives the {{BaseURL}}, {{Hostname}} etc. variables from a URL.
func builtinVars(baseURL string) map[string]interface{} {
	vars := map[string]interface{}{
		"BaseURL": strings.TrimRight(baseURL, "/"),
		"RootURL": baseURL,
	}
	u, err := url.Parse(baseURL)
	if err == nil {
		vars["Hostname"] = u.Host
		vars["Host"] = u.Hostname()
		vars["Scheme"] = u.Scheme
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		vars["Port"] = port
		vars["Path"] = u.Path
		vars["RootURL"] = u.Scheme + "://" + u.Host
		if idx := strings.LastIndex(u.Path, "/"); idx >= 0 {
			vars["File"] = u.Path[idx+1:]
		}
	}
	return vars
}

// preprocess evaluates one-time preprocessors like {{randstr}} consistently
// across the whole template (same randstr token resolves to the same value).
func preprocess(text string, cache map[string]string, rng *rand.Rand) string {
	return interpRe.ReplaceAllStringFunc(text, func(m string) string {
		inner := strings.TrimSpace(interpRe.FindStringSubmatch(m)[1])
		if randstrRe.MatchString(inner) {
			if v, ok := cache[inner]; ok {
				return v
			}
			v := randString(rng, 27)
			cache[inner] = v
			return v
		}
		return m // leave other expressions for the DSL interpolation pass
	})
}

func randString(rng *rand.Rand, n int) string {
	const cs = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[rng.Intn(len(cs))]
	}
	return string(b)
}

// interpolate evaluates {{ ... }} expressions in text using the env. Plain
// variable references resolve directly; anything else is evaluated as DSL.
func interpolate(text string, env map[string]interface{}) string {
	return interpRe.ReplaceAllStringFunc(text, func(m string) string {
		inner := strings.TrimSpace(interpRe.FindStringSubmatch(m)[1])
		if inner == "" {
			return m
		}
		// Direct variable reference (fast path)
		if v, ok := env[inner]; ok {
			return toString(v)
		}
		// Otherwise evaluate as a DSL expression
		if out, err := evalDSLString(inner, env); err == nil {
			return out
		}
		return m // leave unresolved (could be interactsh-url handled elsewhere)
	})
}

func toString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprintf("%v", v)
	}
}

// newRNG creates a per-template RNG seeded once.
func newRNG() *rand.Rand {
	return rand.New(rand.NewSource(time.Now().UnixNano()))
}
