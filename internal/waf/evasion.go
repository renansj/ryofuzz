package waf

import (
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"unicode"
)

// DetectWAF fingerprints known WAFs from response attributes.
func DetectWAF(respHeaders map[string][]string, respBody string, statusCode int) string {
	for k := range respHeaders {
		kl := strings.ToLower(k)
		if kl == "cf-ray" {
			return "cloudflare"
		}
		if strings.HasPrefix(kl, "x-amzn") {
			return "aws-waf"
		}
		if strings.Contains(kl, "akamai") {
			return "akamai"
		}
		if strings.Contains(kl, "x-sucuri") {
			return "sucuri"
		}
	}
	bodyLower := strings.ToLower(respBody)
	if strings.Contains(bodyLower, "mod_security") || strings.Contains(bodyLower, "modsecurity") {
		return "modsecurity"
	}
	if strings.Contains(bodyLower, "imperva") || strings.Contains(bodyLower, "incapsula") {
		return "imperva"
	}
	return ""
}

// EvasionChains returns encoding transformation functions for WAF bypass.
func EvasionChains() []func(string) string {
	return []func(string) string{
		doubleURLEncode,
		unicodeEscape,
		caseRandomize,
		inlineComments,
		htmlEntityEncode,
		mixedURLEncode,
	}
}

// ApplyEvasion applies the Nth evasion chain to a payload.
func ApplyEvasion(payload string, chainIndex int) string {
	chains := EvasionChains()
	if chainIndex < 0 || chainIndex >= len(chains) {
		return payload
	}
	return chains[chainIndex](payload)
}

// EvasionVariants returns all evasion variants of a blocked payload.
func EvasionVariants(payload string) []string {
	chains := EvasionChains()
	variants := make([]string, 0, len(chains))
	for _, fn := range chains {
		variants = append(variants, fn(payload))
	}
	return variants
}

// IsBlocked returns true if the status code indicates WAF blocking.
func IsBlocked(statusCode int) bool {
	return statusCode == 403 || statusCode == 406
}

func doubleURLEncode(s string) string {
	first := url.QueryEscape(s)
	return url.QueryEscape(first)
}

func unicodeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r > 127 || !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			b.WriteString(fmt.Sprintf("\\u%04x", r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func caseRandomize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) {
			if rand.Intn(2) == 0 {
				b.WriteRune(unicode.ToUpper(r))
			} else {
				b.WriteRune(unicode.ToLower(r))
			}
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func inlineComments(s string) string {
	keywords := []string{"SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE", "DROP",
		"select", "union", "from", "where", "and", "or", "insert", "update", "delete", "drop"}
	result := s
	for _, kw := range keywords {
		result = strings.ReplaceAll(result, kw, kw[:len(kw)/2]+"/**/"+kw[len(kw)/2:])
	}
	return result
}

func htmlEntityEncode(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '<' || r == '>' || r == '\'' || r == '"' || r == '&' || r == '/' {
			b.WriteString(fmt.Sprintf("&#x%x;", r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func mixedURLEncode(s string) string {
	var b strings.Builder
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			b.WriteString(fmt.Sprintf("%%%02X", r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
