package nuclei

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// respData holds everything matchers/extractors/DSL need about a response.
type respData struct {
	status     int
	headersRaw string            // "Key: Value\n..." form
	headerMap  map[string][]string
	body       string
	durationMs int64
	rawAll     string // status line + headers + body
}

// partText returns the response part for a matcher/extractor.
func (r *respData) partText(part string) string {
	switch strings.ToLower(part) {
	case "", "body":
		return r.body
	case "header":
		return r.headersRaw
	case "all", "response":
		return r.rawAll
	case "raw":
		return r.rawAll
	case "status":
		return fmt.Sprintf("%d", r.status)
	default:
		return r.body
	}
}

// dslEnv builds the variable environment for DSL evaluation from a response.
func (r *respData) dslEnv(extra map[string]interface{}) map[string]interface{} {
	env := map[string]interface{}{
		"status_code":    r.status,
		"content_length": len(r.body),
		"body":           r.body,
		"header":         r.headersRaw,
		"all_headers":    r.headersRaw,
		"duration":       float64(r.durationMs) / 1000.0,
		"response":       r.rawAll,
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

// evalMatcher evaluates a single matcher against the response. Returns matched
// and an error (error => could not fully evaluate, caller must NOT emit a match).
func evalMatcher(m Matcher, r *respData, env map[string]interface{}) (bool, string, error) {
	switch strings.ToLower(m.Type) {
	case "status":
		for _, code := range m.Status {
			if r.status == code {
				return true, fmt.Sprintf("status: %d", code), nil
			}
		}
		return false, "", nil

	case "size":
		bl := len(r.body)
		for _, sz := range m.Size {
			if bl == sz {
				return true, fmt.Sprintf("size: %d", sz), nil
			}
		}
		return false, "", nil

	case "word", "":
		target := r.partText(m.Part)
		if m.CaseInsensitive {
			target = strings.ToLower(target)
		}
		isAnd := strings.ToLower(m.Condition) == "and"
		matchedCount := 0
		var firstWord string
		for _, w := range m.Words {
			ww := w
			if m.CaseInsensitive {
				ww = strings.ToLower(ww)
			}
			if strings.Contains(target, ww) {
				matchedCount++
				if firstWord == "" {
					firstWord = w
				}
				if !isAnd && !m.MatchAll {
					return true, "word: " + w, nil
				}
			} else if isAnd {
				if m.MatchAll {
					continue
				}
				return false, "", nil
			}
		}
		if m.MatchAll {
			return matchedCount == len(m.Words), "all words matched", nil
		}
		if isAnd {
			return matchedCount == len(m.Words), "words matched (and)", nil
		}
		return matchedCount > 0, "word: " + firstWord, nil

	case "regex":
		target := r.partText(m.Part)
		isAnd := strings.ToLower(m.Condition) == "and"
		matchedCount := 0
		var first string
		for _, pat := range m.Regex {
			re, err := regexp.Compile(pat)
			if err != nil {
				return false, "", fmt.Errorf("bad regex %q: %w", pat, err)
			}
			if re.MatchString(target) {
				matchedCount++
				if first == "" {
					first = pat
				}
				if !isAnd && !m.MatchAll {
					return true, "regex: " + pat, nil
				}
			} else if isAnd && !m.MatchAll {
				return false, "", nil
			}
		}
		if m.MatchAll {
			return matchedCount == len(m.Regex), "all regex matched", nil
		}
		if isAnd {
			return matchedCount == len(m.Regex), "regex matched (and)", nil
		}
		return matchedCount > 0, "regex: " + first, nil

	case "binary":
		target := r.partText(m.Part)
		for _, b := range m.Binary {
			raw, err := hex.DecodeString(strings.TrimSpace(b))
			if err != nil {
				return false, "", fmt.Errorf("bad binary %q: %w", b, err)
			}
			if strings.Contains(target, string(raw)) {
				return true, "binary: " + b, nil
			}
		}
		return false, "", nil

	case "dsl":
		isAnd := strings.ToLower(m.Condition) == "and"
		matchedCount := 0
		for _, expr := range m.DSL {
			ok, err := evalDSL(expr, env)
			if err != nil {
				return false, "", fmt.Errorf("dsl eval %q: %w", expr, err)
			}
			if ok {
				matchedCount++
				if !isAnd {
					return true, "dsl: " + expr, nil
				}
			} else if isAnd {
				return false, "", nil
			}
		}
		if isAnd {
			return matchedCount == len(m.DSL), "dsl matched (and)", nil
		}
		return matchedCount > 0, "dsl matched", nil

	case "xpath":
		// XPath matcher: evaluate via the xpath helper (htmlquery). Treated as
		// "node exists" semantics.
		for _, xp := range m.XPath {
			ok, err := xpathExists(r.body, xp)
			if err != nil {
				return false, "", fmt.Errorf("xpath %q: %w", xp, err)
			}
			if ok {
				return true, "xpath: " + xp, nil
			}
		}
		return false, "", nil
	}

	return false, "", fmt.Errorf("unsupported matcher type %q", m.Type)
}

// evalMatchers evaluates all matchers with the matchers-condition. Returns
// matched, evidence, and error. On any evaluation error the whole template is
// treated as non-matching with an error (G9: never emit a half-evaluated match).
func evalMatchers(matchers []Matcher, condition string, r *respData, env map[string]interface{}) (bool, string, error) {
	if len(matchers) == 0 {
		return false, "", nil
	}
	isAnd := strings.ToLower(condition) == "and"
	allMatched := true
	anyMatched := false
	var evidence string

	for _, m := range matchers {
		if m.Internal {
			continue // internal matchers do not affect the final verdict
		}
		matched, ev, err := evalMatcher(m, r, env)
		if err != nil {
			return false, "", err
		}
		if m.Negative {
			matched = !matched
		}
		if matched {
			anyMatched = true
			if evidence == "" {
				evidence = ev
			}
		} else {
			allMatched = false
		}
	}

	if isAnd {
		return allMatched, evidence, nil
	}
	return anyMatched, evidence, nil
}
