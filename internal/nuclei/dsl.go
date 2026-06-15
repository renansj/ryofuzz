package nuclei

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/expr-lang/expr"
)

// dslFunctions is the helper-function library exposed to DSL expressions and
// {{...}} interpolation. This is the minimum-viable subset for CVE templates
// from the projectdiscovery/dsl library.
func dslFunctions() map[string]interface{} {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const numeric = "0123456789"
	const alphanum = alpha + numeric

	randFrom := func(n int, charset string) string {
		if n <= 0 {
			n = 1
		}
		b := make([]byte, n)
		for i := range b {
			b[i] = charset[rng.Intn(len(charset))]
		}
		return string(b)
	}

	toStr := func(v interface{}) string { return fmt.Sprintf("%v", v) }

	return map[string]interface{}{
		"contains":      func(s, sub string) bool { return strings.Contains(s, sub) },
		"icontains":     func(s, sub string) bool { return strings.Contains(strings.ToLower(s), strings.ToLower(sub)) },
		"contains_all":  func(s string, subs ...string) bool { for _, x := range subs { if !strings.Contains(s, x) { return false } }; return true },
		"contains_any":  func(s string, subs ...string) bool { for _, x := range subs { if strings.Contains(s, x) { return true } }; return false },
		"startswith":    func(s, p string) bool { return strings.HasPrefix(s, p) },
		"endswith":      func(s, p string) bool { return strings.HasSuffix(s, p) },
		"len":           func(v interface{}) int { return len(toStr(v)) },
		"to_lower":      strings.ToLower,
		"to_upper":      strings.ToUpper,
		"trim":          func(s, cut string) string { return strings.Trim(s, cut) },
		"trim_space":    strings.TrimSpace,
		"trim_prefix":   func(s, p string) string { return strings.TrimPrefix(s, p) },
		"trim_suffix":   func(s, p string) string { return strings.TrimSuffix(s, p) },
		"replace":       func(s, old, new string) string { return strings.ReplaceAll(s, old, new) },
		"split":         func(s, sep string) []string { return strings.Split(s, sep) },
		"concat":        func(args ...interface{}) string { var b strings.Builder; for _, a := range args { b.WriteString(toStr(a)) }; return b.String() },
		"regex":         func(pattern, s string) bool { re, err := regexp.Compile(pattern); if err != nil { return false }; return re.MatchString(s) },
		"md5":           func(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) },
		"sha1":          func(s string) string { h := sha1.Sum([]byte(s)); return hex.EncodeToString(h[:]) },
		"sha256":        func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) },
		"hmac":          dslHMAC,
		"base64":        func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
		"base64_decode": func(s string) string { d, _ := base64.StdEncoding.DecodeString(s); return string(d) },
		"hex_encode":    func(s string) string { return hex.EncodeToString([]byte(s)) },
		"hex_decode":    func(s string) string { d, _ := hex.DecodeString(s); return string(d) },
		"url_encode":    func(s string) string { return url.QueryEscape(s) },
		"url_decode":    func(s string) string { d, _ := url.QueryUnescape(s); return d },
		"to_number":     func(s string) float64 { f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64); return f },
		"to_string":     toStr,
		"unix_time":     func() int64 { return time.Now().Unix() },
		"rand_base":     func(n int) string { return randFrom(n, alphanum) },
		"rand_char":     func() string { return randFrom(1, alphanum) },
		"rand_int":      func() int { return rng.Intn(2147483647) },
		"rand_text_alpha":   func(n int) string { return randFrom(n, alpha) },
		"rand_text_numeric": func(n int) string { return randFrom(n, numeric) },
		"rand_text_alphanumeric": func(n int) string { return randFrom(n, alphanum) },
		"compare_versions": dslCompareVersions,
		"status_code":      func(v interface{}) int { n, _ := strconv.Atoi(toStr(v)); return n },
		"repeat":           func(s string, n int) string { return strings.Repeat(s, n) },
		// case-variant aliases seen in templates
		"toupper":   strings.ToUpper,
		"tolower":   strings.ToLower,
		"tostring":  toStr,
		"to_title":  strings.Title,
		"mmh3":      dslMMH3,
	}
}

// dslMMH3 computes the MurmurHash3 (32-bit) of the input, as used by favicon
// hash templates (the value nuclei prints for favicons).
func dslMMH3(s string) int32 {
	data := []byte(s)
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	var h uint32
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[nblocks*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}

func dslHMAC(algo, data, key string) string {
	var h func() ([]byte)
	switch strings.ToLower(algo) {
	case "sha256":
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(data))
		return hex.EncodeToString(mac.Sum(nil))
	case "sha1":
		mac := hmac.New(sha1.New, []byte(key))
		mac.Write([]byte(data))
		return hex.EncodeToString(mac.Sum(nil))
	case "md5":
		mac := hmac.New(md5.New, []byte(key))
		mac.Write([]byte(data))
		return hex.EncodeToString(mac.Sum(nil))
	}
	_ = h
	return ""
}

// dslCompareVersions returns true if version constraints are satisfied.
// Simplified: supports a single current version vs constraints like ">= 1.2.3".
func dslCompareVersions(version string, constraints ...string) bool {
	cur := parseVer(version)
	for _, c := range constraints {
		c = strings.TrimSpace(c)
		var op, ver string
		for _, prefix := range []string{">=", "<=", "==", "!=", ">", "<"} {
			if strings.HasPrefix(c, prefix) {
				op = prefix
				ver = strings.TrimSpace(strings.TrimPrefix(c, prefix))
				break
			}
		}
		if op == "" {
			continue
		}
		cmp := cmpVer(cur, parseVer(ver))
		ok := false
		switch op {
		case ">=":
			ok = cmp >= 0
		case "<=":
			ok = cmp <= 0
		case ">":
			ok = cmp > 0
		case "<":
			ok = cmp < 0
		case "==":
			ok = cmp == 0
		case "!=":
			ok = cmp != 0
		}
		if !ok {
			return false
		}
	}
	return true
}

func parseVer(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		num := ""
		for _, c := range p {
			if c >= '0' && c <= '9' {
				num += string(c)
			} else {
				break
			}
		}
		n, _ := strconv.Atoi(num)
		out = append(out, n)
	}
	return out
}

func cmpVer(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var av, bv int
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

// knownDSLFuncs is the set of supported function names, for capability gating.
var knownDSLFuncs = func() map[string]bool {
	m := make(map[string]bool)
	for name := range dslFunctions() {
		m[name] = true
	}
	// operators/identifiers that are not functions but are valid in expressions
	return m
}()

var dslFuncCallRe = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)

var dslStringLitRe = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`)

// unknownDSLFunction returns the first function name used in expr that is not
// implemented, and ok=false. If all functions are known, returns ("", true).
// String literals are stripped first so that text like "alert(1)" inside a
// string argument is not mistaken for a function call.
func unknownDSLFunction(expr string) (string, bool) {
	stripped := dslStringLitRe.ReplaceAllString(expr, `""`)
	for _, m := range dslFuncCallRe.FindAllStringSubmatch(stripped, -1) {
		fn := m[1]
		// builtins from expr-lang we allow
		switch fn {
		case "all", "any", "none", "one", "filter", "map", "count", "int", "float", "string", "len":
			continue
		}
		if !knownDSLFuncs[fn] {
			return fn, false
		}
	}
	return "", true
}

// evalDSL evaluates a DSL boolean expression against the given variable env.
func evalDSL(expression string, env map[string]interface{}) (bool, error) {
	expression = sanitizeDSL(expression)
	full := buildFullEnv(env)
	program, err := expr.Compile(expression, expr.Env(full))
	if err != nil {
		return false, err
	}
	out, err := expr.Run(program, full)
	if err != nil {
		return false, err
	}
	if b, ok := out.(bool); ok {
		return b, nil
	}
	return false, nil
}

// evalDSLString evaluates a DSL expression and returns its string value (for
// interpolation and extractors).
func evalDSLString(expression string, env map[string]interface{}) (string, error) {
	expression = sanitizeDSL(expression)
	full := buildFullEnv(env)
	program, err := expr.Compile(expression, expr.Env(full))
	if err != nil {
		return "", err
	}
	out, err := expr.Run(program, full)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", out), nil
}

// conflictFuncs are nuclei DSL function names that collide with expr-lang
// operator keywords; calls to them are rewritten to a safe alias before compile.
var conflictFuncs = []string{"contains", "matches", "startsWith", "endsWith"}

var conflictRes = func() map[string]*regexp.Regexp {
	m := make(map[string]*regexp.Regexp)
	for _, f := range conflictFuncs {
		m[f] = regexp.MustCompile(`\b` + f + `\s*\(`)
	}
	return m
}()

// sanitizeDSL rewrites function calls whose names clash with expr operators
// (e.g. contains(a,b)) into a non-conflicting alias (ryo_contains(a,b)).
func sanitizeDSL(expression string) string {
	for _, f := range conflictFuncs {
		expression = conflictRes[f].ReplaceAllString(expression, "ryo_"+f+"(")
	}
	return expression
}

// buildFullEnv merges helper functions with the variable env. The SAME map must
// be used for both Compile and Run, otherwise function calls fail at runtime.
func buildFullEnv(env map[string]interface{}) map[string]interface{} {
	full := make(map[string]interface{}, len(env)+48)
	for k, v := range dslFunctions() {
		full[k] = v
	}
	// Aliases for operator-conflicting function names.
	fns := dslFunctions()
	full["ryo_contains"] = fns["contains"]
	full["ryo_matches"] = func(pattern, s string) bool {
		re, err := regexp.Compile(pattern)
		return err == nil && re.MatchString(s)
	}
	full["ryo_startsWith"] = func(s, p string) bool { return strings.HasPrefix(s, p) }
	full["ryo_endsWith"] = func(s, p string) bool { return strings.HasSuffix(s, p) }
	for k, v := range env {
		full[k] = v
	}
	return full
}
