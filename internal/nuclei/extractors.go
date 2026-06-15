package nuclei

import (
	"regexp"
	"strings"

	"github.com/tidwall/gjson"
)

// runExtractors evaluates all extractors against a response and returns the
// extracted variables. Named extractors become {{name}}; internal extractors
// flow into subsequent requests but are not reported as output.
func runExtractors(extractors []Extractor, r *respData, env map[string]interface{}) map[string]string {
	out := make(map[string]string)
	for i, e := range extractors {
		vals := extractOne(e, r, env)
		if len(vals) == 0 {
			continue
		}
		name := e.Name
		if name == "" {
			name = "extracted_" + itoaSmall(i+1)
		}
		// First value becomes the named variable; all values joined too.
		out[name] = vals[0]
	}
	return out
}

func extractOne(e Extractor, r *respData, env map[string]interface{}) []string {
	target := r.partText(e.Part)
	switch strings.ToLower(e.Type) {
	case "regex", "":
		var out []string
		for _, pat := range e.Regex {
			re, err := regexp.Compile(pat)
			if err != nil {
				continue
			}
			matches := re.FindAllStringSubmatch(target, -1)
			for _, m := range matches {
				if e.Group > 0 && e.Group < len(m) {
					out = append(out, m[e.Group])
				} else if len(m) > 0 {
					out = append(out, m[0])
				}
			}
		}
		return out

	case "kval":
		// key-value extraction from headers (kval uses underscores for dashes)
		var out []string
		for _, key := range e.KVal {
			norm := strings.ReplaceAll(strings.ToLower(key), "_", "-")
			for hk, hvs := range r.headerMap {
				if strings.ToLower(hk) == norm {
					out = append(out, hvs...)
				}
			}
		}
		return out

	case "json":
		var out []string
		for _, path := range e.JSON {
			// nuclei/jq paths often start with "."; gjson uses bare paths.
			gpath := strings.TrimPrefix(path, ".")
			res := gjson.Get(r.body, gpath)
			if res.Exists() {
				if res.IsArray() {
					res.ForEach(func(_, v gjson.Result) bool {
						out = append(out, v.String())
						return true
					})
				} else {
					out = append(out, res.String())
				}
			}
		}
		return out

	case "xpath":
		var out []string
		for _, xp := range e.XPath {
			vals, err := xpathExtract(r.body, xp)
			if err == nil {
				out = append(out, vals...)
			}
		}
		return out

	case "dsl":
		var out []string
		for _, expr := range e.DSL {
			if v, err := evalDSLString(expr, env); err == nil && v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	return nil
}

func itoaSmall(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}
