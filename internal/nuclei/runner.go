package nuclei

import (
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Template represents a nuclei template. Fields are a superset of the schema;
// unsupported protocol blocks are parsed so we can gate on them (G9).
type Template struct {
	ID            string      `yaml:"id"`
	Info          Info        `yaml:"info"`
	Requests      []Request   `yaml:"http"`      // primary key
	RequestsLegacy []Request  `yaml:"requests"`  // legacy alias of http
	Variables     yaml.Node   `yaml:"variables"` // ordered, DSL-evaluable
	DNS           []yaml.Node `yaml:"dns"`
	TCP           []yaml.Node `yaml:"tcp"`
	SSL           []yaml.Node `yaml:"ssl"`
	File          []yaml.Node `yaml:"file"`
	Headless      []yaml.Node `yaml:"headless"`
	Code          []yaml.Node `yaml:"code"`
	JavaScript    []yaml.Node `yaml:"javascript"`
	Flow          string      `yaml:"flow"`
	SelfContained bool        `yaml:"self-contained"`
}

// AllRequests returns the http requests, honoring both `http:` and `requests:`.
func (t *Template) AllRequests() []Request {
	if len(t.Requests) > 0 {
		return t.Requests
	}
	return t.RequestsLegacy
}

type Info struct {
	Name           string            `yaml:"name"`
	Author         string            `yaml:"author"`
	Severity       string            `yaml:"severity"`
	Description    string            `yaml:"description"`
	Tags           StringOrSlice     `yaml:"tags"`
	Reference      StringOrSlice     `yaml:"reference"`
	Classification Classification    `yaml:"classification"`
	Metadata       map[string]any    `yaml:"metadata"`
}

// Classification carries CVE/CWE/CVSS metadata.
type Classification struct {
	CVEID       StringOrSlice `yaml:"cve-id"`
	CWEID       StringOrSlice `yaml:"cwe-id"`
	CVSSMetrics string        `yaml:"cvss-metrics"`
	CVSSScore   float64       `yaml:"cvss-score"`
}

// StringOrSlice accepts a YAML field that may be a string or a list of strings.
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var str string
		if err := value.Decode(&str); err != nil {
			return err
		}
		// tags/reference may be comma-separated in scalar form
		parts := strings.Split(str, ",")
		var out []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		*s = out
	case yaml.SequenceNode:
		var arr []string
		if err := value.Decode(&arr); err != nil {
			return err
		}
		*s = arr
	}
	return nil
}

// String returns the values joined by comma (for legacy comparisons).
func (s StringOrSlice) String() string { return strings.Join(s, ",") }

type Request struct {
	Method            string                 `yaml:"method"`
	Path              []string               `yaml:"path"`
	Raw               []string               `yaml:"raw"`
	Headers           map[string]string      `yaml:"headers"`
	Body              string                 `yaml:"body"`
	Attack            string                 `yaml:"attack"`
	Payloads          map[string]interface{} `yaml:"payloads"`
	Matchers          []Matcher              `yaml:"matchers"`
	MatchersCondition string                 `yaml:"matchers-condition"`
	Extractors        []Extractor            `yaml:"extractors"`
	ReqCondition      bool                   `yaml:"req-condition"`
	StopAtFirstMatch  bool                   `yaml:"stop-at-first-match"`
	Redirects         bool                   `yaml:"redirects"`
	HostRedirects     bool                   `yaml:"host-redirects"`
	MaxRedirects      int                    `yaml:"max-redirects"`
	CookieReuse       bool                   `yaml:"cookie-reuse"`
	Unsafe            bool                   `yaml:"unsafe"`
	Pipeline          bool                   `yaml:"pipeline"`
	IterateAll        bool                   `yaml:"iterate-all"`
	SkipVarCheck      bool                   `yaml:"skip-variables-check"`
}

type Matcher struct {
	Type            string   `yaml:"type"`
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	Status          []int    `yaml:"status"`
	Size            []int    `yaml:"size"`
	Binary          []string `yaml:"binary"`
	DSL             []string `yaml:"dsl"`
	XPath           []string `yaml:"xpath"`
	Part            string   `yaml:"part"`
	Condition       string   `yaml:"condition"`
	Negative        bool     `yaml:"negative"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
	MatchAll        bool     `yaml:"match-all"`
	Internal        bool     `yaml:"internal"`
	Encoding        string   `yaml:"encoding"`
	Group           int      `yaml:"group"`
}

type Extractor struct {
	Type     string   `yaml:"type"`
	Name     string   `yaml:"name"`
	Regex    []string `yaml:"regex"`
	Group    int      `yaml:"group"`
	KVal     []string `yaml:"kval"`
	JSON     []string `yaml:"json"`
	XPath    []string `yaml:"xpath"`
	DSL      []string `yaml:"dsl"`
	Part     string   `yaml:"part"`
	Internal bool     `yaml:"internal"`
}

// Result of a template execution
type Result struct {
	TemplateID string
	Name       string
	Severity   string
	Matched    bool
	URL        string
	MatchedAt  string
	Evidence   string
	// Classification metadata (Phase 1 / G7)
	CVEID    string
	CWEID    string
	CVSS     float64
	Tags     []string
	// Capability gating (G9)
	Skipped       bool
	SkipReason    string
	ExtractedVars map[string]string
}

// LoadTemplate parses a single nuclei template file
func LoadTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	if t.ID == "" {
		return nil, fmt.Errorf("invalid template: missing id")
	}
	// Accept templates that have http requests OR another protocol block (the
	// latter are gated/skipped loudly at execution time per G9).
	if len(t.AllRequests()) == 0 && !t.hasOtherProtocol() {
		return nil, fmt.Errorf("invalid template: no supported request block")
	}
	return &t, nil
}

// hasOtherProtocol reports whether the template defines a non-http protocol.
func (t *Template) hasOtherProtocol() bool {
	return len(t.DNS) > 0 || len(t.TCP) > 0 || len(t.SSL) > 0 || len(t.File) > 0 ||
		len(t.Headless) > 0 || len(t.Code) > 0 || len(t.JavaScript) > 0 || t.Flow != ""
}

// LoadTemplates loads all templates from a directory (recursive)
func LoadTemplates(dir string, tags string, severity string) ([]*Template, error) {
	var templates []*Template
	tagFilter := parseCSV(tags)
	sevFilter := parseCSV(severity)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		t, err := LoadTemplate(path)
		if err != nil {
			return nil
		}
		if len(sevFilter) > 0 && !matchesFilter(t.Info.Severity, sevFilter) {
			return nil
		}
		if len(tagFilter) > 0 && !matchesAnyTag(t.Info.Tags.String(), tagFilter) {
			return nil
		}
		templates = append(templates, t)
		return nil
	})
	return templates, err
}

// Execute runs a template against a target URL. Backward compatible signature.
func Execute(t *Template, baseURL string, timeout int, proxy string) *Result {
	// Classification metadata for the result (G7)
	classify := func(res *Result) *Result {
		res.TemplateID = t.ID
		res.Name = t.Info.Name
		res.Severity = t.Info.Severity
		res.Tags = t.Info.Tags
		if len(t.Info.Classification.CVEID) > 0 {
			res.CVEID = t.Info.Classification.CVEID[0]
		}
		if len(t.Info.Classification.CWEID) > 0 {
			res.CWEID = t.Info.Classification.CWEID[0]
		}
		res.CVSS = t.Info.Classification.CVSSScore
		return res
	}

	// G9: capability gating. Never half-evaluate.
	if reason, ok := t.CheckCapability(); !ok {
		return classify(&Result{Skipped: true, SkipReason: reason})
	}
	// interactsh required but no provider: skip loudly.
	if t.templateUsesInteractsh() && oobProvider == nil {
		return classify(&Result{Skipped: true, SkipReason: "template uses interactsh but no OOB provider configured"})
	}

	client := newHTTPClient(timeout, proxy, false)

	// Build base interpolation env: built-in vars + template variables block +
	// preprocessors (randstr) computed once for the whole template.
	rng := newRNG()
	preCache := map[string]string{}
	env := builtinVars(baseURL)
	applyTemplateVariables(t, env, rng, preCache)

	// interactsh URL minting
	var interactshID string
	if t.templateUsesInteractsh() && oobProvider != nil {
		id, full := oobProvider.NewURL()
		interactshID = id
		env["interactsh-url"] = full
	}

	// Extracted dynamic variables flow across requests.
	dynamicVars := map[string]string{}
	// Store response data per request index for req-condition references.
	var responses []*respData

	for _, reqDef := range t.AllRequests() {
		ps := normalizePayloads(normalizePayloadsRaw(reqDef.Payloads))
		perms := permutations(reqDef.Attack, ps)

		for _, perm := range perms {
			// Per-permutation env: base + dynamic vars + payload placeholders
			penv := cloneEnv(env)
			for k, v := range dynamicVars {
				penv[k] = v
			}
			for k, v := range perm {
				penv[k] = v
			}

			reqs := buildRequests(reqDef, baseURL, penv, rng, preCache)
			for _, hr := range reqs {
				rd := doRequest(client, hr, reqDef)
				if rd == nil {
					continue
				}
				responses = append(responses, rd)

				// Run extractors -> dynamic vars for subsequent requests
				ev := rd.dslEnv(penv)
				addInteractshVars(ev, interactshID)
				ext := runExtractors(reqDef.Extractors, rd, ev)
				for k, v := range ext {
					dynamicVars[k] = v
					penv[k] = v
				}

				// Evaluate matchers. On eval error, skip loudly (G9).
				matched, evidence, err := evalMatchers(reqDef.Matchers, reqDef.MatchersCondition, rd, ev)
				if err != nil {
					return classify(&Result{Skipped: true, SkipReason: "matcher evaluation error: " + err.Error()})
				}
				if matched {
					return classify(&Result{
						Matched:       true,
						URL:           hr.url,
						MatchedAt:     evidence,
						Evidence:      evidence,
						ExtractedVars: dynamicVars,
					})
				}
			}
		}
	}

	// interactsh post-check: a template may match purely on a callback.
	if interactshID != "" && oobProvider != nil {
		if proto, _, got := oobProvider.Poll(interactshID); got {
			// Only assert if a matcher referenced interactsh; otherwise informational.
			if templateMatchesInteractsh(t, proto) {
				return classify(&Result{Matched: true, URL: baseURL, MatchedAt: "interactsh callback: " + proto, Evidence: "OOB interactsh " + proto})
			}
		}
	}

	return classify(&Result{Matched: false})
}

// normalizePayloadsRaw is a small adapter (payloads may be nil).
func normalizePayloadsRaw(raw map[string]interface{}) map[string]interface{} {
	if raw == nil {
		return map[string]interface{}{}
	}
	return raw
}

func cloneEnv(env map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(env)+8)
	for k, v := range env {
		out[k] = v
	}
	return out
}

func addInteractshVars(env map[string]interface{}, id string) {
	if id == "" || oobProvider == nil {
		return
	}
	proto, request, got := oobProvider.Poll(id)
	if got {
		env["interactsh_protocol"] = proto
		env["interactsh_request"] = request
	} else {
		env["interactsh_protocol"] = ""
		env["interactsh_request"] = ""
	}
}

// templateMatchesInteractsh reports whether any matcher expects the given proto.
func templateMatchesInteractsh(t *Template, proto string) bool {
	for _, r := range t.AllRequests() {
		for _, m := range r.Matchers {
			if m.Part == "interactsh_protocol" {
				for _, w := range m.Words {
					if w == proto {
						return true
					}
				}
			}
			for _, d := range m.DSL {
				if indexOfStr(d, "interactsh_protocol") >= 0 {
					return true
				}
			}
		}
	}
	return false
}

// applyTemplateVariables evaluates the template-level variables block in order.
func applyTemplateVariables(t *Template, env map[string]interface{}, rng *rand.Rand, preCache map[string]string) {
	if t.Variables.Kind == 0 {
		return
	}
	var raw map[string]string
	if err := t.Variables.Decode(&raw); err != nil {
		return
	}
	for k, v := range raw {
		v = preprocess(v, preCache, rng)
		v = interpolate(v, env)
		env[k] = v
	}
}

// checkMatchers is kept for backward compatibility (legacy callers/tests).
func checkMatchers(matchers []Matcher, condition string, resp *http.Response, body string) (bool, string) {
	rd := responseToData(resp, body, 0)
	matched, ev, err := evalMatchers(matchers, condition, rd, rd.dslEnv(nil))
	if err != nil {
		return false, ""
	}
	return matched, ev
}

func buildURL(base, path string) string {
	path = strings.ReplaceAll(path, "{{BaseURL}}", base)
	path = strings.ReplaceAll(path, "{{RootURL}}", base)
	if strings.HasPrefix(path, "http") {
		return path
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func matchesFilter(value string, filters []string) bool {
	lower := strings.ToLower(value)
	for _, f := range filters {
		if lower == f {
			return true
		}
	}
	return false
}

func matchesAnyTag(tags string, filters []string) bool {
	lower := strings.ToLower(tags)
	for _, f := range filters {
		if strings.Contains(lower, f) {
			return true
		}
	}
	return false
}
