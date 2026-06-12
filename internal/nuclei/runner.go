package nuclei

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Template represents a nuclei template (subset of fields we support)
type Template struct {
	ID       string   `yaml:"id"`
	Info     Info     `yaml:"info"`
	Requests []Request `yaml:"http"`
}

type Info struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Tags        string   `yaml:"tags"`
	Reference   []string `yaml:"reference"`
}

type Request struct {
	Method          string            `yaml:"method"`
	Path            []string          `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	Matchers        []Matcher         `yaml:"matchers"`
	MatchersCondition string          `yaml:"matchers-condition"`
	Redirects       bool              `yaml:"redirects"`
	MaxRedirects    int               `yaml:"max-redirects"`
}

type Matcher struct {
	Type      string   `yaml:"type"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Status    []int    `yaml:"status"`
	Part      string   `yaml:"part"`
	Condition string   `yaml:"condition"`
	Negative  bool     `yaml:"negative"`
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
	if t.ID == "" || len(t.Requests) == 0 {
		return nil, fmt.Errorf("invalid template: missing id or requests")
	}
	return &t, nil
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
		if len(tagFilter) > 0 && !matchesAnyTag(t.Info.Tags, tagFilter) {
			return nil
		}
		templates = append(templates, t)
		return nil
	})
	return templates, err
}

// Execute runs a template against a target URL
func Execute(t *Template, baseURL string, timeout int, proxy string) *Result {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, reqDef := range t.Requests {
		for _, path := range reqDef.Path {
			url := buildURL(baseURL, path)
			method := strings.ToUpper(reqDef.Method)
			if method == "" {
				method = "GET"
			}

			var bodyReader io.Reader
			if reqDef.Body != "" {
				bodyReader = strings.NewReader(reqDef.Body)
			}

			req, err := http.NewRequest(method, url, bodyReader)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "ryofuzz/0.3 (nuclei-compat)")
			for k, v := range reqDef.Headers {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			matched, evidence := checkMatchers(reqDef.Matchers, reqDef.MatchersCondition, resp, string(body))
			if matched {
				return &Result{
					TemplateID: t.ID,
					Name:       t.Info.Name,
					Severity:   t.Info.Severity,
					Matched:    true,
					URL:        url,
					MatchedAt:  evidence,
				}
			}
		}
	}
	return &Result{TemplateID: t.ID, Matched: false}
}

func checkMatchers(matchers []Matcher, condition string, resp *http.Response, body string) (bool, string) {
	if len(matchers) == 0 {
		return false, ""
	}

	isAnd := strings.ToLower(condition) == "and"
	anyMatched := false
	allMatched := true
	var evidence string

	for _, m := range matchers {
		matched, ev := checkMatcher(m, resp, body)
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
		return allMatched, evidence
	}
	return anyMatched, evidence
}

func checkMatcher(m Matcher, resp *http.Response, body string) (bool, string) {
	target := body
	switch strings.ToLower(m.Part) {
	case "header":
		var hdr strings.Builder
		for k, vals := range resp.Header {
			for _, v := range vals {
				hdr.WriteString(k + ": " + v + "\n")
			}
		}
		target = hdr.String()
	case "status":
		// handled below
	}

	switch strings.ToLower(m.Type) {
	case "word":
		isAnd := strings.ToLower(m.Condition) == "and"
		allFound := true
		for _, word := range m.Words {
			if strings.Contains(target, word) {
				if !isAnd {
					return true, "word: " + word
				}
			} else {
				allFound = false
			}
		}
		return allFound && isAnd, "words matched"

	case "regex":
		for _, pattern := range m.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			if re.MatchString(target) {
				return true, "regex: " + pattern
			}
		}

	case "status":
		for _, code := range m.Status {
			if resp.StatusCode == code {
				return true, fmt.Sprintf("status: %d", code)
			}
		}
	}

	return false, ""
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
