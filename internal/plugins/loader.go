package plugins

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
	"github.com/renansj/ryofuzz/internal/vulns"
	"gopkg.in/yaml.v3"
)

// regexMatchTimeout bounds a single regex evaluation against a response body.
// Go's regexp is RE2 (linear time) so catastrophic backtracking is impossible,
// but a pathological pattern over a large body can still burn CPU; combined
// with the bounded body read (util.ReadBodyLimited) this caps the blast radius
// of a hostile plugin pattern or adversarial response (ReDoS defense, F2).
const regexMatchTimeout = 2 * time.Second

// validMethods is the closed set of detection methods a plugin may declare.
var validMethods = map[string]bool{
	"contains": true,
	"regex":    true,
	"status":   true,
	"time":     true,
	"header":   true,
}

// validSeverities is the closed set of severities a plugin may declare.
var validSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"info":     true,
}

type Plugin struct {
	Name        string          `yaml:"name"`
	Description string          `yaml:"description"`
	Author      string          `yaml:"author"`
	Severity    string          `yaml:"severity"`
	Module      string          `yaml:"module"`
	OWASP       string          `yaml:"owasp"`
	CWE         string          `yaml:"cwe"`
	Payloads    []PluginPayload `yaml:"payloads"`
	Detection   PluginDetection `yaml:"detection"`
}

type PluginPayload struct {
	Value    string `yaml:"value"`
	Variant  string `yaml:"variant"`
	Encoding string `yaml:"encoding"` // none, url, double-url, base64
}

type PluginDetection struct {
	Method     string   `yaml:"method"` // contains, regex, status, time, header
	Patterns   []string `yaml:"patterns"`
	StatusCode int      `yaml:"status_code"`
	TimeDelay  int      `yaml:"time_delay_ms"`
	HeaderName string   `yaml:"header_name"`
	HeaderVal  string   `yaml:"header_value"`
	Negate     bool     `yaml:"negate"` // true = finding se pattern NÃO match
}

// PluginModule implementa vulns.VulnModule para plugins YAML
type PluginModule struct {
	plugin *Plugin
	// regexes are pre-compiled once at load time (C2/F2) instead of on every
	// response. A plugin whose patterns fail to compile is rejected at load.
	regexes []*regexp.Regexp
}

func (m *PluginModule) Name() string        { return m.plugin.Module }
func (m *PluginModule) Description() string { return m.plugin.Description }

func (m *PluginModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	for _, point := range points {
		for _, pp := range m.plugin.Payloads {
			val := encodePayload(pp.Value, pp.Encoding)
			payloads = append(payloads, mutator.Payload{
				Value:   val,
				Point:   point,
				Module:  m.plugin.Module,
				Variant: pp.Variant,
			})
		}
	}
	return payloads
}

func (m *PluginModule) Detect(payload mutator.Payload, baselineBody string, baselineStatus int, baselineTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *vulns.Finding {

	d := m.plugin.Detection
	matched := false

	switch d.Method {
	case "contains":
		lowerBody := strings.ToLower(respBody)
		for _, p := range d.Patterns {
			if strings.Contains(lowerBody, strings.ToLower(p)) {
				matched = true
				break
			}
		}
	case "regex":
		for _, re := range m.regexes {
			if matchWithTimeout(re, respBody) {
				matched = true
				break
			}
		}
	case "status":
		matched = respStatus == d.StatusCode
	case "time":
		matched = respTime-baselineTime >= int64(d.TimeDelay)
	case "header":
		// Canonicalize the lookup the way net/http stores header keys so a
		// plugin's header_name matches regardless of casing (J2).
		canonical := http.CanonicalHeaderKey(d.HeaderName)
		for k, vals := range respHeaders {
			if http.CanonicalHeaderKey(k) != canonical {
				continue
			}
			for _, v := range vals {
				if strings.Contains(v, d.HeaderVal) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
	}

	if d.Negate {
		matched = !matched
	}

	if !matched {
		return nil
	}

	return &vulns.Finding{
		Module:      m.plugin.Module,
		Severity:    m.plugin.Severity,
		Confidence:  "medium",
		Title:       fmt.Sprintf("[Plugin] %s", m.plugin.Name),
		Description: m.plugin.Description,
		Payload:     payload.Value,
		Point:       payload.Point,
		Evidence:    fmt.Sprintf("Detection method: %s", d.Method),
		OWASP:       m.plugin.OWASP,
		CWE:         m.plugin.CWE,
	}
}

// matchWithTimeout runs re.MatchString under a wall-clock deadline so a single
// evaluation cannot hang a fuzzing goroutine indefinitely (F2). RE2 guarantees
// linear time, so this is a belt-and-suspenders cap for pathological inputs.
func matchWithTimeout(re *regexp.Regexp, body string) bool {
	done := make(chan bool, 1)
	go func() {
		defer func() {
			// A panic inside regexp is not expected, but never let it escape
			// this helper goroutine and crash the process.
			if r := recover(); r != nil {
				done <- false
			}
		}()
		done <- re.MatchString(body)
	}()
	select {
	case res := <-done:
		return res
	case <-time.After(regexMatchTimeout):
		return false
	}
}

// LoadPlugins loads every plugin from the given directories. A single broken
// plugin no longer aborts the whole load (J1): invalid plugins are logged to
// stderr and skipped, and the successfully loaded modules are returned together
// with an aggregated error describing what was skipped.
func LoadPlugins(dirs []string) ([]vulns.VulnModule, error) {
	var modules []vulns.VulnModule
	var loadErrs []error

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			loadErrs = append(loadErrs, fmt.Errorf("failed to read directory %s: %w", dir, err))
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			mod, err := LoadModule(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] skipping plugin %s: %v\n", entry.Name(), err)
				loadErrs = append(loadErrs, fmt.Errorf("%s: %w", entry.Name(), err))
				continue
			}
			modules = append(modules, mod)
		}
	}

	if len(loadErrs) > 0 {
		return modules, fmt.Errorf("%d plugin(s) skipped: %w", len(loadErrs), errors.Join(loadErrs...))
	}
	return modules, nil
}

// LoadPlugin loads and validates a single plugin from a YAML file.
func LoadPlugin(path string) (*Plugin, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Plugin
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("YAML inválido em %s: %w", path, err)
	}
	if err := validatePlugin(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadModule loads a plugin file and returns a ready-to-use VulnModule with its
// regexes already compiled. Compilation failures are surfaced as load errors so
// a bad pattern fails loudly at startup instead of silently never matching.
func LoadModule(path string) (vulns.VulnModule, error) {
	p, err := LoadPlugin(path)
	if err != nil {
		return nil, err
	}
	return p.ToModule()
}

// validatePlugin enforces the plugin schema (J2): required fields plus a closed
// set of detection methods and severities.
func validatePlugin(p *Plugin) error {
	if p.Name == "" || p.Module == "" {
		return errors.New("'name' e 'module' são obrigatórios")
	}
	if p.Detection.Method != "" && !validMethods[p.Detection.Method] {
		return fmt.Errorf("detection.method %q inválido (use: contains, regex, status, time, header)", p.Detection.Method)
	}
	if p.Severity != "" && !validSeverities[strings.ToLower(p.Severity)] {
		return fmt.Errorf("severity %q inválida (use: critical, high, medium, low, info)", p.Severity)
	}
	return nil
}

// ToModule converts a Plugin to a VulnModule, pre-compiling its regex patterns
// once (C2). Returns an error if any pattern is invalid.
func (p *Plugin) ToModule() (vulns.VulnModule, error) {
	m := &PluginModule{plugin: p}
	if p.Detection.Method == "regex" {
		for _, pat := range p.Detection.Patterns {
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("regex inválida %q: %w", pat, err)
			}
			m.regexes = append(m.regexes, re)
		}
	}
	return m, nil
}

func encodePayload(value, encoding string) string {
	switch encoding {
	case "url":
		return url.QueryEscape(value)
	case "double-url":
		return url.QueryEscape(url.QueryEscape(value))
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(value))
	default:
		return value
	}
}
