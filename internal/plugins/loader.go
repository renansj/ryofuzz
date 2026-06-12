package plugins

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
	"github.com/renansj/ryofuzz/internal/vulns"
	"gopkg.in/yaml.v3"
)

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
		for _, p := range d.Patterns {
			if strings.Contains(strings.ToLower(respBody), strings.ToLower(p)) {
				matched = true
				break
			}
		}
	case "regex":
		for _, p := range d.Patterns {
			if re, err := regexp.Compile(p); err == nil && re.MatchString(respBody) {
				matched = true
				break
			}
		}
	case "status":
		matched = respStatus == d.StatusCode
	case "time":
		matched = respTime-baselineTime >= int64(d.TimeDelay)
	case "header":
		if vals, ok := respHeaders[strings.ToLower(d.HeaderName)]; ok {
			for _, v := range vals {
				if strings.Contains(v, d.HeaderVal) {
					matched = true
					break
				}
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

// LoadPlugins carrega todos os plugins dos diretórios especificados
func LoadPlugins(dirs []string) ([]vulns.VulnModule, error) {
	var modules []vulns.VulnModule
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
				continue
			}
			p, err := LoadPlugin(filepath.Join(dir, entry.Name()))
			if err != nil {
				return nil, fmt.Errorf("erro ao carregar plugin %s: %w", entry.Name(), err)
			}
			modules = append(modules, p.ToModule())
		}
	}
	return modules, nil
}

// LoadPlugin carrega um único plugin de um arquivo YAML
func LoadPlugin(path string) (*Plugin, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Plugin
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("YAML inválido em %s: %w", path, err)
	}
	if p.Name == "" || p.Module == "" {
		return nil, fmt.Errorf("plugin %s: 'name' e 'module' são obrigatórios", path)
	}
	return &p, nil
}

// ToModule converte um Plugin para VulnModule
func (p *Plugin) ToModule() vulns.VulnModule {
	return &PluginModule{plugin: p}
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
