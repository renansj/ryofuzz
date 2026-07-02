package workflow

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"strings"

	"github.com/renansj/ryofuzz/internal/httpx"
	"github.com/renansj/ryofuzz/internal/util"
	"gopkg.in/yaml.v3"
)

type Workflow struct {
	Name  string `yaml:"name"`
	Steps []Step `yaml:"steps"`
}

type Step struct {
	Name        string            `yaml:"name"`
	Request     StepRequest       `yaml:"request"`
	Fuzz        []string          `yaml:"fuzz"`
	AssertLogic []string          `yaml:"assert_logic"`
	Extract     map[string]string `yaml:"extract"`
}

type StepRequest struct {
	Method  string            `yaml:"method"`
	URL     string            `yaml:"url"`
	Body    string            `yaml:"body"`
	Headers map[string]string `yaml:"headers"`
}

type WorkflowFinding struct {
	Step     string
	Strategy string
	Type     string
	Evidence string
	Severity string
}

func LoadWorkflow(path string) (*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wf Workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, err
	}
	return &wf, nil
}

func Run(wf *Workflow, client *http.Client) []WorkflowFinding {
	var findings []WorkflowFinding
	vars := make(map[string]string)

	// Ensure client has a cookie jar for state
	if client.Jar == nil {
		client.Jar, _ = cookiejar.New(nil)
	}

	// Normal execution to build state
	for i, step := range wf.Steps {
		resp, body := execStep(client, step, vars)
		if resp == nil {
			continue
		}
		// Extract variables
		for varName, expr := range step.Extract {
			vars[varName] = extract(body, expr)
		}
		// Check assertions
		for _, a := range step.AssertLogic {
			if !checkAssertion(a, resp.StatusCode, body) {
				findings = append(findings, WorkflowFinding{
					Step:     step.Name,
					Strategy: "normal",
					Type:     "assertion_failed",
					Evidence: fmt.Sprintf("assertion %q failed on normal flow", a),
					Severity: "medium",
				})
			}
		}
		// Run fuzz strategies
		for _, strat := range step.Fuzz {
			sf := runStrategy(strat, client, wf, i, vars)
			findings = append(findings, sf...)
		}
	}
	return findings
}

func execStep(client *http.Client, step Step, vars map[string]string) (*http.Response, string) {
	url := substituteVars(step.Request.URL, vars)
	bodyStr := substituteVars(step.Request.Body, vars)

	var bodyReader io.Reader
	if bodyStr != "" {
		bodyReader = strings.NewReader(bodyStr)
	}
	req, err := http.NewRequest(step.Request.Method, url, bodyReader)
	if err != nil {
		return nil, ""
	}
	for k, v := range step.Request.Headers {
		req.Header.Set(k, substituteVars(v, vars))
	}
	if bodyStr != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()
	b, _ := util.ReadBodyLimited(resp.Body, 0)
	return resp, string(b)
}

func runStrategy(strat string, client *http.Client, wf *Workflow, stepIdx int, vars map[string]string) []WorkflowFinding {
	var findings []WorkflowFinding
	step := wf.Steps[stepIdx]

	switch strat {
	case "replay_n_times":
		successCount := 0
		for i := 0; i < 5; i++ {
			resp, _ := execStep(client, step, vars)
			if resp != nil && resp.StatusCode < 400 {
				successCount++
			}
		}
		if successCount > 1 {
			findings = append(findings, WorkflowFinding{
				Step:     step.Name,
				Strategy: "replay_n_times",
				Type:     "double-spend",
				Evidence: fmt.Sprintf("%d/5 replays succeeded (expected 1)", successCount),
				Severity: "high",
			})
		}

	case "negative_qty":
		origBody := step.Request.Body
		re := regexp.MustCompile(`("(?:qty|amount|quantity)":\s*)(\d+)`)
		if re.MatchString(origBody) {
			negStep := step
			negStep.Request.Body = re.ReplaceAllString(origBody, `${1}-1`)
			resp, body := execStep(client, negStep, vars)
			if resp != nil && resp.StatusCode < 400 {
				findings = append(findings, WorkflowFinding{
					Step:     step.Name,
					Strategy: "negative_qty",
					Type:     "logic-flaw",
					Evidence: fmt.Sprintf("negative qty accepted, status=%d, body=%s", resp.StatusCode, truncate(body, 200)),
					Severity: "high",
				})
			}
		}

	case "reorder":
		// Skip this step and try the next one directly
		if stepIdx+1 < len(wf.Steps) {
			nextStep := wf.Steps[stepIdx+1]
			resp, body := execStep(client, nextStep, vars)
			if resp != nil && resp.StatusCode < 400 {
				findings = append(findings, WorkflowFinding{
					Step:     step.Name,
					Strategy: "reorder",
					Type:     "state-confusion",
					Evidence: fmt.Sprintf("skipped step succeeded, status=%d, body=%s", resp.StatusCode, truncate(body, 200)),
					Severity: "medium",
				})
			}
		}

	case "skip_auth":
		// Try without cookies/auth headers
		noAuthClient := httpx.New(httpx.Options{TimeoutSec: 10, InsecureSkipVerify: true})
		resp, body := execStep(noAuthClient, step, vars)
		if resp != nil && resp.StatusCode < 400 {
			findings = append(findings, WorkflowFinding{
				Step:     step.Name,
				Strategy: "skip_auth",
				Type:     "auth-bypass",
				Evidence: fmt.Sprintf("step succeeded without auth, status=%d, body=%s", resp.StatusCode, truncate(body, 200)),
				Severity: "critical",
			})
		}
	}
	return findings
}

func checkAssertion(assertion string, status int, body string) bool {
	switch assertion {
	case "status_ok":
		return status < 400
	case "total_not_negative":
		re := regexp.MustCompile(`"total":\s*(-\d+)`)
		return !re.MatchString(body)
	case "qty_positive":
		re := regexp.MustCompile(`"(?:qty|quantity)":\s*(-\d+)`)
		return !re.MatchString(body)
	}
	return true
}

func substituteVars(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func extract(body string, expr string) string {
	// Simple regex-based extraction
	re, err := regexp.Compile(expr)
	if err != nil {
		return ""
	}
	m := re.FindStringSubmatch(body)
	if len(m) > 1 {
		return m[1]
	}
	if len(m) > 0 {
		return m[0]
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
