package behavioral

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/renansj/ryofuzz/internal/httpx"
)

// Engine implements behavioral intent mapping.
// Instead of "does this payload trigger a known bug?", it asks:
// "How does this server PROCESS my input? Where are the inconsistencies?"
//
// Phase 1: Probe - send structured input variations to map behavior
// Phase 2: Model - build a model of how the server treats input
// Phase 3: Attack - find inconsistencies in the model and exploit them
type Engine struct {
	Target     string
	Method     string
	Body       string
	Headers    []string
	Cookies    string
	ParamName  string
	ParamValue string
	Timeout    int
	client     *http.Client
	ctx        context.Context
}

// BehaviorModel represents the server's observed behavior
type BehaviorModel struct {
	InputType       string                    // what the server thinks our input is (url, query, filename, id, text)
	Transformations []string                  // what the server does to our input (url_fetch, db_query, file_read, reflect, ignore)
	Boundaries      []Boundary                // where behavior changes
	Inconsistencies []Inconsistency           // the bugs - where logic breaks
	ResponseMap     map[string]*ResponseClass // all observed response classes
}

// Boundary is where server behavior changes
type Boundary struct {
	Input       string
	Before      string // behavior before this input
	After       string // behavior after this input
	Trigger     string // what caused the change
	Description string
}

// Inconsistency is a logical contradiction in server behavior
type Inconsistency struct {
	Severity    string
	Title       string
	Description string
	ProofA      Probe  // request that shows behavior A
	ProofB      Probe  // request that shows contradicting behavior B
	Implication string // what this means for an attacker
}

// Probe is a single request/response pair
type Probe struct {
	Input   string
	Status  int
	Size    int
	TimeMs  int64
	Body    string
	Headers map[string]string
	Class   string // which response class this belongs to
}

// ResponseClass groups similar responses
type ResponseClass struct {
	Name    string
	Status  int
	SizeMin int
	SizeMax int
	TimeAvg int64
	Pattern string // what makes this class unique
	Count   int
	Samples []Probe
}

// Finding from behavioral analysis
type Finding struct {
	Severity    string
	Confidence  string
	Title       string
	Description string
	Evidence    []Probe
	Implication string
}

type Config struct {
	Target  string
	Method  string
	Body    string
	Headers []string
	Cookies string
	Param   string
	Value   string
	Timeout int
	Ctx     context.Context
}

func New(cfg Config) *Engine {
	return &Engine{
		Target:     cfg.Target,
		Method:     cfg.Method,
		Body:       cfg.Body,
		Headers:    cfg.Headers,
		Cookies:    cfg.Cookies,
		ParamName:  cfg.Param,
		ParamValue: cfg.Value,
		Timeout:    cfg.Timeout,
		ctx:        cfg.Ctx,
	}
}

// context returns the engine context, defaulting to Background when unset so
// direct (non-CLI) callers keep working.
func (e *Engine) context() context.Context {
	if e.ctx == nil {
		return context.Background()
	}
	return e.ctx
}

// Run executes the full behavioral analysis pipeline
func (e *Engine) Run() (*BehaviorModel, []Finding) {
	fmt.Println("[behavioral] Phase 1: Probing server intent...")
	probes := e.phase1Probe()

	fmt.Printf("[behavioral] Phase 2: Building behavior model (%d probes)...\n", len(probes))
	model := e.phase2Model(probes)

	fmt.Printf("[behavioral] Phase 3: Finding inconsistencies (classes=%d, boundaries=%d)...\n",
		len(model.ResponseMap), len(model.Boundaries))
	findings := e.phase3Attack(model)

	return model, findings
}

// Phase 1: Send structured variations to understand how the server processes input
func (e *Engine) phase1Probe() []Probe {
	var probes []Probe

	// Group 1: Type detection - what does the server think our input is?
	typeProbes := []struct {
		input string
		label string
	}{
		{e.ParamValue, "original"},
		{"", "empty"},
		{" ", "space"},
		{"null", "null_word"},
		{"true", "boolean"},
		{"123", "integer"},
		{"-1", "negative"},
		{"1.5", "float"},
		{"test@email.com", "email"},
		{"http://127.0.0.1", "url_internal"},
		{"http://example.com", "url_external"},
		{"/etc/passwd", "path_absolute"},
		{"../test", "path_relative"},
		{`{"key":"value"}`, "json"},
		{"<xml>test</xml>", "xml"},
		{"SELECT 1", "sql_keyword"},
		{"AAAA", "alpha"},
	}

	fmt.Printf("[behavioral]   Type detection: %d probes\n", len(typeProbes))
	for _, tp := range typeProbes {
		p := e.send(tp.input)
		p.Class = tp.label
		probes = append(probes, p)
	}

	// Group 2: Transformation detection - what does the server DO with our input?
	transformProbes := []struct {
		input string
		label string
	}{
		// Does it URL-decode?
		{"%41%42%43", "urlencode_abc"},
		{"ABC", "plain_abc"},
		// Does it HTML-decode?
		{"&#65;&#66;&#67;", "htmlencode_abc"},
		// Does it reflect input back?
		{"RYOFUZZ_CANARY_12345", "canary"},
		// Does it follow URLs?
		{"http://127.0.0.1:1", "url_dead_port"},
		// Does it resolve DNS?
		{"http://definitely-not-a-real-domain-xyz123.com", "dns_resolve"},
		// Does it read files?
		{"/dev/null", "file_devnull"},
		{"C:\\Windows\\System32\\drivers\\etc\\hosts", "file_windows"},
		// Does it execute?
		{"$(echo test)", "exec_subshell"},
		{"`echo test`", "exec_backtick"},
		{"{{7*7}}", "template_expr"},
		{"${7*7}", "expression"},
	}

	fmt.Printf("[behavioral]   Transformation detection: %d probes\n", len(transformProbes))
	for _, tp := range transformProbes {
		p := e.send(tp.input)
		p.Class = tp.label
		probes = append(probes, p)
	}

	// Group 3: Boundary detection - where does behavior change?
	// Incrementally add special chars to find where parsing breaks
	boundaryProbes := []struct {
		input string
		label string
	}{
		{"a", "char_a"},
		{"'", "single_quote"},
		{`"`, "double_quote"},
		{"\\", "backslash"},
		{"\n", "newline"},
		{"\r\n", "crlf"},
		{"\x00", "null_byte"},
		{"<", "lt"},
		{">", "gt"},
		{"{", "open_brace"},
		{"}", "close_brace"},
		{"|", "pipe"},
		{";", "semicolon"},
		{"&", "ampersand"},
		{"$", "dollar"},
		{"`", "backtick"},
		{"(", "open_paren"},
		{")", "close_paren"},
		{"..", "double_dot"},
		{"://", "scheme_sep"},
		{"@", "at_sign"},
		{"#", "hash"},
		{"%", "percent"},
		{"\t", "tab"},
	}

	fmt.Printf("[behavioral]   Boundary detection: %d probes\n", len(boundaryProbes))
	for _, bp := range boundaryProbes {
		// Test the char alone
		p := e.send(bp.input)
		p.Class = "boundary_" + bp.label
		probes = append(probes, p)
		// Test the char prepended to original value
		p2 := e.send(bp.input + e.ParamValue)
		p2.Class = "prepend_" + bp.label
		probes = append(probes, p2)
		// Test the char appended
		p3 := e.send(e.ParamValue + bp.input)
		p3.Class = "append_" + bp.label
		probes = append(probes, p3)
	}

	// Group 4: Length boundaries
	lengths := []int{1, 10, 100, 500, 1000, 5000, 10000}
	fmt.Printf("[behavioral]   Length boundaries: %d probes\n", len(lengths))
	for _, l := range lengths {
		p := e.send(strings.Repeat("A", l))
		p.Class = fmt.Sprintf("length_%d", l)
		probes = append(probes, p)
	}

	// Group 5: Timing probes - detect processing differences
	timingProbes := []struct {
		input string
		label string
	}{
		{"http://127.0.0.1:1", "timing_dead_port"},
		{"http://10.255.255.1", "timing_timeout_ip"},
		{strings.Repeat("a]", 500), "timing_regex_bomb"},
		{strings.Repeat("(", 50) + "a" + strings.Repeat(")", 50), "timing_nested_parens"},
		{`{"a":` + strings.Repeat(`{"a":`, 100) + `1` + strings.Repeat(`}`, 101), "timing_deep_json"},
	}

	fmt.Printf("[behavioral]   Timing probes: %d probes\n", len(timingProbes))
	for _, tp := range timingProbes {
		p := e.send(tp.input)
		p.Class = tp.label
		probes = append(probes, p)
	}

	return probes
}

// Phase 2: Analyze probes and build a model of server behavior
func (e *Engine) phase2Model(probes []Probe) *BehaviorModel {
	model := &BehaviorModel{
		ResponseMap: make(map[string]*ResponseClass),
	}

	// Cluster probes by response pattern
	for i := range probes {
		p := &probes[i]
		classKey := fmt.Sprintf("%d_%d", p.Status, p.Size/50*50)

		if cls, ok := model.ResponseMap[classKey]; ok {
			cls.Count++
			if p.Size < cls.SizeMin {
				cls.SizeMin = p.Size
			}
			if p.Size > cls.SizeMax {
				cls.SizeMax = p.Size
			}
			cls.TimeAvg = (cls.TimeAvg*int64(cls.Count-1) + p.TimeMs) / int64(cls.Count)
			if len(cls.Samples) < 5 {
				cls.Samples = append(cls.Samples, *p)
			}
		} else {
			model.ResponseMap[classKey] = &ResponseClass{
				Name:    classKey,
				Status:  p.Status,
				SizeMin: p.Size,
				SizeMax: p.Size,
				TimeAvg: p.TimeMs,
				Count:   1,
				Samples: []Probe{*p},
			}
		}
	}

	// Determine input type based on behavioral differences
	model.InputType = e.inferInputType(probes)
	model.Transformations = e.inferTransformations(probes)
	// If we know it's a URL parameter, ensure url_fetch is in transformations
	if strings.Contains(model.InputType, "url") && !slices.Contains(model.Transformations, "url_fetch") {
		model.Transformations = append(model.Transformations, "url_fetch")
	}
	model.Boundaries = e.findBoundaries(probes)

	return model
}

// Phase 3: Find inconsistencies in the model and generate findings
func (e *Engine) phase3Attack(model *BehaviorModel) []Finding {
	var findings []Finding

	// Report what we learned about the server
	findings = append(findings, Finding{
		Severity:    "info",
		Confidence:  "confirmed",
		Title:       fmt.Sprintf("Server treats input as: %s", model.InputType),
		Description: fmt.Sprintf("Detected transformations: %s", strings.Join(model.Transformations, ", ")),
		Implication: "Attack surface mapped",
	})

	// Check each inconsistency
	for _, inc := range model.Inconsistencies {
		findings = append(findings, Finding{
			Severity:    inc.Severity,
			Confidence:  "high",
			Title:       inc.Title,
			Description: inc.Description,
			Evidence:    []Probe{inc.ProofA, inc.ProofB},
			Implication: inc.Implication,
		})
	}

	// Analyze boundaries - only report filter bypasses, not expected validation
	for _, b := range model.Boundaries {
		if b.Before == "success" && b.After == "error" {
			// Expected: valid input works, invalid doesn't. Skip unless interesting.
			continue
		}
		if b.Before == "error" && b.After == "success" {
			// Something that SHOULD be rejected is accepted
			findings = append(findings, Finding{
				Severity:    "high",
				Confidence:  "high",
				Title:       fmt.Sprintf("Filter bypass via '%s'", b.Trigger),
				Description: b.Description,
				Implication: "Server accepts input that should be blocked - possible injection point",
			})
		}
	}

	// Check for SSRF intent
	if slices.Contains(model.Transformations, "url_fetch") {
		findings = append(findings, e.probeSSRFDepth()...)
	}
	// Check for reflection (XSS potential)
	if slices.Contains(model.Transformations, "reflect") {
		findings = append(findings, e.probeReflectionContext()...)
	}
	// Check for file operations
	if slices.Contains(model.Transformations, "file_read") {
		findings = append(findings, e.probeFileAccess()...)
	}
	// Check for execution
	if slices.Contains(model.Transformations, "execute") {
		findings = append(findings, e.probeExecution()...)
	}
	// Check for database interaction
	if slices.Contains(model.Transformations, "db_query") {
		findings = append(findings, e.probeDatabase()...)
	}

	return findings
}

// --- Inference functions ---

func (e *Engine) inferInputType(probes []Probe) string {
	// If original value is a URL, the server processes URLs
	if strings.HasPrefix(e.ParamValue, "http://") || strings.HasPrefix(e.ParamValue, "https://") {
		return "url (server fetches it)"
	}

	original := findProbe(probes, "original")
	urlInternal := findProbe(probes, "url_internal")
	urlExternal := findProbe(probes, "url_external")
	pathAbs := findProbe(probes, "path_absolute")
	integer := findProbe(probes, "integer")
	canary := findProbe(probes, "canary")

	// If URL inputs produce drastically different timing/responses than non-URLs
	if urlExternal != nil && original != nil {
		if urlExternal.TimeMs > 500 || (urlExternal.Status == 200 && urlExternal.Size != original.Size) {
			return "url (server fetches it)"
		}
	}
	if urlInternal != nil && urlInternal.Status == 500 && original.Status == 200 {
		return "url (server fetches it, internal blocked)"
	}

	// If file paths produce different responses
	if pathAbs != nil && original != nil && pathAbs.Status != original.Status {
		return "file path"
	}

	// If integers produce different response size (database lookup)
	if integer != nil && original != nil && integer.Size != original.Size && integer.Status == 200 {
		return "database identifier"
	}

	// If input is reflected verbatim
	if canary != nil && strings.Contains(canary.Body, "RYOFUZZ_CANARY_12345") {
		return "reflected text"
	}

	return "unknown (needs more probing)"
}

func (e *Engine) inferTransformations(probes []Probe) []string {
	var transforms []string

	canary := findProbe(probes, "canary")
	urlDead := findProbe(probes, "url_dead_port")
	dnsResolve := findProbe(probes, "dns_resolve")
	urlEncABC := findProbe(probes, "urlencode_abc")
	plainABC := findProbe(probes, "plain_abc")
	execSub := findProbe(probes, "exec_subshell")
	templateExpr := findProbe(probes, "template_expr")
	original := findProbe(probes, "original")

	// URL fetching
	if urlDead != nil && (urlDead.TimeMs > 1000 || urlDead.Status == 500) {
		transforms = append(transforms, "url_fetch")
	}
	if dnsResolve != nil && dnsResolve.TimeMs > 2000 {
		transforms = append(transforms, "dns_resolution")
	}

	// Reflection
	if canary != nil && strings.Contains(canary.Body, "RYOFUZZ_CANARY_12345") {
		transforms = append(transforms, "reflect")
	}

	// URL decoding
	if urlEncABC != nil && plainABC != nil {
		if urlEncABC.Status == plainABC.Status && urlEncABC.Size == plainABC.Size {
			transforms = append(transforms, "url_decode")
		}
	}

	// Template evaluation
	if templateExpr != nil && original != nil {
		if strings.Contains(templateExpr.Body, "49") && !strings.Contains(original.Body, "49") {
			transforms = append(transforms, "template_eval")
		}
	}

	// Command execution
	if execSub != nil && original != nil {
		if execSub.Status != original.Status || execSub.TimeMs > original.TimeMs*3 {
			transforms = append(transforms, "execute")
		}
	}

	if len(transforms) == 0 {
		transforms = append(transforms, "unknown")
	}
	return transforms
}

func (e *Engine) findBoundaries(probes []Probe) []Boundary {
	var boundaries []Boundary
	original := findProbe(probes, "original")
	if original == nil {
		return boundaries
	}

	// Compare each boundary probe to original
	for _, p := range probes {
		if !strings.HasPrefix(p.Class, "boundary_") {
			continue
		}
		charName := strings.TrimPrefix(p.Class, "boundary_")

		if p.Status != original.Status {
			before := "success"
			after := "error"
			if original.Status >= 400 {
				before = "error"
			}
			if p.Status < 400 {
				after = "success"
			}
			boundaries = append(boundaries, Boundary{
				Input:       p.Input,
				Before:      before,
				After:       after,
				Trigger:     charName,
				Description: fmt.Sprintf("Character '%s' changes response from %d to %d", charName, original.Status, p.Status),
			})
		}
	}

	return boundaries
}

// --- Targeted probing based on discovered intent ---

func (e *Engine) probeSSRFDepth() []Finding {
	var findings []Finding

	// We know the server fetches URLs - try internal targets
	targets := []struct {
		url   string
		label string
	}{
		{"http://169.254.169.254/latest/meta-data/", "AWS metadata (direct)"},
		{"http://0xA9FEA9FE/", "AWS metadata (hex)"},
		{"http://2852039166/", "AWS metadata (decimal)"},
		{"http://127.0.0.1:6379/", "Redis"},
		{"http://127.0.0.1:9200/", "Elasticsearch"},
		{"http://127.0.0.1:3000/", "Internal app (3000)"},
	}

	blocked := e.send("http://169.254.169.254/latest/meta-data/")
	for _, t := range targets {
		p := e.send(t.url)
		// Detect SSRF: metadata content, timeout (connection attempt), or different from blocked
		if strings.Contains(p.Body, "meta-data") || strings.Contains(p.Body, "AccessKeyId") || strings.Contains(p.Body, "ami-id") {
			findings = append(findings, Finding{
				Severity:    "critical",
				Confidence:  "confirmed",
				Title:       "SSRF - Metadata accessed: " + t.label,
				Description: fmt.Sprintf("Server fetched %s and returned cloud metadata", t.url),
				Evidence:    []Probe{p},
				Implication: "Cloud credential theft possible via metadata service",
			})
		} else if p.TimeMs > 3000 {
			// Timeout = server attempted to connect (SSRF confirmed by timing)
			findings = append(findings, Finding{
				Severity:    "high",
				Confidence:  "high",
				Title:       "SSRF - Connection attempt (timeout): " + t.label,
				Description: fmt.Sprintf("Server attempted connection to %s (took %dms)", t.url, p.TimeMs),
				Evidence:    []Probe{p},
				Implication: "Server makes outbound requests to attacker-controlled destinations",
			})
		} else if strings.Contains(p.Body, "refused") || strings.Contains(p.Body, "Connection refused") {
			findings = append(findings, Finding{
				Severity:    "high",
				Confidence:  "confirmed",
				Title:       "SSRF - Internal port scan: " + t.label,
				Description: fmt.Sprintf("Server connected to %s and got connection refused", t.url),
				Evidence:    []Probe{p},
				Implication: "Internal network accessible - port scanning possible",
			})
		} else if p.Status != blocked.Status && p.Status != 403 {
			findings = append(findings, Finding{
				Severity:    "medium",
				Confidence:  "medium",
				Title:       "SSRF - Filter bypass (different response): " + t.label,
				Description: fmt.Sprintf("Server response differs from blocked (%d vs %d)", p.Status, blocked.Status),
				Evidence:    []Probe{blocked, p},
				Implication: "SSRF filter can be bypassed with alternative IP formats",
			})
		}
	}
	_ = blocked
	return findings
}

func (e *Engine) probeReflectionContext() []Finding {
	var findings []Finding

	// We know input is reflected - determine if it's executable
	tests := []struct {
		input    string
		label    string
		confirms string
	}{
		{"<b>RYOTEST</b>", "html_tags", "<b>RYOTEST</b>"},
		{"<img src=x>", "img_tag", "<img src=x>"},
		{`"onmouseover="alert(1)`, "event_handler", "onmouseover"},
	}

	for _, t := range tests {
		p := e.send(t.input)
		if strings.Contains(p.Body, t.confirms) {
			ct := ""
			if v, ok := p.Headers["Content-Type"]; ok {
				ct = v
			}
			if strings.Contains(ct, "html") {
				findings = append(findings, Finding{
					Severity:    "high",
					Confidence:  "confirmed",
					Title:       "XSS - " + t.label + " reflected in HTML without encoding",
					Evidence:    []Probe{p},
					Implication: "Client-side code execution possible",
				})
			}
		}
	}
	return findings
}

func (e *Engine) probeFileAccess() []Finding {
	var findings []Finding
	paths := []struct {
		path     string
		evidence string
	}{
		{"/etc/passwd", "root:"},
		{"/etc/shadow", "root:"},
		{"../../../../etc/passwd", "root:"},
		{"/proc/self/environ", "PATH="},
	}
	for _, p := range paths {
		probe := e.send(p.path)
		if strings.Contains(probe.Body, p.evidence) {
			findings = append(findings, Finding{
				Severity:    "critical",
				Confidence:  "confirmed",
				Title:       "LFI - File read confirmed: " + p.path,
				Evidence:    []Probe{probe},
				Implication: "Arbitrary file read on the server",
			})
			break
		}
	}
	return findings
}

func (e *Engine) probeExecution() []Finding {
	var findings []Finding
	cmds := []struct {
		input    string
		evidence string
	}{
		{";id", "uid="},
		{"$(id)", "uid="},
		{"|id", "uid="},
	}
	for _, c := range cmds {
		p := e.send(c.input)
		if strings.Contains(p.Body, c.evidence) {
			findings = append(findings, Finding{
				Severity:    "critical",
				Confidence:  "confirmed",
				Title:       "RCE - Command execution confirmed",
				Evidence:    []Probe{p},
				Implication: "Arbitrary command execution on the server",
			})
			break
		}
	}
	return findings
}

func (e *Engine) probeDatabase() []Finding {
	var findings []Finding
	// Send sleep-based probes to confirm DB interaction
	sleeps := []struct {
		input string
		label string
	}{
		{"' OR SLEEP(3)-- ", "MySQL"},
		{"' OR pg_sleep(3)-- ", "PostgreSQL"},
		{"'; WAITFOR DELAY '0:0:3'-- ", "MSSQL"},
	}
	baseline := e.send(e.ParamValue)
	for _, s := range sleeps {
		p := e.send(s.input)
		if p.TimeMs > baseline.TimeMs+2500 {
			findings = append(findings, Finding{
				Severity:    "critical",
				Confidence:  "confirmed",
				Title:       fmt.Sprintf("SQL Injection (time-based) - %s confirmed", s.label),
				Evidence:    []Probe{baseline, p},
				Implication: fmt.Sprintf("Blind SQL injection via time delay (%dms vs %dms baseline)", p.TimeMs, baseline.TimeMs),
			})
			break
		}
	}
	return findings
}

// --- HTTP execution ---

func (e *Engine) send(value string) Probe {
	req := e.buildRequest(value)
	if req == nil {
		return Probe{Input: value, Status: -1}
	}

	start := time.Now()
	resp, err := e.getClient().Do(req)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		return Probe{Input: value, Status: -1, TimeMs: elapsed}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return Probe{
		Input:   value,
		Status:  resp.StatusCode,
		Size:    len(bodyBytes),
		TimeMs:  elapsed,
		Body:    string(bodyBytes),
		Headers: headers,
	}
}

func (e *Engine) buildRequest(value string) *http.Request {
	targetURL := e.Target
	body := e.Body
	method := e.Method
	if method == "" {
		if body != "" {
			method = "POST"
		} else {
			method = "GET"
		}
	}

	// Inject value into the appropriate location
	if body != "" {
		// Replace in body
		body = strings.Replace(body, e.ParamValue, value, 1)
	} else {
		// Replace in URL query
		parsed, err := url.Parse(targetURL)
		if err != nil {
			return nil
		}
		q := parsed.Query()
		q.Set(e.ParamName, value)
		parsed.RawQuery = q.Encode()
		targetURL = parsed.String()
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(e.context(), method, targetURL, bodyReader)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "ryofuzz/0.4 behavioral-mode")
	if body != "" {
		if strings.HasPrefix(strings.TrimSpace(body), "{") {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	for _, h := range e.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	if e.Cookies != "" {
		req.Header.Set("Cookie", e.Cookies)
	}
	return req
}

func (e *Engine) getClient() *http.Client {
	if e.client != nil {
		return e.client
	}
	e.client = httpx.New(httpx.Options{
		TimeoutSec:         e.Timeout,
		InsecureSkipVerify: true,
	})
	return e.client
}

// --- Helpers ---

func findProbe(probes []Probe, class string) *Probe {
	for i := range probes {
		if probes[i].Class == class {
			return &probes[i]
		}
	}
	return nil
}

// PrintModel outputs the behavior model in a readable format
func PrintModel(model *BehaviorModel) {
	fmt.Println("\n[behavioral] === BEHAVIOR MODEL ===")
	fmt.Printf("  Input type:       %s\n", model.InputType)
	fmt.Printf("  Transformations:  %s\n", strings.Join(model.Transformations, ", "))
	fmt.Printf("  Response classes: %d\n", len(model.ResponseMap))
	fmt.Printf("  Boundaries:       %d\n", len(model.Boundaries))

	// Sort classes by count
	var classes []*ResponseClass
	for _, c := range model.ResponseMap {
		classes = append(classes, c)
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i].Count > classes[j].Count })

	fmt.Println("\n  Response classes (grouped by behavior):")
	for _, c := range classes {
		fmt.Printf("    [%d] status=%d size=%d-%d avg_time=%dms (n=%d)\n",
			c.Status, c.Status, c.SizeMin, c.SizeMax, c.TimeAvg, c.Count)
	}

	if len(model.Boundaries) > 0 {
		fmt.Println("\n  Behavior boundaries (where server logic changes):")
		for _, b := range model.Boundaries {
			fmt.Printf("    '%s': %s -> %s (%s)\n", b.Trigger, b.Before, b.After, b.Description)
		}
	}
}

// PrintFindings outputs findings
func PrintFindings(findings []Finding) {
	fmt.Printf("\n[behavioral] === FINDINGS: %d ===\n", len(findings))

	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.Slice(findings, func(i, j int) bool {
		return sevOrder[findings[i].Severity] < sevOrder[findings[j].Severity]
	})

	for i, f := range findings {
		sev := strings.ToUpper(f.Severity)
		fmt.Printf("\n  %d. [%s] %s\n", i+1, sev, f.Title)
		if f.Description != "" {
			fmt.Printf("     %s\n", f.Description)
		}
		if f.Implication != "" {
			fmt.Printf("     -> %s\n", f.Implication)
		}
		if len(f.Evidence) > 0 {
			for _, e := range f.Evidence {
				body := e.Body
				if len(body) > 100 {
					body = body[:100] + "..."
				}
				fmt.Printf("     Proof: input=%q status=%d size=%d time=%dms\n", truncate(e.Input, 40), e.Status, e.Size, e.TimeMs)
			}
		}
	}

	// Summary
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Printf("\n  Summary: critical=%d high=%d medium=%d low=%d info=%d\n",
		counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"])
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// Unused but keeping for potential future use
var _ = math.Abs
