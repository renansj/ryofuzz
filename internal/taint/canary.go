package taint

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CanarySource tracks where a canary was injected
type CanarySource struct {
	Endpoint string
	Param    string
	Location string
	Canary   string
	Injected time.Time
}

// CanaryMatch records where a canary was found
type CanaryMatch struct {
	Source  CanarySource
	FoundAt string
	Context string
}

// InjectionTarget describes an endpoint and the parameters to seed with canaries.
type InjectionTarget struct {
	URL    string
	Method string
	Body   string
	Params []ParamRef // parameters to inject into
}

// ParamRef identifies a single injectable parameter.
type ParamRef struct {
	Name     string
	Location string // "query", "form", "json"
}

// Tracker manages canary injection and detection
type Tracker struct {
	mu       sync.Mutex
	canaries []CanarySource
	prefix   string
	// extra headers (auth/cookies) applied to every request
	headers map[string]string
}

func NewTracker() *Tracker {
	return &Tracker{prefix: "ryofz", headers: make(map[string]string)}
}

// SetHeaders configures auth/session headers propagated to all requests.
func (t *Tracker) SetHeaders(h map[string]string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range h {
		t.headers[k] = v
	}
}

// Generate creates a unique canary string and records its source.
func (t *Tracker) Generate(endpoint, param, location string) string {
	b := make([]byte, 8)
	rand.Read(b)
	canary := t.prefix + hex.EncodeToString(b)
	t.mu.Lock()
	t.canaries = append(t.canaries, CanarySource{
		Endpoint: endpoint,
		Param:    param,
		Location: location,
		Canary:   canary,
		Injected: time.Now(),
	})
	t.mu.Unlock()
	return canary
}

// Scan checks a response body for any previously injected canaries.
func (t *Tracker) Scan(responseBody, foundAtURL string) []CanaryMatch {
	t.mu.Lock()
	defer t.mu.Unlock()
	var matches []CanaryMatch
	for _, src := range t.canaries {
		if idx := strings.Index(responseBody, src.Canary); idx >= 0 {
			start := idx - 50
			if start < 0 {
				start = 0
			}
			end := idx + len(src.Canary) + 50
			if end > len(responseBody) {
				end = len(responseBody)
			}
			matches = append(matches, CanaryMatch{
				Source:  src,
				FoundAt: foundAtURL,
				Context: responseBody[start:end],
			})
		}
	}
	return matches
}

// applyHeaders adds configured auth/session headers to a request.
func (t *Tracker) applyHeaders(req *http.Request) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
}

// Inject seeds a unique canary into each parameter of each injection target.
// This is the write phase of stored/second-order detection: the canary is
// actually sent to the server so it can be persisted.
func (t *Tracker) Inject(client *http.Client, targets []InjectionTarget) {
	for _, tgt := range targets {
		method := tgt.Method
		if method == "" {
			method = "GET"
		}
		for _, p := range tgt.Params {
			canary := t.Generate(tgt.URL, p.Name, p.Location)
			reqURL := tgt.URL
			reqBody := tgt.Body
			contentType := ""

			switch p.Location {
			case "query":
				reqURL = injectQuery(tgt.URL, p.Name, canary)
			case "form":
				reqBody = injectForm(tgt.Body, p.Name, canary)
				contentType = "application/x-www-form-urlencoded"
			case "json":
				reqBody = injectJSONField(tgt.Body, p.Name, canary)
				contentType = "application/json"
			default:
				reqURL = injectQuery(tgt.URL, p.Name, canary)
			}

			var bodyReader io.Reader
			if reqBody != "" {
				bodyReader = bytes.NewReader([]byte(reqBody))
			}
			req, err := http.NewRequest(method, reqURL, bodyReader)
			if err != nil {
				continue
			}
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}
			t.applyHeaders(req)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}
}

// ScanEndpoints visits all endpoints and checks for canaries in their responses.
// This is the read phase: canaries injected earlier may now surface elsewhere.
func (t *Tracker) ScanEndpoints(client *http.Client, endpoints []string) []CanaryMatch {
	var allMatches []CanaryMatch
	for _, ep := range endpoints {
		req, err := http.NewRequest("GET", ep, nil)
		if err != nil {
			continue
		}
		t.applyHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		matches := t.Scan(string(body), ep)
		allMatches = append(allMatches, matches...)
	}
	return allMatches
}

// InjectAndScan performs the full two-phase flow: inject canaries into the
// targets, then scan all endpoints for where those canaries resurface.
func (t *Tracker) InjectAndScan(client *http.Client, targets []InjectionTarget, scanEndpoints []string) []CanaryMatch {
	t.Inject(client, targets)
	return t.ScanEndpoints(client, scanEndpoints)
}

// --- injection helpers ---

func injectQuery(rawURL, param, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func injectForm(body, param, value string) string {
	vals, err := url.ParseQuery(body)
	if err != nil {
		vals = url.Values{}
	}
	vals.Set(param, value)
	return vals.Encode()
}

func injectJSONField(body, field, value string) string {
	var obj map[string]interface{}
	if body == "" || json.Unmarshal([]byte(body), &obj) != nil {
		obj = map[string]interface{}{}
	}
	obj[field] = value
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return string(out)
}
