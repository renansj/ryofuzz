package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/renansj/ryofuzz/internal/httpx"
	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
	"github.com/renansj/ryofuzz/internal/util"
)

// Config do engine
type Config struct {
	Method      string
	URL         string
	Body        string
	Headers     []string
	Cookies     string
	Proxy       string
	Timeout     int
	FollowRedir bool
	// MaxBody bounds how many bytes of each response body are read into memory.
	// 0 applies util.DefaultMaxBodyBytes. Prevents OOM on hostile/huge bodies.
	MaxBody int64
	// VerifyTLS enables TLS certificate verification. Default (false) keeps the
	// pentest-friendly skip-verify behavior; --verify-tls flips it on (F3).
	VerifyTLS bool
}

// Response capturada
type Response struct {
	StatusCode  int
	Status      string
	Headers     http.Header
	Body        string
	BodyLength  int
	TimeMs      int64
	ContentType string
}

// FuzzResult - resultado de um request fuzzado
type FuzzResult struct {
	Payload  mutator.Payload
	Point    input.InjectionPoint
	Response Response
	Error    error
}

// CaptureBaseline sends the original request and captures the reference
// response. Compatibility wrapper around CaptureBaselineContext.
func CaptureBaseline(cfg Config) (*Response, error) {
	return CaptureBaselineContext(context.Background(), cfg)
}

// CaptureBaselineContext is the cancellable form of CaptureBaseline.
func CaptureBaselineContext(ctx context.Context, cfg Config) (*Response, error) {
	client := buildClient(cfg)
	req, err := buildRequest(ctx, cfg)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("baseline request falhou: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := util.ReadBodyLimited(resp.Body, cfg.MaxBody)

	return &Response{
		StatusCode:  resp.StatusCode,
		Status:      resp.Status,
		Headers:     resp.Header,
		Body:        string(bodyBytes),
		BodyLength:  len(bodyBytes),
		TimeMs:      elapsed,
		ContentType: resp.Header.Get("Content-Type"),
	}, nil
}

// Fuzz executes all payloads against injection points with concurrency.
// It is a compatibility wrapper around FuzzContext using a background context
// (no external cancellation). Prefer FuzzContext so Ctrl+C and a global scan
// timeout can cancel work in flight (review B1).
func Fuzz(cfg Config, points []input.InjectionPoint, payloads []mutator.Payload, concurrency, delayMs, rateLimit int, verbose bool) []FuzzResult {
	return FuzzContext(context.Background(), cfg, points, payloads, concurrency, delayMs, rateLimit, verbose)
}

// FuzzContext is the cancellable form of Fuzz. When ctx is cancelled (SIGINT,
// SIGTERM or a global timeout), the dispatch loop stops sending new payloads,
// in-flight requests are aborted via http.NewRequestWithContext, and whatever
// results were collected so far are returned.
func FuzzContext(ctx context.Context, cfg Config, points []input.InjectionPoint, payloads []mutator.Payload, concurrency, delayMs, rateLimit int, verbose bool) []FuzzResult {
	var results []FuzzResult
	var mu sync.Mutex

	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	// Singleton HTTP client (reuse connections)
	client := buildClient(cfg)

	// Rate limiter (properly managed ticker)
	var limiter <-chan time.Time
	var ticker *time.Ticker
	if rateLimit > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(rateLimit))
		limiter = ticker.C
		defer ticker.Stop()
	}

	total := len(payloads)
	done := 0

dispatch:
	for _, p := range payloads {
		// Stop dispatching as soon as the scan is cancelled.
		select {
		case <-ctx.Done():
			break dispatch
		default:
		}

		if rateLimit > 0 {
			select {
			case <-limiter:
			case <-ctx.Done():
				break dispatch
			}
		}
		if delayMs > 0 {
			select {
			case <-time.After(time.Duration(delayMs) * time.Millisecond):
			case <-ctx.Done():
				break dispatch
			}
		}

		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Done()
			break dispatch
		}
		go func(payload mutator.Payload) {
			defer wg.Done()
			defer func() { <-sem }()

			result := safeSendFuzzed(ctx, client, cfg, payload, verbose)

			mu.Lock()
			results = append(results, result)
			done++
			cur := done
			mu.Unlock()

			if cur%100 == 0 || verbose {
				fmt.Fprintf(os.Stderr, "\r[*] Progress: %d/%d requests sent", cur, total)
			}
		}(p)
	}

	wg.Wait()
	fmt.Fprintln(os.Stderr)
	return results
}

// safeSendFuzzed wraps sendFuzzedWith with a recover so a panic inside request
// construction, injection, or the HTTP client cannot crash the whole scan and
// lose every result. The panic is converted into a FuzzResult carrying the
// error, tagged with the payload that triggered it for triage.
func safeSendFuzzed(ctx context.Context, client *http.Client, cfg Config, payload mutator.Payload, verbose bool) (result FuzzResult) {
	defer func() {
		if r := recover(); r != nil {
			result = FuzzResult{
				Payload: payload,
				Point:   payload.Point,
				Error:   fmt.Errorf("panic while fuzzing payload %q (%s): %v", payload.Value, payload.Module, r),
			}
			if verbose {
				fmt.Fprintf(os.Stderr, "\n[!] recovered panic on payload %q (%s): %v\n", payload.Value, payload.Module, r)
			}
		}
	}()
	return sendFuzzedWith(ctx, client, cfg, payload, verbose)
}

func sendFuzzed(cfg Config, payload mutator.Payload, verbose bool) FuzzResult {
	return sendFuzzedWith(context.Background(), buildClient(cfg), cfg, payload, verbose)
}

func sendFuzzedWith(ctx context.Context, client *http.Client, cfg Config, payload mutator.Payload, verbose bool) FuzzResult {

	// Real multipart/form-data upload (when the module requests it via Metadata)
	if payload.Metadata != nil && payload.Metadata["upload"] == "1" {
		return sendMultipart(ctx, client, cfg, payload)
	}

	// Host-level raw path probe (e.g. infoleak: GET scheme://host/.git/config)
	if payload.Metadata != nil && payload.Metadata["rawpath"] != "" {
		return sendRawPath(ctx, client, cfg, payload)
	}

	// Construir request com payload injetado
	fuzzedURL := cfg.URL
	fuzzedBody := cfg.Body
	fuzzedHeaders := cfg.Headers
	fuzzedCookies := cfg.Cookies

	switch payload.Point.Location {
	case input.LocQueryParam:
		fuzzedURL = injectQueryParam(cfg.URL, payload.Point.Name, payload.Value)
	case input.LocJSONBody:
		fuzzedBody = injectJSON(cfg.Body, payload.Point.JSONPath, payload.Value)
	case input.LocFormBody:
		fuzzedBody = injectFormParam(cfg.Body, payload.Point.Name, payload.Value)
	case input.LocPath:
		fuzzedURL = injectPath(cfg.URL, payload.Point.OriginalValue, payload.Value)
	case input.LocHeader:
		fuzzedHeaders = injectHeader(cfg.Headers, payload.Point.Name, payload.Value)
	case input.LocCookie:
		fuzzedCookies = injectCookie(cfg.Cookies, payload.Point.Name, payload.Value)
	}

	modCfg := Config{
		Method:      cfg.Method,
		URL:         fuzzedURL,
		Body:        fuzzedBody,
		Headers:     fuzzedHeaders,
		Cookies:     fuzzedCookies,
		Proxy:       cfg.Proxy,
		Timeout:     cfg.Timeout,
		FollowRedir: cfg.FollowRedir,
	}

	req, err := buildRequest(ctx, modCfg)
	if err != nil {
		return FuzzResult{Payload: payload, Point: payload.Point, Error: err}
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return FuzzResult{Payload: payload, Point: payload.Point, Error: err}
	}
	defer resp.Body.Close()

	bodyBytes, _ := util.ReadBodyLimited(resp.Body, cfg.MaxBody)

	return FuzzResult{
		Payload: payload,
		Point:   payload.Point,
		Response: Response{
			StatusCode:  resp.StatusCode,
			Status:      resp.Status,
			Headers:     resp.Header,
			Body:        string(bodyBytes),
			BodyLength:  len(bodyBytes),
			TimeMs:      elapsed,
			ContentType: resp.Header.Get("Content-Type"),
		},
	}
}

// sendMultipart builds a real multipart/form-data upload request. The module
// signals this via Metadata: upload_field (form field name), upload_filename
// (the dangerous filename), upload_content (file bytes), upload_ctype (MIME).
func sendMultipart(ctx context.Context, client *http.Client, cfg Config, payload mutator.Payload) FuzzResult {
	field := payload.Metadata["upload_field"]
	if field == "" {
		field = payload.Point.Name
	}
	if field == "" {
		field = "file"
	}
	filename := payload.Metadata["upload_filename"]
	if filename == "" {
		filename = payload.Value
	}
	content := payload.Metadata["upload_content"]
	if content == "" {
		content = "ryofuzz-upload-test"
	}
	ctype := payload.Metadata["upload_ctype"]
	if ctype == "" {
		ctype = "application/octet-stream"
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	hdr := make(textproto.MIMEHeader)
	hdr.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, field, filename))
	hdr.Set("Content-Type", ctype)
	part, err := mw.CreatePart(hdr)
	if err == nil {
		part.Write([]byte(content))
	}
	mw.Close()

	method := cfg.Method
	if method == "" {
		method = "POST"
	}
	req, err := http.NewRequestWithContext(ctx, method, cfg.URL, &buf)
	if err != nil {
		return FuzzResult{Payload: payload, Point: payload.Point, Error: err}
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	for _, h := range cfg.Headers {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	if cfg.Cookies != "" {
		req.Header.Set("Cookie", cfg.Cookies)
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return FuzzResult{Payload: payload, Point: payload.Point, Error: err}
	}
	defer resp.Body.Close()
	bodyBytes, _ := util.ReadBodyLimited(resp.Body, cfg.MaxBody)

	return FuzzResult{
		Payload: payload,
		Point:   payload.Point,
		Response: Response{
			StatusCode:  resp.StatusCode,
			Status:      resp.Status,
			Headers:     resp.Header,
			Body:        string(bodyBytes),
			BodyLength:  len(bodyBytes),
			TimeMs:      elapsed,
			ContentType: resp.Header.Get("Content-Type"),
		},
	}
}

// sendRawPath issues a GET to scheme://host + rawpath, ignoring the original
// URL path/query. Used for host-level checks like sensitive file disclosure.
func sendRawPath(ctx context.Context, client *http.Client, cfg Config, payload mutator.Payload) FuzzResult {
	base, err := url.Parse(cfg.URL)
	if err != nil {
		return FuzzResult{Payload: payload, Point: payload.Point, Error: err}
	}
	rawpath := payload.Metadata["rawpath"]
	target := base.Scheme + "://" + base.Host + rawpath

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return FuzzResult{Payload: payload, Point: payload.Point, Error: err}
	}
	for _, h := range cfg.Headers {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	if cfg.Cookies != "" {
		req.Header.Set("Cookie", cfg.Cookies)
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return FuzzResult{Payload: payload, Point: payload.Point, Error: err}
	}
	defer resp.Body.Close()
	bodyBytes, _ := util.ReadBodyLimited(resp.Body, cfg.MaxBody)

	return FuzzResult{
		Payload: payload,
		Point:   payload.Point,
		Response: Response{
			StatusCode:  resp.StatusCode,
			Status:      resp.Status,
			Headers:     resp.Header,
			Body:        string(bodyBytes),
			BodyLength:  len(bodyBytes),
			TimeMs:      elapsed,
			ContentType: resp.Header.Get("Content-Type"),
		},
	}
}

func buildClient(cfg Config) *http.Client {
	return httpx.New(httpx.Options{
		TimeoutSec:         cfg.Timeout,
		Proxy:              cfg.Proxy,
		InsecureSkipVerify: !cfg.VerifyTLS,
		FollowRedirects:    cfg.FollowRedir,
	})
}

func buildRequest(ctx context.Context, cfg Config) (*http.Request, error) {
	var bodyReader io.Reader
	if cfg.Body != "" {
		bodyReader = strings.NewReader(cfg.Body)
	}

	method := cfg.Method
	if method == "" {
		if cfg.Body != "" {
			method = "POST"
		} else {
			method = "GET"
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, cfg.URL, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "ryofuzz/1.0.0")

	// Auto Content-Type
	if cfg.Body != "" && req.Header.Get("Content-Type") == "" {
		trimmed := strings.TrimSpace(cfg.Body)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	// Custom headers
	for _, h := range cfg.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	// Cookies
	if cfg.Cookies != "" {
		req.Header.Set("Cookie", cfg.Cookies)
	}

	return req, nil
}

// --- Injection helpers ---

func injectQueryParam(rawURL, param, value string) string {
	parsed, _ := url.Parse(rawURL)
	q := parsed.Query()
	q.Set(param, value)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func injectJSON(body, jsonPath, value string) string {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return body
	}

	parts := strings.Split(jsonPath, ".")
	setNested(obj, parts, value)

	result, _ := json.Marshal(obj)
	return string(result)
}

func setNested(obj map[string]interface{}, path []string, value string) {
	if len(path) == 1 {
		obj[path[0]] = value
		return
	}
	if next, ok := obj[path[0]].(map[string]interface{}); ok {
		setNested(next, path[1:], value)
	}
}

func injectFormParam(body, param, value string) string {
	values, err := url.ParseQuery(body)
	if err != nil {
		return param + "=" + url.QueryEscape(value)
	}
	values.Set(param, value)
	return values.Encode()
}

func injectPath(rawURL, original, value string) string {
	return strings.Replace(rawURL, original, value, 1)
}

func injectHeader(headers []string, name, value string) []string {
	var result []string
	found := false
	for _, h := range headers {
		if strings.HasPrefix(strings.ToLower(h), strings.ToLower(name)+":") {
			result = append(result, name+": "+value)
			found = true
		} else {
			result = append(result, h)
		}
	}
	if !found {
		result = append(result, name+": "+value)
	}
	return result
}

func injectCookie(cookies, name, value string) string {
	pairs := strings.Split(cookies, ";")
	var result []string
	found := false
	for _, pair := range pairs {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == name {
			result = append(result, name+"="+value)
			found = true
		} else {
			result = append(result, strings.TrimSpace(pair))
		}
	}
	if !found {
		result = append(result, name+"="+value)
	}
	return strings.Join(result, "; ")
}
