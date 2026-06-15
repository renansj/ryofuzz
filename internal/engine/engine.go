package engine

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
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

// CaptureBaseline envia o request original e captura a resposta de referência
func CaptureBaseline(cfg Config) (*Response, error) {
	client := buildClient(cfg)
	req, err := buildRequest(cfg)
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

	bodyBytes, _ := io.ReadAll(resp.Body)

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

// Fuzz executes all payloads against injection points with concurrency
func Fuzz(cfg Config, points []input.InjectionPoint, payloads []mutator.Payload, concurrency, delayMs, rateLimit int, verbose bool) []FuzzResult {
	var results []FuzzResult
	var mu sync.Mutex

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

	for _, p := range payloads {
		if rateLimit > 0 {
			<-limiter
		}
		if delayMs > 0 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(payload mutator.Payload) {
			defer wg.Done()
			defer func() { <-sem }()

			result := sendFuzzedWith(client, cfg, payload, verbose)

			mu.Lock()
			results = append(results, result)
			done++
			if done%100 == 0 || verbose {
				fmt.Printf("\r[*] Progress: %d/%d requests sent", done, total)
			}
			mu.Unlock()
		}(p)
	}

	wg.Wait()
	fmt.Println()
	return results
}

func sendFuzzed(cfg Config, payload mutator.Payload, verbose bool) FuzzResult {
	return sendFuzzedWith(buildClient(cfg), cfg, payload, verbose)
}

func sendFuzzedWith(client *http.Client, cfg Config, payload mutator.Payload, verbose bool) FuzzResult {

	// Real multipart/form-data upload (when the module requests it via Metadata)
	if payload.Metadata != nil && payload.Metadata["upload"] == "1" {
		return sendMultipart(client, cfg, payload)
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

	req, err := buildRequest(modCfg)
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

	bodyBytes, _ := io.ReadAll(resp.Body)

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
func sendMultipart(client *http.Client, cfg Config, payload mutator.Payload) FuzzResult {
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
	req, err := http.NewRequest(method, cfg.URL, &buf)
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
	bodyBytes, _ := io.ReadAll(resp.Body)

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
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 100,
		DisableKeepAlives:   false,
	}

	if cfg.Proxy != "" {
		proxyURL, _ := url.Parse(cfg.Proxy)
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
	}

	if !cfg.FollowRedir {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

func buildRequest(cfg Config) (*http.Request, error) {
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

	req, err := http.NewRequest(method, cfg.URL, bodyReader)
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
