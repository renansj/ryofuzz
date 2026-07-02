package nuclei

import (
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/renansj/ryofuzz/internal/httpx"
	"github.com/renansj/ryofuzz/internal/util"
)

// httpReq is a fully-interpolated request ready to send.
type httpReq struct {
	method  string
	url     string
	headers map[string]string
	body    string
	raw     string // if set, a raw request (byte fidelity)
}

func newHTTPClient(timeout int, proxy string, follow bool) *http.Client {
	return httpx.New(httpx.Options{
		TimeoutSec:         timeout,
		Proxy:              proxy,
		FollowRedirects:    follow,
		InsecureSkipVerify: true,
	})
}

// buildRequests produces concrete requests from a Request definition, applying
// interpolation to paths/raw/headers/body.
func buildRequests(def Request, baseURL string, env map[string]interface{}, rng *rand.Rand, preCache map[string]string) []httpReq {
	var out []httpReq
	method := strings.ToUpper(def.Method)
	if method == "" {
		method = "GET"
	}

	interp := func(s string) string {
		s = preprocess(s, preCache, rng)
		return interpolate(s, env)
	}

	// Raw requests take precedence (byte fidelity).
	for _, raw := range def.Raw {
		out = append(out, httpReq{raw: interp(raw), url: baseURL})
	}

	headers := map[string]string{}
	for k, v := range def.Headers {
		headers[interp(k)] = interp(v)
	}
	body := interp(def.Body)

	for _, p := range def.Path {
		u := interp(p)
		u = resolveURL(baseURL, u)
		out = append(out, httpReq{method: method, url: u, headers: headers, body: body})
	}
	return out
}

func resolveURL(base, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}

// doRequest sends a request (raw or structured) and returns response data.
func doRequest(client *http.Client, hr httpReq, def Request) *respData {
	if def.MaxRedirects > 0 || def.Redirects {
		// follow redirects for this request
		client = &http.Client{Timeout: client.Timeout, Transport: client.Transport}
	}

	var req *http.Request
	var err error

	if hr.raw != "" {
		req, err = parseRawRequest(hr.raw, hr.url)
	} else {
		var bodyReader io.Reader
		if hr.body != "" {
			bodyReader = strings.NewReader(hr.body)
		}
		req, err = http.NewRequest(hr.method, hr.url, bodyReader)
		if err == nil {
			req.Header.Set("User-Agent", "ryofuzz/1.0 (nuclei-compat)")
			for k, v := range hr.headers {
				req.Header.Set(k, v)
			}
		}
	}
	if err != nil {
		return nil
	}

	start := time.Now()
	resp, err := client.Do(req)
	dur := time.Since(start).Milliseconds()
	if err != nil {
		return nil
	}
	body, _ := util.ReadBodyLimited(resp.Body, 0)
	resp.Body.Close()
	return responseToData(resp, string(body), dur)
}

// parseRawRequest builds an *http.Request from a raw HTTP request string.
func parseRawRequest(raw, baseURL string) (*http.Request, error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return http.NewRequest("GET", baseURL, nil)
	}
	// Request line: METHOD PATH HTTP/x
	parts := strings.Fields(lines[0])
	method, path := "GET", "/"
	if len(parts) >= 2 {
		method, path = parts[0], parts[1]
	}

	headers := map[string]string{}
	bodyStart := len(lines)
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			bodyStart = i + 1
			break
		}
		kv := strings.SplitN(lines[i], ":", 2)
		if len(kv) == 2 {
			headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	body := ""
	if bodyStart < len(lines) {
		body = strings.Join(lines[bodyStart:], "\n")
	}

	// Build full URL from baseURL host + raw path
	fullURL := path
	if strings.HasPrefix(path, "/") {
		u, err := url.Parse(baseURL)
		if err == nil {
			fullURL = u.Scheme + "://" + u.Host + path
		}
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, fullURL, bodyReader)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	return req, nil
}

// responseToData converts an http.Response + body into respData.
func responseToData(resp *http.Response, body string, durMs int64) *respData {
	var hdr strings.Builder
	hmap := make(map[string][]string)
	for k, vals := range resp.Header {
		hmap[k] = vals
		for _, v := range vals {
			hdr.WriteString(k + ": " + v + "\n")
		}
	}
	statusLine := resp.Proto + " " + resp.Status + "\n"
	rawAll := statusLine + hdr.String() + "\n" + body
	return &respData{
		status:     resp.StatusCode,
		headersRaw: hdr.String(),
		headerMap:  hmap,
		body:       body,
		durationMs: durMs,
		rawAll:     rawAll,
	}
}
