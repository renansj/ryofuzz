package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/vulns"
)

// Proxy is a MITM HTTP/HTTPS proxy with light fuzzing.
type Proxy struct {
	listenAddr string
	ca         *x509.Certificate
	caKey      *ecdsa.PrivateKey
	caPEM      []byte

	findings []*vulns.Finding
	mu       sync.Mutex
	seen     map[string]bool

	certCache   map[string]*tls.Certificate
	certCacheMu sync.Mutex

	recorder *EndpointRecorder

	// scope: if non-empty, only hosts matching one of these suffixes are fuzzed.
	// Recon/mapping still happens for all traffic; only active probing is gated.
	scope []string

	OnFinding func(*vulns.Finding)
}

// NewProxy creates a proxy with a fresh CA.
func NewProxy(addr string) (*Proxy, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ryofuzz CA", Organization: []string{"ryofuzz"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	return &Proxy{
		listenAddr: addr,
		ca:         ca,
		caKey:      caKey,
		caPEM:      caPEM,
		seen:       make(map[string]bool),
		certCache:  make(map[string]*tls.Certificate),
		recorder:   NewEndpointRecorder(),
	}, nil
}

// ExportCA writes the CA cert PEM to a file.
func (p *Proxy) ExportCA(path string) error {
	return os.WriteFile(path, p.caPEM, 0644)
}

// Findings returns all collected findings.
func (p *Proxy) Findings() []*vulns.Finding {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := make([]*vulns.Finding, len(p.findings))
	copy(cp, p.findings)
	return cp
}

// ExportEndpoints writes the discovered endpoints as an OpenAPI 3.0 spec.
func (p *Proxy) ExportEndpoints(path string) error {
	return p.recorder.ExportOpenAPI(path)
}

// SetScope restricts active fuzzing to hosts matching the given suffixes.
// Empty scope means everything is in scope. Recon mapping is never gated.
func (p *Proxy) SetScope(hosts []string) {
	var cleaned []string
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h != "" {
			cleaned = append(cleaned, strings.ToLower(h))
		}
	}
	p.scope = cleaned
}

// inScope reports whether a host is allowed for active fuzzing.
func (p *Proxy) inScope(host string) bool {
	if len(p.scope) == 0 {
		return true
	}
	host = strings.ToLower(hostOnly(host))
	for _, s := range p.scope {
		if host == s || strings.HasSuffix(host, "."+s) || strings.Contains(host, s) {
			return true
		}
	}
	return false
}

// EndpointCount returns how many distinct endpoints were observed.
func (p *Proxy) EndpointCount() int {
	return p.recorder.Count()
}

// Start begins listening.
func (p *Proxy) Start() error {
	ln, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: p}
	return srv.Serve(ln)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	conn, _, err := hij.Hijack()
	if err != nil {
		return
	}

	host := hostOnly(r.Host)
	cert, err := p.certFor(host)
	if err != nil {
		conn.Close()
		return
	}

	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{*cert}})
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return
	}

	// Serve requests on the TLS connection
	buf := &singleConnListener{conn: tlsConn}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w2 http.ResponseWriter, r2 *http.Request) {
			r2.URL.Scheme = "https"
			r2.URL.Host = r.Host
			p.proxyAndFuzz(w2, r2)
		}),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	srv.Serve(buf)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	p.proxyAndFuzz(w, r)
}

func (p *Proxy) proxyAndFuzz(w http.ResponseWriter, r *http.Request) {
	// Read body for replay
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
		r.Body.Close()
	}

	// Forward original
	outReq, _ := http.NewRequest(r.Method, r.URL.String(), bytes.NewReader(bodyBytes))
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}
	outReq.Header.Del("Proxy-Connection")

	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	// Record endpoint for recon spec (passive, always on)
	p.recorder.Record(r, bodyBytes, resp.StatusCode)

	// Write response back
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	// Background fuzz only for in-scope hosts. Recon mapping already happened
	// above for all traffic; active probing is gated to avoid hitting
	// out-of-scope third parties (CDNs, analytics, etc).
	if p.inScope(r.URL.Host) {
		go p.lightFuzz(r, bodyBytes, resp, respBody)
	}
}

// lightFuzz runs light active probes and passive checks.
func (p *Proxy) lightFuzz(r *http.Request, reqBody []byte, origResp *http.Response, respBody []byte) {
	targetURL := r.URL.String()
	var hdrs []string
	for k, vv := range r.Header {
		for _, v := range vv {
			hdrs = append(hdrs, k+": "+v)
		}
	}
	cookie := r.Header.Get("Cookie")

	// Passive checks on original response
	p.passiveChecks(targetURL, origResp, respBody)

	// Dedup key
	sig := r.Method + "|" + r.URL.Path + "|" + r.URL.RawQuery
	p.mu.Lock()
	if p.seen[sig] {
		p.mu.Unlock()
		return
	}
	p.seen[sig] = true
	p.mu.Unlock()

	// Parse injection points
	points, err := input.Parse(targetURL, r.Method, string(reqBody), hdrs, cookie)
	if err != nil || len(points) == 0 {
		return
	}

	// Light probes per point
	probes := []struct {
		payload string
		detect  func(string, int) *vulns.Finding
	}{
		{"'", func(body string, _ int) *vulns.Finding {
			sqliPatterns := []string{"SQL syntax", "mysql_", "ORA-", "SQLITE_ERROR", "PostgreSQL", "syntax error", "unterminated", "quoted string"}
			for _, pat := range sqliPatterns {
				if strings.Contains(body, pat) {
					return &vulns.Finding{Module: "sqli", Severity: "high", Confidence: "medium", Title: "SQL Error (proxy probe)", Evidence: pat, OWASP: "A03:2021 Injection", CWE: "CWE-89"}
				}
			}
			return nil
		}},
		{"ryofuzz<xss>canary", func(body string, _ int) *vulns.Finding {
			if strings.Contains(body, "ryofuzz<xss>canary") {
				return &vulns.Finding{Module: "xss", Severity: "high", Confidence: "medium", Title: "XSS Reflection (proxy probe)", Evidence: "canary reflected unencoded", OWASP: "A03:2021 Injection", CWE: "CWE-79"}
			}
			return nil
		}},
		{"{{7*7}}", func(body string, _ int) *vulns.Finding {
			if strings.Contains(body, "49") {
				return &vulns.Finding{Module: "ssti", Severity: "high", Confidence: "low", Title: "SSTI marker 7*7=49 (proxy probe)", Evidence: "49 in response", OWASP: "A03:2021 Injection", CWE: "CWE-1336"}
			}
			return nil
		}},
		{"../../../../../etc/passwd", func(body string, _ int) *vulns.Finding {
			if strings.Contains(body, "root:") && strings.Contains(body, "/bin/") {
				return &vulns.Finding{Module: "lfi", Severity: "critical", Confidence: "high", Title: "Path Traversal (proxy probe)", Evidence: "etc/passwd content", OWASP: "A01:2021 Broken Access Control", CWE: "CWE-22"}
			}
			return nil
		}},
	}

	for _, pt := range points {
		for _, probe := range probes {
			fuzzedURL, fuzzedBody := injectPayload(targetURL, string(reqBody), pt, probe.payload)
			req2, err := http.NewRequest(r.Method, fuzzedURL, strings.NewReader(fuzzedBody))
			if err != nil {
				continue
			}
			for k, vv := range r.Header {
				for _, v := range vv {
					req2.Header.Add(k, v)
				}
			}
			client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
			resp2, err := client.Do(req2)
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(resp2.Body)
			resp2.Body.Close()

			if f := probe.detect(string(b), resp2.StatusCode); f != nil {
				f.Payload = probe.payload
				f.Point = pt
				p.addFinding(f)
			}
		}
	}
}

func (p *Proxy) passiveChecks(targetURL string, resp *http.Response, body []byte) {
	// Missing security headers
	headers := map[string]string{
		"Content-Security-Policy": "Missing CSP header",
		"X-Frame-Options":        "Missing X-Frame-Options header",
		"Strict-Transport-Security": "Missing HSTS header",
	}
	for h, title := range headers {
		if resp.Header.Get(h) == "" {
			p.addFindingDedup("passive|"+targetURL+"|"+h, &vulns.Finding{
				Module: "passive", Severity: "info", Confidence: "confirmed",
				Title: title, Evidence: targetURL, OWASP: "A05:2021 Security Misconfiguration", CWE: "CWE-693",
			})
		}
	}

	// Cookie flags
	for _, c := range resp.Header.Values("Set-Cookie") {
		lower := strings.ToLower(c)
		if !strings.Contains(lower, "httponly") || !strings.Contains(lower, "secure") {
			p.addFindingDedup("passive|cookie|"+targetURL, &vulns.Finding{
				Module: "passive", Severity: "low", Confidence: "confirmed",
				Title: "Cookie missing HttpOnly/Secure flag", Evidence: c,
				OWASP: "A05:2021 Security Misconfiguration", CWE: "CWE-614",
			})
			break
		}
	}

	// Sensitive data patterns
	bodyStr := string(body)
	patterns := map[string]*regexp.Regexp{
		"JWT token leaked":     regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		"API key pattern":      regexp.MustCompile(`(?i)(api[_-]?key|apikey|api_secret)["\s:=]+["\s]*[A-Za-z0-9]{16,}`),
		"Stack trace exposed":  regexp.MustCompile(`(?i)(goroutine \d+|at \w+\.\w+\(|Traceback \(most recent|Exception in thread)`),
	}
	for title, re := range patterns {
		if m := re.FindString(bodyStr); m != "" {
			p.addFindingDedup("passive|"+title+"|"+targetURL, &vulns.Finding{
				Module: "passive", Severity: "medium", Confidence: "high",
				Title: title, Evidence: truncate(m, 80),
				OWASP: "A01:2021 Broken Access Control", CWE: "CWE-200",
			})
		}
	}
}

func (p *Proxy) addFinding(f *vulns.Finding) {
	p.mu.Lock()
	p.findings = append(p.findings, f)
	p.mu.Unlock()
	if p.OnFinding != nil {
		p.OnFinding(f)
	}
}

func (p *Proxy) addFindingDedup(key string, f *vulns.Finding) {
	p.mu.Lock()
	if p.seen[key] {
		p.mu.Unlock()
		return
	}
	p.seen[key] = true
	p.findings = append(p.findings, f)
	p.mu.Unlock()
	if p.OnFinding != nil {
		p.OnFinding(f)
	}
}

func (p *Proxy) certFor(host string) (*tls.Certificate, error) {
	p.certCacheMu.Lock()
	defer p.certCacheMu.Unlock()
	if c, ok := p.certCache[host]; ok {
		return c, nil
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
	p.certCache[host] = cert
	return cert, nil
}

// injectPayload replaces the original value of a point with a payload.
func injectPayload(rawURL, body string, pt input.InjectionPoint, payload string) (string, string) {
	switch pt.Location {
	case input.LocQueryParam:
		u, err := url.Parse(rawURL)
		if err != nil {
			return rawURL, body
		}
		q := u.Query()
		q.Set(pt.Name, payload)
		u.RawQuery = q.Encode()
		return u.String(), body
	case input.LocFormBody:
		vals, err := url.ParseQuery(body)
		if err != nil {
			return rawURL, body
		}
		vals.Set(pt.Name, payload)
		return rawURL, vals.Encode()
	case input.LocJSONBody:
		// Simple string replace for speed
		return rawURL, strings.Replace(body, pt.OriginalValue, payload, 1)
	case input.LocPath:
		return strings.Replace(rawURL, pt.OriginalValue, url.PathEscape(payload), 1), body
	case input.LocHeader, input.LocCookie:
		// Skip header/cookie injection in light mode for safety
		return rawURL, body
	}
	return rawURL, body
}

func hostOnly(h string) string {
	host, _, err := net.SplitHostPort(h)
	if err != nil {
		return h
	}
	return host
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// singleConnListener wraps a single net.Conn as a net.Listener.
type singleConnListener struct {
	conn net.Conn
	once sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	return nil, io.EOF
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
