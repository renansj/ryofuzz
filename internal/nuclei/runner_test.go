package nuclei

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// loadInline parses a template from an inline YAML string.
func loadInline(t *testing.T, src string) *Template {
	t.Helper()
	var tmpl Template
	if err := yaml.Unmarshal([]byte(src), &tmpl); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &tmpl
}

func TestNuclei_WordMatcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.49")
		w.Write([]byte("Hello vulnerable world"))
	}))
	defer srv.Close()

	tmpl := loadInline(t, `
id: word-test
info:
  name: word test
  severity: high
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "vulnerable"
`)
	res := Execute(tmpl, srv.URL, 5, "")
	if !res.Matched {
		t.Fatal("expected word match")
	}
}

func TestNuclei_StatusAndHeaderPart(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.WriteHeader(500)
	}))
	defer srv.Close()

	tmpl := loadInline(t, `
id: status-header
info: {name: sh, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers-condition: and
    matchers:
      - type: status
        status: [500]
      - type: word
        part: header
        words: ["PHP/7.4"]
`)
	res := Execute(tmpl, srv.URL, 5, "")
	if !res.Matched {
		t.Fatal("expected status+header match")
	}
}

func TestNuclei_SizeAndNegative(t *testing.T) {
	body := "0123456789" // 10 bytes
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	tmpl := loadInline(t, `
id: size-test
info: {name: size, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: size
        size: [10]
`)
	if !Execute(tmpl, srv.URL, 5, "").Matched {
		t.Fatal("expected size match")
	}
}

func TestNuclei_DSLMatcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("admin panel login"))
	}))
	defer srv.Close()

	tmpl := loadInline(t, `
id: dsl-test
info: {name: dsl, severity: high}
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200 && contains(body, 'admin')"
`)
	res := Execute(tmpl, srv.URL, 5, "")
	if !res.Matched {
		t.Fatal("expected dsl match")
	}
}

func TestNuclei_DSLInterpolation(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tmpl := loadInline(t, `
id: interp
info: {name: interp, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/{{to_lower('ADMIN')}}"]
    matchers:
      - type: word
        words: ["ok"]
`)
	Execute(tmpl, srv.URL, 5, "")
	if gotPath != "/admin" {
		t.Fatalf("expected DSL interpolation to /admin, got %q", gotPath)
	}
}

func TestNuclei_Extractor_MultiStep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Write([]byte(`{"csrf":"SECRET123"}`))
			return
		}
		// second step should carry the extracted token
		if r.URL.Query().Get("t") == "SECRET123" {
			w.Write([]byte("authorized"))
			return
		}
		w.Write([]byte("denied"))
	}))
	defer srv.Close()

	tmpl := loadInline(t, `
id: multistep
info: {name: ms, severity: high}
http:
  - method: GET
    path:
      - "{{BaseURL}}/token"
    extractors:
      - type: json
        name: tok
        internal: true
        json:
          - ".csrf"
  - method: GET
    path:
      - "{{BaseURL}}/check?t={{tok}}"
    matchers:
      - type: word
        words: ["authorized"]
`)
	res := Execute(tmpl, srv.URL, 5, "")
	if !res.Matched {
		t.Fatalf("expected multi-step extractor match; vars=%v", res.ExtractedVars)
	}
}

func TestNuclei_RawRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.Contains(r.Header.Get("X-Custom"), "ryo") {
			w.Write([]byte("raw matched"))
			return
		}
		w.Write([]byte("no"))
	}))
	defer srv.Close()

	tmpl := loadInline(t, `
id: raw-test
info: {name: raw, severity: high}
http:
  - raw:
      - |
        POST /submit HTTP/1.1
        Host: {{Hostname}}
        X-Custom: ryotest

        data=1
    matchers:
      - type: word
        words: ["raw matched"]
`)
	res := Execute(tmpl, srv.URL, 5, "")
	if !res.Matched {
		t.Fatal("expected raw request match")
	}
}

func TestNuclei_CapabilitySkipsUnsupported(t *testing.T) {
	tmpl := loadInline(t, `
id: js-test
info: {name: js, severity: info}
javascript:
  - code: "log('x')"
`)
	res := Execute(tmpl, "http://example.com", 5, "")
	if !res.Skipped {
		t.Fatal("expected javascript template to be skipped")
	}
}

func TestNuclei_ClassificationParsing(t *testing.T) {
	tmpl := loadInline(t, `
id: cve-test
info:
  name: cve
  severity: critical
  tags: [cve, rce]
  classification:
    cve-id: CVE-2021-44228
    cwe-id: CWE-502
    cvss-score: 10.0
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: status
        status: [200]
`)
	if len(tmpl.Info.Tags) != 2 {
		t.Fatalf("expected 2 tags, got %v", tmpl.Info.Tags)
	}
	if len(tmpl.Info.Classification.CVEID) == 0 || tmpl.Info.Classification.CVEID[0] != "CVE-2021-44228" {
		t.Fatalf("cve parse failed: %v", tmpl.Info.Classification.CVEID)
	}
	if tmpl.Info.Classification.CVSSScore != 10.0 {
		t.Fatalf("cvss parse failed: %v", tmpl.Info.Classification.CVSSScore)
	}
}

func TestNuclei_TagsStringForm(t *testing.T) {
	tmpl := loadInline(t, `
id: tags-string
info:
  name: t
  severity: info
  tags: "cve,rce,oast"
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: status
        status: [200]
`)
	if len(tmpl.Info.Tags) != 3 {
		t.Fatalf("expected 3 tags from string form, got %v", tmpl.Info.Tags)
	}
}

func TestNuclei_RequestsAlias(t *testing.T) {
	tmpl := loadInline(t, `
id: legacy
info: {name: legacy, severity: info}
requests:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: status
        status: [200]
`)
	if len(tmpl.AllRequests()) != 1 {
		t.Fatal("expected requests: alias to work")
	}
}
