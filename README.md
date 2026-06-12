# ryofuzz

Offensive multi-class web vulnerability fuzzer. Automatically detects injection points, tests for 29+ vulnerability classes, and performs behavioral differential analysis to identify security issues.

```
  ╔═══════════════════════════════════════════╗
  ║             ryofuzz v0.1.0                ║
  ║    Offensive Web Vulnerability Fuzzer     ║
  ║    github.com/renansj/ryofuzz             ║
  ╚═══════════════════════════════════════════╝
```

## Features

- **Auto-detection of injection points** - URL query params, path segments, JSON body (nested), URL-encoded body, headers, cookies
- **29 vulnerability modules** - OWASP Top 10, API Security Top 10, LLM Top 10, and underground techniques
- **Radamsa-style mutation engine** - 12 mutation strategies + encoding variants for WAF bypass
- **Embedded payload database** - 740+ payloads from PayloadsAllTheThings, organized by category
- **Behavioral differential analysis** - Compares fuzzed responses against baseline (status, body length, timing, reflection, error patterns)
- **OOB callback server** - Built-in out-of-band listener supporting local, ngrok, and private/CTF networks
- **Web crawler** - Discovers endpoints via spidering, form parsing, JavaScript analysis, sitemap/robots.txt
- **Authentication** - Supports basic, bearer, form login, cookie, and custom header auth with auto-refresh
- **Plugin system** - Extend with custom YAML-based checks
- **Multiple output formats** - Terminal (colored), JSON, Markdown, HTML (self-contained dark theme with SVG charts)
- **Proxy support** - Route traffic through Burp Suite or ZAP for inspection
- **Single binary** - ~10MB, zero runtime dependencies

## Installation

### go install

```bash
go install github.com/renansj/ryofuzz@latest
```

### Download binary

```bash
# Linux amd64
curl -Lo ryofuzz https://github.com/renansj/ryofuzz/releases/latest/download/ryofuzz-linux-amd64
chmod +x ryofuzz && sudo mv ryofuzz /usr/local/bin/

# macOS Apple Silicon
curl -Lo ryofuzz https://github.com/renansj/ryofuzz/releases/latest/download/ryofuzz-darwin-arm64
chmod +x ryofuzz && sudo mv ryofuzz /usr/local/bin/
```

### From source

```bash
git clone https://github.com/renansj/ryofuzz.git
cd ryofuzz
go build -ldflags="-s -w" -o ryofuzz .
sudo mv ryofuzz /usr/local/bin/
```

### Requirements

- Go 1.22+ (for go install / from source)

## Quick Start

```bash
# Fuzz all vulnerability classes
ryofuzz -u "http://target/api?id=1&name=test" -t all

# JSON body
ryofuzz -u "http://target/api" -d '{"user":"admin","role":"viewer","id":1}' -t sqli,ssti,nosqli

# URL-encoded body
ryofuzz -u "http://target/login" -X POST -d "username=admin&password=test" -t sqli,xss

# Specific modules only
ryofuzz -u "http://target/search?q=test" -t xss,ssti,cmdi
```

## Usage

```
ryofuzz [flags]

Flags:
  -u, --url string           Target URL (required)
  -X, --method string        HTTP method (auto-detected if not provided)
  -d, --data string          Request body (JSON or URL-encoded)
  -H, --header strings       Custom headers (repeatable)
  -b, --cookie string        Cookies
  -t, --tests string         Test modules: all, sqli, xss, ssti, ... (default "all")
  -c, --concurrency int      Concurrent goroutines (default 20)
  -v, --verbose              Verbose output
  -o, --output string        Output file
      --format string        Format: text, json, markdown, html (default "text")
      --proxy string         Proxy (e.g., http://127.0.0.1:8080)
      --timeout int          Timeout per request in seconds (default 15)
      --delay int            Delay between requests in ms
      --rate int             Rate limit (requests/second, 0=unlimited)
      --mode string          Mode: smart, payloads, mutate (default "smart")
  -n, --mutations int        Number of radamsa-style mutations (0=auto)
      --follow               Follow redirects

Authentication:
      --auth string          Auth method: basic, bearer, form, cookie, custom
      --auth-user string     Username
      --auth-pass string     Password
      --auth-token string    Token/API key
      --auth-url string      Login URL (for auth=form)
      --auth-body string     Login body (for auth=form)
      --auth-field string    Token field in login response (default "token")
      --auth-header string   Header to send token (default "Authorization")
      --auth-prefix string   Token prefix (default "Bearer")

Crawler:
      --crawl                Discover endpoints before fuzzing
      --crawl-depth int      Max crawl depth (default 3)
      --ignore-robots        Ignore robots.txt

OOB Callbacks:
      --oob string           OOB domain/IP for callbacks
      --oob-listen int       OOB listener port (default 8888)
      --oob-mode string      OOB mode: local, ngrok, private (default "local")

Plugins:
      --plugins-dir string   Custom plugins directory
```

## Vulnerability Modules

### OWASP Top 10 (2021)

| Module | Class | Detection |
|--------|-------|-----------|
| `sqli` | SQL Injection | Error-based, time-based, boolean-based, union, stacked, OOB |
| `xss` | Cross-Site Scripting | Reflection detection, DOM vectors, polyglots, WAF bypass |
| `ssti` | Server-Side Template Injection | Jinja2, Twig, Freemarker, Thymeleaf, Mako, Pebble, Velocity, EJS, Pug, Handlebars, Smarty |
| `ssrf` | Server-Side Request Forgery | AWS/GCP/Azure metadata, localhost bypass, protocol smuggling |
| `cmdi` | OS Command Injection | Linux/Windows, time-based, wildcard/IFS bypass |
| `lfi` | Local File Inclusion | Path traversal, PHP wrappers, log poisoning, null byte |
| `xxe` | XML External Entity | File read, SSRF via XXE, blind/OOB |
| `deser` | Insecure Deserialization | PHP, Python pickle, Java, Node.js, .NET |
| `cors` | CORS Misconfiguration | Origin reflection, null origin, credential leaks |
| `csp` | CSP Analysis | Weak directives, bypass vectors |

### OWASP API Security Top 10 (2023)

| Module | Class |
|--------|-------|
| `idor` | Broken Object Level Authorization |
| `mass-assign` | Broken Object Property Level Authorization |
| `ratelimit` | Unrestricted Resource Consumption |
| `graphql` | Introspection, batching, alias enumeration |
| `logic` | Business logic flaws (negative values, zero amounts) |

### OWASP LLM Top 10 (2025)

| Module | Class |
|--------|-------|
| `prompt` | Prompt Injection (direct, indirect, jailbreak, system prompt leak) |

### Advanced / Underground

| Module | Class |
|--------|-------|
| `prototype` | Prototype Pollution (Node.js __proto__, constructor) |
| `jwt` | JWT Algorithm Confusion, alg:none, JWK injection |
| `smuggling` | HTTP Request Smuggling (CL/TE desync) |
| `cache` | Web Cache Poisoning (unkeyed headers) |
| `hostheader` | Host Header Injection (password reset poisoning) |
| `crlf` | CRLF Injection / Response Splitting |
| `redirect` | Open Redirect |
| `nosqli` | NoSQL Injection (MongoDB operators) |
| `ldapi` | LDAP Injection |
| `xpathi` | XPath Injection |
| `verb` | HTTP Verb Tampering |
| `race` | Race Conditions |

## Advanced Usage

### Crawl + Fuzz

```bash
ryofuzz -u "http://target" --crawl --crawl-depth 3 -t all -c 50
```

### With Authentication

```bash
# Bearer token
ryofuzz -u "http://target/api/users" -t idor,sqli --auth bearer --auth-token "eyJ..."

# Form login (auto-extracts token from response)
ryofuzz -u "http://target/admin/api" -t all \
  --auth form \
  --auth-url "http://target/api/login" \
  --auth-body '{"email":"user@test.com","password":"pass123"}' \
  --auth-field "access_token"

# Basic auth
ryofuzz -u "http://target/api" -t all --auth basic --auth-user admin --auth-pass secret

# Custom API key header
ryofuzz -u "http://target/api" -t all --auth custom --auth-token "sk-xxxx" --auth-header "X-API-Key"
```

### OOB Callbacks (Blind SSRF, XXE, CMDi)

```bash
# Local listener (your machine is reachable from target)
ryofuzz -u "http://target/api?url=x" -t ssrf,xxe --oob 10.10.14.5 --oob-listen 8888 --oob-mode private

# Via ngrok (start ngrok separately: ngrok http 8888)
ryofuzz -u "http://target/api" -t ssrf --oob auto --oob-mode ngrok

# Private network (CTF)
ryofuzz -u "http://10.10.10.50/api?file=x" -t ssrf,lfi --oob 10.10.14.5:8888 --oob-mode private
```

### HTML Report

```bash
ryofuzz -u "http://target/api?id=1" -t all --format html -o report.html
```

### With Burp Suite Proxy

```bash
ryofuzz -u "http://target/api" -d '{"q":"test"}' -t all --proxy http://127.0.0.1:8080
```

### Mutation-Only Mode (0-day Research)

```bash
# Pure radamsa-style mutations (no known payloads, fuzz for parser bugs)
ryofuzz -u "http://target/api" -d '{"data":"test"}' --mode mutate -n 10000
```

## Plugin System

Create custom checks as YAML files in `~/.ryofuzz/plugins/` or `./plugins/`:

```yaml
name: custom-waf-bypass
description: Custom SQLi bypass for specific WAF
author: your-handle
severity: critical
module: sqli-custom
owasp: "A03:2021 Injection"
cwe: CWE-89
payloads:
  - value: "' /*!50000OR*/ 1=1-- -"
    variant: mysql-versioned-comment
  - value: "' %55NION %53ELECT 1,2,3-- -"
    variant: hex-keywords
detection:
  method: contains
  patterns:
    - "syntax error"
    - "mysql"
    - "warning"
```

Load custom plugins:

```bash
ryofuzz -u "http://target" --plugins-dir ./my-plugins -t all
```

## Nuclei Template Compatibility

ryofuzz can run [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) natively. This gives you access to 10,000+ community templates for known CVEs, misconfigurations, and exposures.

### Setup

```bash
# Clone nuclei-templates
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates
```

### Usage

```bash
# Run all critical/high CVE templates
ryofuzz -u "http://target" -t all --nuclei-templates ~/nuclei-templates/http/cves/

# Filter by tags
ryofuzz -u "http://target" -t all --nuclei-templates ~/nuclei-templates/http/ --nuclei-tags rce,sqli

# Misconfigurations only
ryofuzz -u "http://target" -t all --nuclei-templates ~/nuclei-templates/http/misconfiguration/

# Combined: nuclei templates + ryofuzz fuzzing
ryofuzz -u "http://target/api?id=1" -t all --nuclei-templates ~/nuclei-templates/http/cves/ --mode smart
```

### Why use nuclei templates through ryofuzz?

- **Single tool** - no need to install nuclei separately
- **Combined results** - nuclei findings + fuzzing findings in one report
- **Fuzz around CVEs** - ryofuzz tests the endpoint for unknown bugs while nuclei checks for known ones

### Supported template features

- HTTP requests (GET, POST, PUT, etc.)
- Word matchers (body, header)
- Regex matchers
- Status code matchers
- Matchers condition (AND/OR)
- Negative matchers
- Multiple paths per template
- {{BaseURL}} / {{RootURL}} variables

## Architecture

```
ryofuzz/
├── main.go
├── cmd/root.go                  # CLI and orchestration
├── internal/
│   ├── input/parser.go          # Auto-detection of injection points
│   ├── engine/engine.go         # Concurrent request engine
│   ├── fuzzer/guided.go         # Coverage-guided evolutionary fuzzer (AFL++ style)
│   ├── mutator/                 # Radamsa-style mutations + smart type-aware generation
│   ├── payloads/database.go     # Embedded payload database (740+)
│   ├── vulns/                   # 29 vulnerability modules
│   ├── analyzer/                # Behavioral analysis + FP filter
│   ├── nuclei/runner.go         # Nuclei template parser and executor
│   ├── reporter/                # Output: text, json, markdown, html
│   ├── oob/                     # OOB callback server (local/ngrok/private)
│   ├── auth/                    # Authentication management
│   ├── crawler/                 # Web crawler + JS parser
│   └── plugins/                 # YAML plugin system
└── plugins/                     # Example plugins
```

## How It Works

1. **Parse** - Detects all injection points (query params, JSON fields, form params, path segments, headers, cookies)
2. **Baseline** - Sends the original request and captures the response as reference
3. **Generate** - Creates payloads from the embedded database + radamsa-style mutations + encoding variants
4. **Fuzz** - Sends all payloads concurrently with configurable rate limiting
5. **Analyze** - Compares each response against baseline (status code, body length, timing, reflection, error patterns)
6. **Report** - Outputs findings with confidence scoring, evidence, and OWASP/CWE classification

## Detection Methods

- **Error-based** - SQL errors, template errors, stack traces in response
- **Time-based** - Response time delta > 4.5s with sleep payloads
- **Boolean-based** - Body length differential between true/false conditions
- **Reflection** - Payload (or dangerous characters) appear in response body
- **Status differential** - Response status differs from baseline
- **Header analysis** - CORS headers, CSP, injected headers
- **OOB callbacks** - External interaction confirms blind vulnerabilities

## Disclaimer

This tool is intended for **authorized security testing** and **CTF challenges** only. Only use against systems you have explicit permission to test. Unauthorized access to computer systems is illegal.

## Author

**RyoSec** - Offensive Security Consulting

## License

MIT
