# ryofuzz

Offensive web vulnerability fuzzer. Discovers unknown bugs through behavioral analysis, coverage-guided mutation, and intent mapping.

```
  ╔═══════════════════════════════════════════╗
  ║             ryofuzz v0.4.0                ║
  ║    Offensive Web Vulnerability Fuzzer     ║
  ║    github.com/renansj/ryofuzz             ║
  ╚═══════════════════════════════════════════╝
```

## What makes it different

Most scanners check for known vulnerabilities. ryofuzz discovers unknown ones.

- **Behavioral mode**: maps how the server processes input, then attacks the logic gaps
- **Guided mode**: AFL++-style coverage-guided evolutionary fuzzing for web
- **Smart mode**: type-aware payload generation with false positive filtering
- **Nuclei compatible**: runs 10,000+ community templates natively

## Installation

```bash
# go install
go install github.com/renansj/ryofuzz@latest

# Binary download (Linux)
curl -Lo ryofuzz https://github.com/renansj/ryofuzz/releases/latest/download/ryofuzz-linux-amd64
chmod +x ryofuzz && sudo mv ryofuzz /usr/local/bin/

# macOS Apple Silicon
curl -Lo ryofuzz https://github.com/renansj/ryofuzz/releases/latest/download/ryofuzz-darwin-arm64
chmod +x ryofuzz && sudo mv ryofuzz /usr/local/bin/

# From source
git clone https://github.com/renansj/ryofuzz.git && cd ryofuzz
go build -ldflags="-s -w" -o ryofuzz . && sudo mv ryofuzz /usr/local/bin/
```

Requires Go 1.22+.

## Modes

### Behavioral (intent mapping)

Maps server behavior first, then attacks based on what it learns. Sends ~120 structured probes to understand:
- What type of input the server expects (URL, path, ID, text, JSON)
- What the server does with it (fetch, reflect, execute, query database)
- Where validation boundaries are (which characters change behavior)
- Then targets the specific vulnerability class that matches

```bash
ryofuzz -u "http://target/api?url=http://example.com" --mode behavioral
ryofuzz -u "http://target/search?q=test" --mode behavioral
```

### Guided (AFL++ for web)

Coverage-guided evolutionary fuzzing. Keeps inputs that trigger new server behaviors, mutates those further. Gets smarter over time.

```bash
ryofuzz -u "http://target/api?id=1" --mode guided -n 10000 -c 50
ryofuzz -u "http://target/api" -d '{"user":"test"}' --mode guided -n 50000
```

### Smart (default)

Known payloads + type-aware smart generation + behavioral differential analysis. Good balance of speed and coverage.

```bash
ryofuzz -u "http://target/api?id=1&name=test" -t all -c 50
ryofuzz -u "http://target/api" -d '{"user":"admin","role":"viewer"}' -t sqli,ssti
```

### Payloads / Mutate

`payloads` = only known payloads, no mutations. `mutate` = radamsa-style random mutations only.

```bash
ryofuzz -u "http://target/search?q=test" --mode payloads -t xss
ryofuzz -u "http://target/api" -d '{"data":"test"}' --mode mutate -n 10000
```

## Vulnerability Modules (29)

| Module | What it tests |
|--------|---------------|
| `sqli` | SQL Injection (error, time, boolean, union, stacked, OOB) |
| `xss` | Cross-Site Scripting (context-aware: only confirms when executable in HTML) |
| `ssti` | Server-Side Template Injection (Jinja2, Twig, Freemarker, Thymeleaf, Mako, Pebble, Velocity, EJS, Pug, Handlebars, Smarty) |
| `ssrf` | Server-Side Request Forgery (AWS/GCP/Azure metadata, IP bypass, protocol smuggling) |
| `cmdi` | OS Command Injection (Linux/Windows, time-based, bypass) |
| `lfi` | Local File Inclusion (traversal, PHP wrappers, null byte, log poisoning) |
| `xxe` | XML External Entity (file read, blind OOB, SSRF via XXE) |
| `nosqli` | NoSQL Injection (MongoDB operators, JS injection) |
| `idor` | Insecure Direct Object Reference |
| `redirect` | Open Redirect |
| `crlf` | CRLF Injection / Response Splitting |
| `prototype` | Prototype Pollution (Node.js) |
| `jwt` | JWT Algorithm Confusion / alg:none / JWK injection |
| `mass-assign` | Mass Assignment / Parameter Pollution |
| `race` | Race Conditions |
| `smuggling` | HTTP Request Smuggling |
| `cors` | CORS Misconfiguration |
| `csp` | Content Security Policy analysis |
| `graphql` | GraphQL Introspection / Batching |
| `deser` | Insecure Deserialization (PHP, Python, Java, Node, .NET) |
| `ldapi` | LDAP Injection |
| `xpathi` | XPath Injection |
| `logic` | Business Logic Flaws (negative values, zero amounts) |
| `ratelimit` | Rate Limit bypass |
| `verb` | HTTP Verb Tampering |
| `hostheader` | Host Header Injection |
| `cache` | Web Cache Poisoning |
| `ws` | WebSocket Security |
| `prompt` | AI/LLM Prompt Injection |
| `cve` | CVE-aware targeted fuzzing (auto-detects framework from headers) |

## Features

### Auto-detection of injection points

Automatically finds all fuzzable parameters:
- URL query params
- Path segments (numeric, UUID, hex)
- JSON body (nested fields)
- URL-encoded form body
- HTTP headers
- Cookies

### Smart payload generation

Type-aware mutations based on detected value type:
- Integer: boundary values, overflow, type confusion
- Float: IEEE 754 edge cases, precision
- String: length variations, unicode, format strings
- URL: internal IPs, metadata, protocol smuggling, bypass patterns
- Email: header injection, domain tricks
- UUID: enumeration, format confusion
- JSON: nesting, prototype pollution, duplicate keys

### False positive filtering

Context-aware filtering eliminates noise:
- Checks Content-Type before claiming XSS (only HTML is executable)
- Detects when server just echoes payload in error messages
- Verifies HTML context for reflection (body vs attribute vs script vs safe)
- Filters CVE probe errors that are just URL parse failures
- Suppresses 500 floods when >20% responses are errors

### CVE-aware probing

Fingerprints the server via response headers, then generates targeted fuzzing:
- Apache: path traversal bypasses (CVE-2021-41773 style)
- Nginx: alias traversal, off-by-slash
- Express/Node.js: prototype pollution chains
- Spring/Java: SpEL injection, Spring4Shell patterns
- Next.js: middleware bypass (CVE-2025-29927)
- Django/Flask: debug pages, SSTI
- Laravel: Ignition RCE patterns
- ASP.NET: ViewState, padding oracle
- Tomcat: Ghostcat, manager paths

### OOB callback server

Built-in out-of-band listener for blind vulnerability confirmation:

```bash
# Local (your IP is reachable from target)
ryofuzz -u "http://target/api" -t ssrf --oob 10.10.14.5 --oob-listen 8888 --oob-mode private

# Via ngrok
ryofuzz -u "http://target/api" -t ssrf --oob auto --oob-mode ngrok

# CTF (private network)
ryofuzz -u "http://10.10.10.50/api?file=x" -t ssrf --oob 10.10.14.5:8888 --oob-mode private
```

### Web crawler

Discovers endpoints before fuzzing:

```bash
ryofuzz -u "http://target" --crawl --crawl-depth 3 -t all
```

Extracts: links, forms, API routes from JavaScript, sitemap.xml, robots.txt.

### Authentication

```bash
# Bearer token
ryofuzz -u "http://target/api" -t all --auth bearer --auth-token "eyJ..."

# Form login (auto-extracts token)
ryofuzz -u "http://target/admin" -t all \
  --auth form --auth-url "http://target/login" \
  --auth-body '{"email":"user@test.com","password":"pass"}' --auth-field "token"

# Basic auth
ryofuzz -u "http://target/api" -t all --auth basic --auth-user admin --auth-pass secret

# API key
ryofuzz -u "http://target/api" -t all --auth custom --auth-token "sk-xxx" --auth-header "X-API-Key"
```

Auto-refreshes when session expires (detects 401/403).

### Nuclei template compatibility

Runs nuclei community templates natively. 10,000+ templates for known CVEs.

```bash
# Setup (once)
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates

# Run CVE templates + fuzzing together
ryofuzz -u "http://target" -t all --nuclei-templates ~/nuclei-templates/http/cves/

# Filter by severity
ryofuzz -u "http://target" -t all --nuclei-templates ~/nuclei-templates/http/ --nuclei-severity critical,high

# Filter by tags
ryofuzz -u "http://target" -t all --nuclei-templates ~/nuclei-templates/http/ --nuclei-tags rce,ssrf,lfi
```

### Plugin system

Extend with custom YAML checks:

```yaml
# ~/.ryofuzz/plugins/custom-check.yaml
name: custom-waf-bypass
severity: critical
module: sqli-custom
owasp: "A03:2021 Injection"
cwe: CWE-89
payloads:
  - value: "' /*!50000OR*/ 1=1-- -"
    variant: mysql-versioned-comment
detection:
  method: contains
  patterns:
    - "syntax error"
    - "mysql"
```

```bash
ryofuzz -u "http://target" --plugins-dir ./my-plugins -t all
```

### Output formats

```bash
# Terminal (colored, default)
ryofuzz -u "http://target" -t all

# JSON (for pipelines)
ryofuzz -u "http://target" -t all --format json -o results.json

# Markdown
ryofuzz -u "http://target" -t all --format markdown -o report.md

# HTML (self-contained dark theme with SVG charts)
ryofuzz -u "http://target" -t all --format html -o report.html
```

### Proxy support

Route traffic through Burp Suite or ZAP:

```bash
ryofuzz -u "http://target/api?id=1" -t all --proxy http://127.0.0.1:8080
```

## Full CLI reference

```
ryofuzz [flags]
ryofuzz version

Target:
  -u, --url string           Target URL (required)
  -X, --method string        HTTP method (auto-detected)
  -d, --data string          Request body (JSON or URL-encoded)
  -H, --header strings       Custom headers (repeatable)
  -b, --cookie string        Cookies

Fuzzing:
  -t, --tests string         Modules: all, sqli, xss, ssti, ssrf, ... (default "all")
      --mode string          Mode: smart, payloads, mutate, guided, behavioral (default "smart")
  -n, --mutations int        Payload count for guided/mutate mode (default auto)
  -c, --concurrency int      Concurrent workers (default 20)
      --timeout int          Request timeout in seconds (default 15)
      --delay int            Delay between requests in ms
      --rate int             Max requests/second (0=unlimited)
      --follow               Follow redirects

Output:
  -o, --output string        Output file
      --format string        text, json, markdown, html (default "text")
  -v, --verbose              Verbose output

Auth:
      --auth string          Method: basic, bearer, form, cookie, custom
      --auth-user string     Username
      --auth-pass string     Password
      --auth-token string    Token/API key
      --auth-url string      Login URL (for form auth)
      --auth-body string     Login body (for form auth)
      --auth-field string    Token field in login response
      --auth-header string   Header name for token (default "Authorization")
      --auth-prefix string   Token prefix (default "Bearer")

Discovery:
      --crawl                Crawl before fuzzing
      --crawl-depth int      Max depth (default 3)
      --ignore-robots        Ignore robots.txt

OOB:
      --oob string           OOB domain/IP
      --oob-listen int       Listener port (default 8888)
      --oob-mode string      local, ngrok, private (default "local")

Nuclei:
      --nuclei-templates string   Path to nuclei-templates directory
      --nuclei-tags string        Filter by tags (comma-separated)
      --nuclei-severity string    Filter by severity (default "critical,high")

Plugins:
      --plugins-dir string   Custom plugins directory

Other:
      --proxy string         HTTP proxy (e.g., http://127.0.0.1:8080)
```

## Architecture

```
ryofuzz/
├── cmd/root.go                  # CLI orchestration
├── internal/
│   ├── behavioral/engine.go     # Behavioral intent mapping (Phase 1-2-3)
│   ├── fuzzer/guided.go         # Coverage-guided evolutionary fuzzer
│   ├── input/parser.go          # Injection point auto-detection
│   ├── engine/engine.go         # Concurrent request engine
│   ├── mutator/                 # Radamsa-style + smart type-aware mutations
│   ├── payloads/database.go     # 740+ embedded payloads
│   ├── vulns/                   # 29 vulnerability modules + CVE probe
│   ├── analyzer/                # Behavioral clustering + FP filter
│   ├── nuclei/runner.go         # Nuclei template executor
│   ├── reporter/                # text, json, markdown, html output
│   ├── oob/                     # OOB callback server
│   ├── auth/                    # Authentication manager
│   ├── crawler/                 # Web spider + JS parser
│   └── plugins/                 # YAML plugin loader
└── plugins/                     # Example custom checks
```

## Examples

```bash
# Full scan with all modules
ryofuzz -u "http://target/api?id=1&name=test" -t all -c 50

# Understand server behavior first (recommended for research)
ryofuzz -u "http://target/endpoint?param=value" --mode behavioral

# Deep fuzzing for 0-day discovery
ryofuzz -u "http://target/api?id=1" --mode guided -n 50000 -c 100

# JSON API with auth
ryofuzz -u "http://target/api/users" -d '{"search":"test"}' \
  -t sqli,ssti,nosqli --auth bearer --auth-token "eyJ..."

# Crawl + fuzz + nuclei + HTML report
ryofuzz -u "http://target" --crawl -t all \
  --nuclei-templates ~/nuclei-templates/http/cves/ \
  --format html -o report.html

# Blind SSRF with OOB callbacks
ryofuzz -u "http://target/webhook" -d '{"url":"http://x.com"}' \
  -t ssrf --oob 10.10.14.5 --oob-mode private

# Through Burp proxy
ryofuzz -u "http://target/api?q=test" -t all --proxy http://127.0.0.1:8080
```

## Disclaimer

For authorized security testing and CTF challenges only. Do not use against systems without explicit permission.

## Author

RyoSec - Renan Zapelini

## License

MIT
