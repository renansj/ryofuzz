# ryofuzz

Offensive web vulnerability fuzzer. Discovers unknown bugs through behavioral analysis, coverage-guided mutation, intent mapping, and live proxy interception.

```
  ╔═══════════════════════════════════════════╗
  ║             ryofuzz v1.0.0                ║
  ║    Offensive Web Vulnerability Fuzzer     ║
  ║    github.com/renansj/ryofuzz             ║
  ╚═══════════════════════════════════════════╝
```

## What makes it different

Most scanners check for known vulnerabilities. ryofuzz discovers unknown ones.

- **Behavioral mode**: maps how the server processes input, then attacks the logic gaps
- **Guided mode**: AFL++-style coverage-guided evolutionary fuzzing for web
- **Smart mode**: type-aware payload generation with false positive filtering
- **Live proxy mode**: Burp-style MITM intercept that fuzzes endpoints as you browse
- **Nuclei compatible**: runs 10,000+ community templates natively

Plus capabilities no other open source tool combines in one CLI:
- Canary propagation for stored/second-order injection detection
- Differential authorization testing (auto IDOR/privesc detection)
- Stateful workflow fuzzing for business logic flaws
- Single-packet HTTP/2 race attacks
- Headless browser DOM XSS
- Chain detection that correlates findings into critical attack paths
- OOB callbacks via HTTP and DNS
- Optional LLM-assisted payload generation and triage

## What is new in v1.0.0

| Capability | Flag | Description |
|-----------|------|-------------|
| Live proxy fuzzing | `--proxy-mode` | MITM proxy: browse normally, ryofuzz fuzzes in background |
| Headless browser | `--browser` | Real DOM XSS detection via chromedp |
| Single-packet race | `--race-singlepacket N` | HTTP/2 synchronized burst for TOCTOU bugs |
| Stateful workflows | `--workflow file.yaml` | Multi-step logic flaw fuzzing |
| DNS OOB | `--oob-dns 53` | Capture blind SSRF/XXE via DNS resolution |
| WAF evasion | `--waf-evade` | Adaptive encoding chains on 403/406 blocks |
| LLM assist | `--llm ollama:llama3` | Payload generation + false positive triage |
| Canary taint | `--taint-scan` | Stored/second-order injection detection |
| Differential authz | `--mode authz` | Auto IDOR/broken-auth/privesc |
| OpenAPI import | `--openapi URL` | Auto-discover endpoints from spec |
| SARIF output | `--format sarif` | GitHub Security tab integration |

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

Requires Go 1.22+. Headless browser mode requires Chromium installed.

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

### Live Proxy (Burp-style intercept)

Starts a MITM proxy. Point your browser at it and browse normally. Every request that passes through is fuzzed lightly in the background, and passive checks run on every response. Findings stream live as you navigate.

```bash
# Start the proxy (default port 8081)
ryofuzz --proxy-mode

# Custom port and CA export path
ryofuzz --proxy-mode --proxy-port 8888 --proxy-ca /tmp/ryofuzz-ca.pem
```

Setup:
1. Run the command above. It generates a CA certificate (`ryofuzz-ca.pem`).
2. Set your browser HTTP/HTTPS proxy to `127.0.0.1:8081`.
3. Install `ryofuzz-ca.pem` as a trusted CA in your browser or OS (needed for HTTPS interception).
4. Browse the target application normally.

What it does per request:
- Forwards transparently so the page loads normally
- Light active probes per injection point (single quote for SQLi, canary for XSS, 7*7 for SSTI, traversal for LFI)
- Passive checks: missing security headers (CSP, HSTS, X-Frame-Options), insecure cookie flags, leaked secrets (API keys, JWTs, stack traces)
- Deduplicates by endpoint+param so the same thing is not re-fuzzed

Press Ctrl+C to stop. A full findings summary prints on exit.

## Vulnerability Modules (38)

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
| `cache-deception` | Web Cache Deception (path suffix tricks to cache authenticated pages) |
| `oauth` | OAuth/OIDC flow attacks (redirect_uri bypass, state missing, PKCE downgrade) |
| `upload` | File upload bypass (extension tricks, polyglot, SVG XSS, null bytes) |
| `pwreset` | Password reset poisoning (Host header injection in reset emails) |
| `hpp` | HTTP Parameter Pollution (duplicate params, array injection) |
| `csv` | CSV/Formula Injection (DDE, formula injection via =, +, -, @) |
| `email-inj` | Email Header Injection (CRLF in email fields, BCC injection) |
| `xssi` | Cross-Site Script Inclusion (JSONP data leak, callback injection) |
| `el` | Expression Language Injection (SpEL, OGNL, MVEL, JEXL, JSP EL) |

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
      --mode string          Mode: smart, payloads, mutate, guided, behavioral, authz (default "smart")
  -n, --mutations int        Payload count for guided/mutate mode (default auto)
  -c, --concurrency int      Concurrent workers (default 20)
      --timeout int          Request timeout in seconds (default 15)
      --delay int            Delay between requests in ms
      --rate int             Max requests/second (0=unlimited)
      --follow               Follow redirects

Output:
  -o, --output string        Output file
      --format string        text, json, markdown, html, sarif (default "text")
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
      --oob string           OOB domain/IP:port for callbacks (e.g., 10.10.14.5:8888)
      --oob-listen int       Listener port (default 8888)
      --oob-mode string      local, ngrok, private (default "local")
      --oob-wait int         Seconds to wait for OOB callbacks (default 3)

Nuclei:
      --nuclei-templates string   Path to nuclei-templates directory
      --nuclei-tags string        Filter by tags (comma-separated)
      --nuclei-severity string    Filter by severity (default "critical,high")

Advanced:
      --openapi string             URL to OpenAPI/Swagger spec for endpoint discovery
      --taint-scan                 Enable canary propagation for stored/second-order detection
      --authz-identities strings   Identities for authz testing (name:header:value, repeatable)
      --log-file string            Request/response JSONL log path (default ".ryofuzz-log.jsonl")
      --workflow string            Path to workflow YAML for stateful fuzzing
      --race-singlepacket int      Single-packet race attack parallel requests (0=disabled)
      --browser                    Enable headless browser DOM XSS scanning
      --waf-evade                  Adaptive WAF evasion: retry blocked payloads with encoding chains

Live Proxy:
      --proxy-mode               Start in live proxy fuzzing mode (MITM intercept + scan)
      --proxy-port int           Proxy listen port (default 8081)
      --proxy-ca string          Path to export CA cert for browser trust (default "ryofuzz-ca.pem")

DNS OOB:
      --oob-dns int          UDP port for DNS OOB listener (0=disabled)

LLM:
      --llm string           LLM provider spec (e.g. ollama:llama3)
      --llm-payloads         Use LLM to generate additional payloads
      --llm-triage           Use LLM to triage findings (filter false positives)

Plugins:
      --plugins-dir string   Custom plugins directory

Other:
      --proxy string         HTTP proxy for outbound traffic (e.g., http://127.0.0.1:8080)
```

## Detection quality

### Confirmation loops (false positive reduction)

Time-based findings are automatically re-sent twice:
1. Same payload to confirm the delay reproduces
2. No-sleep variant (sleep(0)) to rule out network latency

If the delay does not reproduce, the finding is discarded silently.

Boolean-based SQLi findings are confirmed by sending the complementary payload (e.g., `OR 1=2` after `OR 1=1`). If both responses are identical, it is not a real boolean oracle and the finding is discarded.

### Coverage-guided corpus persistence

In guided mode, the evolved corpus is saved to `.ryofuzz-corpus.json` at scan completion and reloaded automatically on next run. This enables incremental fuzzing across sessions.

```bash
# First run: explores from scratch
ryofuzz -u "http://target/api?id=1" --mode guided -n 10000

# Second run: resumes from previous corpus
ryofuzz -u "http://target/api?id=1" --mode guided -n 50000
```

### OOB callbacks for blind detection

Built-in HTTP listener with token correlation for blind SSRF, XXE, and RFI:

```bash
ryofuzz -u "http://target/webhook" -d '{"url":"http://x.com"}' \
  -t ssrf --oob 10.10.14.5:8888 --oob-listen 8888 --oob-mode private --oob-wait 10
```

The server generates unique tokens per payload. When the target makes an outbound request to the listener, the callback is correlated with the exact payload that triggered it, producing a confirmed critical finding.

### Chain detection

Post-scan, ryofuzz correlates findings to detect attack chains with elevated severity:
- SSRF + metadata access = Cloud credential theft (critical)
- Open Redirect + OAuth flow = Account takeover (critical)
- XSS + CORS misconfiguration = Cross-origin data theft (critical)
- SQL injection + IDOR = Mass data exfiltration (critical)
- Prototype pollution = Potential RCE via template gadgets (critical)

Chain findings are appended automatically with `[CHAIN]` prefix.

### Canary propagation (stored/second-order detection)

Injects unique canary strings into every parameter, then scans all other responses for their presence. If a canary injected at endpoint A appears in the response of endpoint B, it indicates stored/second-order injection.

```bash
ryofuzz -u "http://target/api" -t all --taint-scan --crawl
```

### Differential authorization testing

Sends the same requests with multiple identities and compares results to detect IDOR, broken authentication, and privilege escalation:

```bash
ryofuzz -u "http://target/api/users/1" --mode authz \
  --authz-identities "anon:" \
  --authz-identities "userA:Authorization:Bearer TOKEN_A" \
  --authz-identities "admin:Authorization:Bearer TOKEN_ADMIN"
```

### OpenAPI/Swagger import

Auto-discovers all endpoints and parameters from an OpenAPI spec:

```bash
ryofuzz --openapi https://target/swagger.json -t all
```

### SARIF output (CI/CD integration)

```bash
ryofuzz -u "http://target" -t all --format sarif -o results.sarif
# Upload to GitHub Security tab via github/codeql-action/upload-sarif
```

### Headless browser DOM XSS

Launches headless Chromium, hooks `eval`, `alert`, `document.write`, and `innerHTML`, then injects canary payloads into query params and URL fragments. Confirms client-side execution rather than just reflection. Requires Chromium installed.

```bash
ryofuzz -u "http://target/page?q=test" --browser
ryofuzz -u "http://target" --crawl --browser
```

### Single-packet race attack (HTTP/2)

Fires N requests in a synchronized burst so they arrive at the server simultaneously, eliminating network jitter. Detects TOCTOU race conditions that normal concurrency misses: coupon reuse, balance bypass, double-spend.

```bash
# 20 parallel requests aligned to the same instant
ryofuzz -u "http://target/api/redeem-coupon" -d '{"code":"SAVE10"}' --race-singlepacket 20
```

If multiple requests succeed where only one should, a race condition is flagged.

### Stateful workflow fuzzing

Models multi-step flows (login, create, read, delete) and fuzzes the transitions: skipping steps, reordering, replaying non-idempotent operations, manipulating state between steps. Catches business logic flaws that stateless fuzzers never see.

```bash
ryofuzz --workflow examples/workflow-checkout.yaml
```

Workflow YAML format:

```yaml
workflow: checkout
steps:
  - name: add_cart
    request: {method: POST, url: "http://target/cart", body: '{"item":1,"qty":1}'}
    extract: {cart_id: "cartId\":\"([^\"]+)"}
  - name: apply_coupon
    request: {method: POST, url: "http://target/coupon", body: '{"code":"SAVE10"}'}
    fuzz: [replay_n_times, reorder]
  - name: checkout
    request: {method: POST, url: "http://target/checkout", body: '{"cart":"{{cart_id}}"}'}
    fuzz: [negative_qty]
    assert_logic: [total_not_negative, qty_positive, status_ok]
```

State carries across steps via cookie jar and `{{varname}}` substitution from `extract`.

### DNS OOB listener

Captures blind SSRF/XXE that triggers DNS resolution but not HTTP callbacks. Runs a DNS server that correlates lookups by subdomain token.

```bash
ryofuzz -u "http://target/api" -t ssrf,xxe \
  --oob 10.10.14.5:8888 --oob-dns 53 --oob-mode private
```

Requires a domain whose NS points to your listener, or a target that resolves DNS against you.

### Adaptive WAF evasion

Detects the WAF (Cloudflare, AWS WAF, Akamai, ModSecurity, Imperva) from blocking behavior, then retries blocked payloads through encoding chains (double URL encode, unicode, case randomization, inline comments, HTML entities) until one passes.

```bash
ryofuzz -u "http://target/api?id=1" -t sqli,xss --waf-evade
```

### LLM-assisted (optional)

Uses a local Ollama model (or compatible API) for contextual payload generation and false positive triage. Degrades gracefully if the model is unavailable.

```bash
# Generate stack-specific payloads
ryofuzz -u "http://target/api?id=1" -t all --llm ollama:llama3 --llm-payloads

# Triage findings to reduce false positives
ryofuzz -u "http://target/api?id=1" -t all --llm ollama:llama3 --llm-triage
```

## Architecture

```
ryofuzz/
├── cmd/root.go                  # CLI orchestration
├── internal/
│   ├── behavioral/engine.go     # Behavioral intent mapping (Phase 1-2-3)
│   ├── fuzzer/guided.go         # Coverage-guided evolutionary fuzzer (simhash coverage)
│   ├── input/parser.go          # Injection point auto-detection
│   ├── engine/engine.go         # Concurrent request engine (pooled client)
│   ├── mutator/                 # Radamsa-style + smart type-aware mutations
│   ├── payloads/database.go     # 740+ embedded payloads
│   ├── vulns/                   # 38 vulnerability modules + CVE probe
│   ├── analyzer/                # Behavioral clustering + FP filter
│   ├── confirm/blind.go         # Statistical blind injection confirmation
│   ├── chain/engine.go          # Finding correlation into attack chains
│   ├── taint/canary.go          # Canary propagation (stored/second-order)
│   ├── authz/diff.go            # Differential authorization testing
│   ├── workflow/engine.go       # Stateful multi-step workflow fuzzing
│   ├── race/singlepacket.go     # HTTP/2 single-packet race attack
│   ├── proxy/proxy.go           # Live MITM proxy fuzzing
│   ├── browser/dom.go           # Headless browser DOM XSS (chromedp)
│   ├── waf/evasion.go           # WAF fingerprint + adaptive evasion
│   ├── llm/client.go            # LLM payload gen + triage (Ollama)
│   ├── schema/openapi.go        # OpenAPI/Swagger import
│   ├── logger/logger.go         # Full request/response JSONL logging
│   ├── nuclei/runner.go         # Nuclei template executor
│   ├── reporter/                # text, json, markdown, html, sarif output
│   ├── oob/                     # OOB callback server (HTTP + DNS)
│   ├── auth/                    # Authentication manager
│   ├── crawler/                 # Web spider + JS parser
│   └── plugins/                 # YAML plugin loader
├── examples/                    # Example workflow YAML
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
  -t ssrf --oob 10.10.14.5:8888 --oob-mode private

# Through Burp proxy
ryofuzz -u "http://target/api?q=test" -t all --proxy http://127.0.0.1:8080

# OpenAPI/Swagger auto-discovery
ryofuzz --openapi https://target/v2/swagger.json -t all

# Stored/second-order detection via canary propagation
ryofuzz -u "http://target/api/comments" -d '{"body":"test"}' -t all --taint-scan --crawl

# Differential authorization (detect IDOR/broken auth/privesc)
ryofuzz -u "http://target/api/users/1" --mode authz \
  --authz-identities "anon:" \
  --authz-identities "user:Authorization:Bearer USER_TOKEN" \
  --authz-identities "admin:Authorization:Bearer ADMIN_TOKEN"

# SARIF output for GitHub Security integration
ryofuzz -u "http://target" -t all --format sarif -o results.sarif

# Multi-target via stdin
cat urls.txt | ryofuzz -t sqli,xss

# Full request/response logging for reproducibility
ryofuzz -u "http://target/api?id=1" -t all --log-file scan.jsonl

# New modules: cache deception, OAuth, upload bypass
ryofuzz -u "http://target/account/profile" -t cache-deception
ryofuzz -u "http://target/oauth/authorize?redirect_uri=http://legit.com/cb" -t oauth
ryofuzz -u "http://target/upload" -d @file.png -t upload

# Live proxy: browse while ryofuzz fuzzes in the background
ryofuzz --proxy-mode --proxy-port 8081

# Headless browser DOM XSS
ryofuzz -u "http://target/page?q=test" --browser

# Single-packet race condition (double-spend, coupon reuse)
ryofuzz -u "http://target/api/redeem" -d '{"code":"SAVE10"}' --race-singlepacket 20

# Stateful workflow logic flaws
ryofuzz --workflow examples/workflow-checkout.yaml

# Blind SSRF via DNS exfiltration
ryofuzz -u "http://target/api" -t ssrf,xxe --oob 10.10.14.5:8888 --oob-dns 53 --oob-mode private

# Adaptive WAF evasion
ryofuzz -u "http://target/api?id=1" -t sqli,xss --waf-evade

# LLM-assisted payloads + triage (local Ollama)
ryofuzz -u "http://target/api?id=1" -t all --llm ollama:llama3 --llm-payloads --llm-triage
```

## Disclaimer

For authorized security testing and CTF challenges only. Do not use against systems without explicit permission.

## Author

RyoSec - Renan Zapelini

## License

MIT
