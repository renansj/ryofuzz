package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/renansj/ryofuzz/internal/analyzer"
	"github.com/renansj/ryofuzz/internal/auth"
	"github.com/renansj/ryofuzz/internal/authz"
	"github.com/renansj/ryofuzz/internal/behavioral"
	"github.com/renansj/ryofuzz/internal/browser"
	"github.com/renansj/ryofuzz/internal/chain"
	"github.com/renansj/ryofuzz/internal/confirm"
	"github.com/renansj/ryofuzz/internal/crawler"
	"github.com/renansj/ryofuzz/internal/engine"
	"github.com/renansj/ryofuzz/internal/fuzzer"
	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/llm"
	"github.com/renansj/ryofuzz/internal/logger"
	"github.com/renansj/ryofuzz/internal/mutator"
	"github.com/renansj/ryofuzz/internal/nuclei"
	"github.com/renansj/ryofuzz/internal/oob"
	"github.com/renansj/ryofuzz/internal/plugins"
	proxymod "github.com/renansj/ryofuzz/internal/proxy"
	"github.com/renansj/ryofuzz/internal/race"
	"github.com/renansj/ryofuzz/internal/reporter"
	"github.com/renansj/ryofuzz/internal/schema"
	"github.com/renansj/ryofuzz/internal/smuggle"
	"github.com/renansj/ryofuzz/internal/taint"
	"github.com/renansj/ryofuzz/internal/vulns"
	"github.com/renansj/ryofuzz/internal/waf"
	"github.com/renansj/ryofuzz/internal/workflow"
	"github.com/renansj/ryofuzz/internal/wscheck"
	"github.com/spf13/cobra"
)

var (
	// Target
	targetURL   string
	method      string
	body        string
	headers     []string
	cookies     string

	// Tests
	tests       string
	concurrency int
	proxy       string
	timeout     int
	delay       int
	mode        string
	mutations   int
	verbose     bool
	followRedir bool
	rateLimit   int
	maxRequests int
	autoMode    bool

	// Safety
	allowDestructive bool
	verifyTLS        bool
	maxBodyKB        int

	// Output
	outputFile string
	format     string

	// OOB
	oobDomain string
	oobListen int
	oobMode   string
	oobWait   int

	// Auth
	authMethod  string
	authUser    string
	authPass    string
	authToken   string
	authURL     string
	authBody    string
	authField   string
	authHeader  string
	authPrefix  string

	// Crawler
	crawlMode   bool
	crawlDepth  int
	ignoreRobots bool

	// Plugins
	pluginsDir string

	// Nuclei templates
	nucleiDir           string
	nucleiTags          string
	nucleiSeverity      string
	nucleiStrict        bool
	nucleiReportSkipped bool

	// Logging
	logFile string

	// Taint/Canary
	taintScan bool

	// Authz
	authzIdentities []string

	// OpenAPI
	openAPIURL string
)

var (
	// OOB DNS
	oobDNS int

	// WAF evasion
	wafEvade bool

	// LLM
	llmSpec     string
	llmTriage   bool
	llmPayloads bool

	// Browser
	browserScan bool

	// Workflow
	workflowFile string

	// Race single-packet
	raceSinglepacket int

	// Proxy mode
	proxyMode bool
	proxyPort int
	proxyCA   string
	proxyEndpoints string
	proxyScope []string
)

var rootCmd = &cobra.Command{
	Use:   "ryofuzz",
	Short: "ryofuzz - Offensive web vulnerability fuzzer",
	Long: `ryofuzz - Offensive multi-class web vulnerability fuzzer

Automatically detects injection points in URLs, JSON body and URL-encoded body.
Tests OWASP Top 10, OWASP API Top 10, OWASP LLM Top 10 and underground techniques.
Performs behavioral differential analysis to identify vulnerabilities.

Modules: sqli, xss, ssti, ssrf, cmdi, lfi, nosqli, xxe, idor, redirect, crlf,
         prototype, jwt, mass-assign, race, smuggling, cors, csp, graphql,
         deser, ldapi, xpathi, logic, ratelimit, verb, hostheader, cache, ws, prompt,
         cache-deception, oauth, upload, pwreset, hpp, csv, email-inj, xssi, el

Author: RyoSec (github.com/renansj)`,
	RunE: run,
}

func init() {
	// Target flags
	rootCmd.Flags().StringVarP(&targetURL, "url", "u", "", "Target URL (required)")
	rootCmd.Flags().StringVarP(&method, "method", "X", "", "HTTP method (auto-detected if not provided)")
	rootCmd.Flags().StringVarP(&body, "data", "d", "", "Request body (JSON or URL-encoded)")
	rootCmd.Flags().StringSliceVarP(&headers, "header", "H", nil, "Custom headers (repeatable)")
	rootCmd.Flags().StringVarP(&cookies, "cookie", "b", "", "Cookies")

	// Test config
	rootCmd.Flags().StringVarP(&tests, "tests", "t", "all", "Test modules (all, sqli, xss, ssti, ssrf, ...)")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 20, "Concurrent goroutines")
	rootCmd.Flags().StringVar(&proxy, "proxy", "", "Proxy (ex: http://127.0.0.1:8080)")
	rootCmd.Flags().IntVar(&timeout, "timeout", 15, "Timeout per request (seconds)")
	rootCmd.Flags().IntVar(&delay, "delay", 0, "Delay between requests (ms)")
	rootCmd.Flags().StringVar(&mode, "mode", "smart", "Mode: smart, payloads, mutate, guided, behavioral")
	rootCmd.Flags().IntVarP(&mutations, "mutations", "n", 0, "Number of radamsa-style mutations (0=auto)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolVar(&followRedir, "follow", false, "Follow redirects")
	rootCmd.Flags().IntVar(&rateLimit, "rate", 0, "Rate limit (requests/segundo, 0=ilimitado)")
	rootCmd.Flags().IntVar(&maxRequests, "max-requests", 0, "Global cap on total payloads per target (0=unlimited)")
	rootCmd.Flags().BoolVar(&autoMode, "auto", false, "Auto mode: crawl + all modules + taint + browser + waf-evade + chain")

	// Safety
	rootCmd.Flags().BoolVar(&allowDestructive, "allow-destructive", false, "Enable destructive payloads (DROP TABLE, xp_cmdshell, LOAD_FILE, UTL_HTTP). DANGEROUS: can delete data or run OS commands on a vulnerable target. Off by default.")
	rootCmd.Flags().BoolVar(&verifyTLS, "verify-tls", false, "Verify TLS certificates (default: skip verification for pentest targets)")
	rootCmd.Flags().IntVar(&maxBodyKB, "max-body", 10240, "Max response body read per request in KB (caps memory on huge/hostile bodies)")

	// Output
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file")
	rootCmd.Flags().StringVar(&format, "format", "text", "Format: text, json, markdown, html, sarif")

	// OOB callback
	rootCmd.Flags().StringVar(&oobDomain, "oob", "", "OOB domain/IP for callbacks (SSRF, XXE, blind)")
	rootCmd.Flags().IntVar(&oobListen, "oob-listen", 8888, "OOB listener port")
	rootCmd.Flags().StringVar(&oobMode, "oob-mode", "local", "OOB mode: local, ngrok, private")
	rootCmd.Flags().IntVar(&oobWait, "oob-wait", 3, "Seconds to wait for OOB callbacks after scan")

	// Auth
	rootCmd.Flags().StringVar(&authMethod, "auth", "", "Auth method: basic, bearer, form, cookie, custom")
	rootCmd.Flags().StringVar(&authUser, "auth-user", "", "Auth username")
	rootCmd.Flags().StringVar(&authPass, "auth-pass", "", "Auth password")
	rootCmd.Flags().StringVar(&authToken, "auth-token", "", "Auth token/API key")
	rootCmd.Flags().StringVar(&authURL, "auth-url", "", "Login URL (for auth=form)")
	rootCmd.Flags().StringVar(&authBody, "auth-body", "", "Login body (for auth=form)")
	rootCmd.Flags().StringVar(&authField, "auth-field", "token", "Token field in login response")
	rootCmd.Flags().StringVar(&authHeader, "auth-header", "Authorization", "Header to send token")
	rootCmd.Flags().StringVar(&authPrefix, "auth-prefix", "Bearer", "Token prefix")

	// Crawler
	rootCmd.Flags().BoolVar(&crawlMode, "crawl", false, "Crawl mode: discover endpoints before fuzzing")
	rootCmd.Flags().IntVar(&crawlDepth, "crawl-depth", 3, "Max crawl depth")
	rootCmd.Flags().BoolVar(&ignoreRobots, "ignore-robots", false, "Ignore robots.txt during crawl")

	// Plugins
	rootCmd.Flags().StringVar(&pluginsDir, "plugins-dir", "", "Custom plugins directory")

	// Nuclei
	rootCmd.Flags().StringVar(&nucleiDir, "nuclei-templates", "", "Path to nuclei-templates directory")
	rootCmd.Flags().StringVar(&nucleiTags, "nuclei-tags", "", "Filter nuclei templates by tags (comma-separated)")
	rootCmd.Flags().StringVar(&nucleiSeverity, "nuclei-severity", "critical,high", "Filter nuclei templates by severity")
	rootCmd.Flags().BoolVar(&nucleiStrict, "nuclei-strict", false, "Report templates skipped due to unsupported features as findings")
	rootCmd.Flags().BoolVar(&nucleiReportSkipped, "nuclei-report-skipped", false, "List nuclei templates skipped for unsupported features")

	// Logging
	rootCmd.Flags().StringVar(&logFile, "log-file", ".ryofuzz-log.jsonl", "Path for request/response JSONL log")

	// Taint/Canary
	rootCmd.Flags().BoolVar(&taintScan, "taint-scan", false, "Enable canary propagation for stored/second-order detection")

	// Authz
	rootCmd.Flags().StringSliceVar(&authzIdentities, "authz-identities", nil, "Identities for authz testing (name:header:value, repeatable)")

	// OpenAPI
	rootCmd.Flags().StringVar(&openAPIURL, "openapi", "", "URL to OpenAPI/Swagger spec for endpoint discovery")

	// OOB DNS
	rootCmd.Flags().IntVar(&oobDNS, "oob-dns", 0, "UDP port for DNS OOB listener (0=disabled)")

	// WAF evasion
	rootCmd.Flags().BoolVar(&wafEvade, "waf-evade", false, "Adaptive WAF evasion: retry blocked payloads with encoding chains")

	// LLM
	rootCmd.Flags().StringVar(&llmSpec, "llm", "", "LLM provider spec (e.g. ollama:llama3)")
	rootCmd.Flags().BoolVar(&llmTriage, "llm-triage", false, "Use LLM to triage findings (filter false positives)")
	rootCmd.Flags().BoolVar(&llmPayloads, "llm-payloads", false, "Use LLM to generate additional payloads")

	// Browser
	rootCmd.Flags().BoolVar(&browserScan, "browser", false, "Enable headless browser DOM XSS scanning")

	// Workflow
	rootCmd.Flags().StringVar(&workflowFile, "workflow", "", "Path to workflow YAML for stateful fuzzing")

	// Race single-packet
	rootCmd.Flags().IntVar(&raceSinglepacket, "race-singlepacket", 0, "Single-packet race attack parallel requests (0=disabled)")

	// Proxy mode
	rootCmd.Flags().BoolVar(&proxyMode, "proxy-mode", false, "Start in live proxy fuzzing mode (MITM intercept + scan)")
	rootCmd.Flags().IntVar(&proxyPort, "proxy-port", 8081, "Proxy listen port")
	rootCmd.Flags().StringVar(&proxyCA, "proxy-ca", "ryofuzz-ca.pem", "Path to export CA cert for browser trust")
	rootCmd.Flags().StringVar(&proxyEndpoints, "proxy-endpoints", "ryofuzz-endpoints.json", "Path to export discovered endpoints as OpenAPI spec")
	rootCmd.Flags().StringSliceVar(&proxyScope, "proxy-scope", nil, "Restrict active fuzzing to these hosts (repeatable). Recon maps all traffic.")
}

func Execute() error {
	return rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) error {
	startTime := time.Now()
	banner()

	// Cancellable scan context: Ctrl+C (SIGINT) or SIGTERM stops the scan
	// cleanly, aborting in-flight requests instead of killing the process
	// mid-write and losing results (review B1).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Destructive-payload gate (F1). Off by default; auto mode never enables it.
	vulns.SetAllowDestructive(allowDestructive)
	if allowDestructive {
		fmt.Println("[!] WARNING: --allow-destructive enabled. Destructive SQLi payloads")
		fmt.Println("[!] (DROP TABLE, xp_cmdshell, LOAD_FILE, UTL_HTTP) may delete data or")
		fmt.Println("[!] execute OS commands on a vulnerable target. Ensure you are authorized.")
	}

	// --- Auto mode: enable everything non-destructive against one target ---
	if autoMode {
		fmt.Println("[*] AUTO MODE: enabling full scan (crawl + all modules + taint + browser + waf-evade + chain)")
		if tests == "" || tests == "all" {
			tests = "all"
		}
		crawlMode = true
		taintScan = true
		browserScan = true
		wafEvade = true
		if maxRequests == 0 {
			maxRequests = 5000 // sane default budget to avoid explosion
		}
		if mode == "" {
			mode = "smart"
		}
	}

	// --- Proxy mode ---
	if proxyMode {
		return runProxyMode()
	}

	// --- OpenAPI Import (runs before target check so it can supply targets) ---
	if openAPIURL != "" {
		spec, err := schema.LoadFromURL(openAPIURL)
		if err != nil {
			fmt.Printf("[-] Failed to load OpenAPI: %v\n", err)
		} else {
			oaTargets := schema.ExtractTargets(spec, targetURL)
			fmt.Printf("[+] OpenAPI: discovered %d endpoints\n", len(oaTargets))
			if len(oaTargets) > 0 && targetURL == "" {
				targetURL = oaTargets[0].URL
				method = oaTargets[0].Method
				body = oaTargets[0].Body
			}
		}
	}

	// Multi-target: read from stdin if -u not provided
	if targetURL == "" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				targetURL = strings.TrimSpace(scanner.Text())
			}
		}
		if targetURL == "" {
			return fmt.Errorf("target URL required: use -u or pipe via stdin")
		}
	}

	// --- Workflow mode ---
	if workflowFile != "" {
		fmt.Printf("[*] Loading workflow: %s\n", workflowFile)
		wf, err := workflow.LoadWorkflow(workflowFile)
		if err != nil {
			return fmt.Errorf("failed to load workflow: %w", err)
		}
		fmt.Printf("[+] Workflow %q: %d steps\n", wf.Name, len(wf.Steps))
		client := engine.NewAuthedClient(timeout, staticAuthHeaders(), cookies, proxy, followRedir)
		wfFindings := workflow.Run(ctx, wf, client)
		fmt.Printf("[+] Workflow findings: %d\n", len(wfFindings))
		var allFindings []*vulns.Finding
		for _, f := range wfFindings {
			mod := "logic"
			if f.Strategy == "replay_n_times" {
				mod = "race"
			}
			allFindings = append(allFindings, &vulns.Finding{
				Module:     mod,
				Severity:   f.Severity,
				Confidence: "high",
				Title:      fmt.Sprintf("[%s] %s: %s", f.Strategy, f.Step, f.Type),
				Evidence:   f.Evidence,
				OWASP:      "A04:2021 Insecure Design",
				CWE:        "CWE-362",
			})
		}
		reporter.Report(allFindings, format, outputFile, verbose)
		return nil
	}

	// --- Single-packet race attack ---
	if raceSinglepacket > 0 {
		fmt.Printf("[*] Single-packet race attack (%d parallel requests)\n", raceSinglepacket)
		hdrs := make(map[string]string)
		for _, h := range headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				hdrs[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
		if cookies != "" {
			hdrs["Cookie"] = cookies
		}
		attacker := &race.SinglePacketAttack{}
		results := attacker.Attack(ctx, targetURL, method, body, hdrs, raceSinglepacket)
		diverged, evidence := race.DetectDivergence(results)
		if diverged {
			fmt.Printf("[!] RACE CONDITION DETECTED: %s\n", evidence)
			finding := &vulns.Finding{
				Module:     "race",
				Severity:   "high",
				Confidence: "high",
				Title:      "HTTP/2 Single-Packet Race Condition (TOCTOU)",
				Evidence:   evidence,
				OWASP:      "A04:2021 Insecure Design",
				CWE:        "CWE-362",
			}
			reporter.Report([]*vulns.Finding{finding}, format, outputFile, verbose)
		} else {
			fmt.Println("[*] No race condition detected (responses uniform)")
		}
		return nil
	}

	// --- Logger ---
	scanLog, err := logger.NewScanLogger(logFile)
	if err != nil {
		fmt.Printf("[-] Failed to open log file: %v\n", err)
	} else {
		defer scanLog.Close()
	}

	// --- OOB Server ---
	var oobManager *oob.Manager
	if oobDomain != "" {
		fmt.Printf("[*] Starting OOB callback server (mode=%s)...\n", oobMode)
		oobCfg := oob.Config{
			Listen:  fmt.Sprintf(":%d", oobListen),
			Domain:  oobDomain,
			Mode:    oobMode,
			DNSPort: oobDNS,
		}
		oobManager = oob.NewManager(oobCfg)
		if err := oobManager.Start(); err != nil {
			fmt.Printf("[-] OOB server failed: %v\n", err)
			oobManager = nil
		} else {
			fmt.Printf("[+] OOB server listening on %s (domain: %s)\n", oobCfg.Listen, oobManager.Domain())
			nuclei.SetInteractshProvider(&interactshAdapter{m: oobManager})
		}
	}

	// --- Autenticação ---
	var session *auth.Session
	if authMethod != "" {
		fmt.Printf("[*] Authenticating (%s)...\n", authMethod)
		authCfg := auth.AuthConfig{
			Method:      authMethod,
			Username:    authUser,
			Password:    authPass,
			Token:       authToken,
			LoginURL:    authURL,
			LoginBody:   authBody,
			TokenField:  authField,
			TokenHeader: authHeader,
			TokenPrefix: authPrefix,
		}
		var err error
		session, err = auth.Login(authCfg)
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
		fmt.Println("[+] Authentication successful")
	}

	// --- Crawler ---
	var crawlTargets []string
	if crawlMode {
		fmt.Printf("[*] Crawling %s (depth=%d)...\n", targetURL, crawlDepth)
		crawlCfg := crawler.CrawlConfig{
			SeedURL:      targetURL,
			MaxDepth:     crawlDepth,
			Concurrency:  concurrency,
			Timeout:      timeout,
			Proxy:        proxy,
			IgnoreRobots: ignoreRobots,
			Headers:      headers,
			Cookies:      cookies,
		}
		result, err := crawler.CrawlContext(ctx, crawlCfg)
		if err != nil {
			fmt.Printf("[-] Crawler error: %v\n", err)
		} else {
			fmt.Printf("[+] Crawler found: %d URLs, %d forms, %d API routes, %d JS files\n",
				len(result.URLs), len(result.Forms), len(result.APIRoutes), len(result.JSFiles))
			for _, u := range result.URLs {
				crawlTargets = append(crawlTargets, u.URL)
			}
			for _, route := range result.APIRoutes {
				crawlTargets = append(crawlTargets, route)
			}
		}
	}

	// --- Carregar plugins ---
	var pluginModules []vulns.VulnModule
	pluginDirs := []string{"./plugins", expandHome("~/.ryofuzz/plugins")}
	if pluginsDir != "" {
		pluginDirs = append([]string{pluginsDir}, pluginDirs...)
	}
	loaded, err := plugins.LoadPlugins(pluginDirs)
	if len(loaded) > 0 {
		pluginModules = loaded
		fmt.Printf("[*] Plugins loaded: %d\n", len(pluginModules))
	}
	if err != nil {
		fmt.Printf("[!] Some plugins were skipped: %v\n", err)
	}

	// --- Targets para fuzzear ---
	targets := []string{targetURL}
	if len(crawlTargets) > 0 {
		targets = append(targets, crawlTargets...)
		// Dedup
		seen := make(map[string]bool)
		var deduped []string
		for _, t := range targets {
			if !seen[t] {
				seen[t] = true
				deduped = append(deduped, t)
			}
		}
		targets = deduped
	}

	var allFindings []*vulns.Finding
	totalRequests := 0

	// --- Behavioral mode (intent mapping) ---
	if mode == "behavioral" {
		fmt.Println("[*] Behavioral intent mapping mode")
		points, err := input.Parse(targetURL, method, body, headers, cookies)
		if err != nil {
			return fmt.Errorf("failed to parse injection points: %w", err)
		}
		fmt.Printf("[*] Injection points: %d\n", len(points))

		for _, point := range points {
			fmt.Printf("\n[*] Analyzing: %s [%s] = %q\n", point.Name, point.Location, point.OriginalValue)

			eng := behavioral.New(behavioral.Config{
				Target:  targetURL,
				Method:  method,
				Body:    body,
				Headers: headers,
				Cookies: cookies,
				Param:   point.Name,
				Value:   point.OriginalValue,
				Timeout: timeout,
				Ctx:     ctx,
			})

			model, findings := eng.Run()
			behavioral.PrintModel(model)
			behavioral.PrintFindings(findings)

			// Convert to vulns.Finding for unified reporting
			for _, f := range findings {
				if f.Severity == "info" {
					continue
				}
				allFindings = append(allFindings, &vulns.Finding{
					Module:      "behavioral",
					Severity:    f.Severity,
					Confidence:  f.Confidence,
					Title:       f.Title,
					Description: f.Description,
					Point:       point,
					Evidence:    f.Implication,
					OWASP:       "A03:2021 Injection",
					CWE:         "CWE-20",
				})
			}
		}

		totalRequests = 200 // approximate
		goto doReport
	}

	// --- Coverage-guided mode (AFL++ for web) ---
	if mode == "guided" {
		fmt.Println("[*] Coverage-guided fuzzing mode (AFL++ style)")
		points, err := input.Parse(targetURL, method, body, headers, cookies)
		if err != nil {
			return fmt.Errorf("failed to parse injection points: %w", err)
		}
		fmt.Printf("[*] Injection points: %d\n", len(points))
		for _, p := range points {
			fmt.Printf("    - %s [%s] = %q\n", p.Name, p.Location, p.OriginalValue)
		}

		maxExecs := int64(10000)
		if mutations > 0 {
			maxExecs = int64(mutations)
		}
		maxTime := 60 * time.Second
		if timeout > 0 {
			maxTime = time.Duration(timeout*4) * time.Second
		}

		fzr := fuzzer.New(fuzzer.Config{
			Target:      targetURL,
			Method:      method,
			Body:        body,
			Headers:     headers,
			Cookies:     cookies,
			Proxy:       proxy,
			Timeout:     timeout,
			Points:      points,
			Concurrency: concurrency,
			Ctx:         ctx,
		})

		fmt.Printf("[*] Starting guided fuzzer (max_execs=%d, max_time=%s)\n", maxExecs, maxTime)

		// Verify target is reachable
		testResp := fzr.TestConnection()
		if testResp.StatusCode == -1 {
			return fmt.Errorf("target unreachable: %s (is the server running?)", testResp.ErrorClass)
		}
		fmt.Printf("[*] Target is up: %d (%dms)\n", testResp.StatusCode, testResp.TimingMs)

		corpus := fzr.Fuzz(maxExecs, maxTime)
		stats := fzr.GetStats()
		fmt.Printf("[+] Done: %d execs, %d coverage, %d corpus, %d crashes, %.0f execs/s\n",
			stats.TotalExecs, stats.TotalCoverage, stats.CorpusSize, stats.CrashCount, stats.ExecsPerSec)

		for _, entry := range corpus {
			if entry.Response.StatusCode == 500 || entry.Response.Interesting || entry.Response.ErrorClass != "" {
				sev := "medium"
				title := "Behavioral divergence at depth " + fmt.Sprintf("%d", entry.Depth)
				if entry.Response.StatusCode == 500 {
					sev = "high"
					title = "Server crash/error"
				}
				if entry.Response.TimingMs > 5000 {
					sev = "high"
					title = "Timing anomaly (possible blind injection)"
				}
				if entry.Response.ErrorClass == "sql_error" {
					sev = "critical"
					title = "SQL error triggered"
				}
				allFindings = append(allFindings, &vulns.Finding{
					Module:     "guided-fuzz",
					Severity:   sev,
					Confidence: "high",
					Title:      title,
					Payload:    entry.Value,
					Point:      entry.Point,
					Evidence:   fmt.Sprintf("status=%d, size=%d, time=%dms, error_class=%s, depth=%d",
						entry.Response.StatusCode, entry.Response.BodyLength, entry.Response.TimingMs, entry.Response.ErrorClass, entry.Depth),
					OWASP: "A03:2021 Injection",
					CWE:   "CWE-20",
				})
			}
		}
		totalRequests = int(stats.TotalExecs)
	} else {
	// --- Standard mode ---

	for _, target := range targets {
		if verbose && len(targets) > 1 {
			fmt.Printf("\n[*] Fuzzing: %s\n", target)
		}

		// Stop between targets if the scan was cancelled (Ctrl+C).
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "\n[!] Scan cancelled, stopping.")
			break
		}

		// Parse injection points
		points, err := input.Parse(target, method, body, headers, cookies)
		if err != nil {
			if verbose {
				fmt.Printf("[-] %s: %v\n", target, err)
			}
			continue
		}

		if target == targetURL {
			fmt.Printf("[*] Injection points detected: %d\n", len(points))
			for _, p := range points {
				fmt.Printf("    ├── %s [%s] = %q\n", p.Name, p.Location, p.OriginalValue)
			}
		}

		// Selecionar módulos
		modules := vulns.Select(parseTests(tests))
		// Adicionar plugin modules
		modules = append(modules, pluginModules...)

		if target == targetURL {
			fmt.Printf("[*] Test modules: %d (%s)\n", len(modules), tests)
		}

		// Capturar baseline
		cfg := engine.Config{
			Method:      method,
			URL:         target,
			Body:        body,
			Headers:     headers,
			Cookies:     cookies,
			Proxy:       proxy,
			Timeout:     timeout,
			FollowRedir: followRedir,
			VerifyTLS:   verifyTLS,
			MaxBody:     int64(maxBodyKB) * 1024,
		}

		// Aplicar auth se disponível
		if session != nil {
			if cookies == "" {
				cfg.Cookies = session.GetCookieString()
			}
			cfg.Headers = session.GetAuthHeaders(cfg.Headers)
		}

		if target == targetURL {
			fmt.Println("[*] Capturing baseline...")
		}
		baseline, err := engine.CaptureBaselineContext(ctx, cfg)
		if err != nil {
			if target == targetURL {
				return fmt.Errorf("target unreachable: %v (is the server running?)", err)
			}
			if verbose {
				fmt.Printf("[-] Baseline failed for %s: %v\n", target, err)
			}
			continue
		}
		if target == targetURL {
			fmt.Printf("[*] Baseline: %d %s | %d bytes | %dms\n",
				baseline.StatusCode, baseline.Status, baseline.BodyLength, baseline.TimeMs)
		}

		// Generate payloads
		var allPayloads []mutator.Payload
		for _, mod := range modules {
			plds := mod.GeneratePayloads(points, mode, mutations)
			allPayloads = append(allPayloads, plds...)
		}

		// Inject OOB callback URLs for blind SSRF/XXE/RFI detection
		if oobManager != nil {
			for _, point := range points {
				oobURL := oobManager.GenerateURL("ssrf-oob", "ssrf", point.Name)
				allPayloads = append(allPayloads, mutator.Payload{
					Value: oobURL, Point: point, Module: "ssrf", Variant: "oob-callback",
				})
				// Also try with https scheme and different paths
				oobURL2 := oobManager.GenerateURL("ssrf-oob-redir", "ssrf", point.Name)
				allPayloads = append(allPayloads, mutator.Payload{
					Value: oobURL2 + "/api/internal", Point: point, Module: "ssrf", Variant: "oob-callback-path",
				})
				// DNS-based OOB payloads for blind SSRF/XXE
				if oobDNS > 0 {
					dnsHost := oobManager.GenerateDNSToken("ssrf-dns", "ssrf", point.Name)
					allPayloads = append(allPayloads, mutator.Payload{
						Value: dnsHost, Point: point, Module: "ssrf", Variant: "oob-dns",
					})
					allPayloads = append(allPayloads, mutator.Payload{
						Value: "http://" + dnsHost + "/", Point: point, Module: "ssrf", Variant: "oob-dns-url",
					})
				}
			}
		}

		// Smart payload generation (type-aware fuzzing - the core differentiator)
		if mode == "smart" || mode == "mutate" {
			gen := &mutator.SmartGen{}
			perPoint := 500
			if mutations > 0 {
				perPoint = mutations / max(len(points), 1)
			}
			for _, point := range points {
				smartPayloads := gen.Generate(point.OriginalValue, perPoint)
				for _, sp := range smartPayloads {
					allPayloads = append(allPayloads, mutator.Payload{
						Value: sp, Point: point, Module: "fuzz", Variant: "smartgen",
					})
				}
			}
		}

		// CVE-aware probing (uses baseline headers for fingerprinting)
		cveProbe := &vulns.CVEProbeModule{}
		if baseline != nil {
			hdrs := make(map[string][]string)
			for k, v := range baseline.Headers {
				hdrs[k] = v
			}
			cveProbe.SetFingerprints(hdrs)
			cvePayloads := cveProbe.GeneratePayloads(points, mode, mutations)
			allPayloads = append(allPayloads, cvePayloads...)
		}

		// LLM-assisted payload generation
		if llmSpec != "" && llmPayloads {
			llmClient, err := llm.NewClient(llmSpec)
			if err == nil {
				for _, point := range points {
					for _, mod := range modules {
						extra := llmClient.GeneratePayloads(target, string(point.Location), mod.Name())
						for _, p := range extra {
							allPayloads = append(allPayloads, mutator.Payload{
								Value: p, Point: point, Module: mod.Name(), Variant: "llm",
							})
						}
					}
				}
			} else {
				fmt.Printf("[!] LLM init failed: %v (skipping payload gen)\n", err)
			}
		}

		// Global request budget: cap total payloads to avoid explosion
		// (38 modules + smartgen + CVE + LLM can produce tens of thousands).
		if maxRequests > 0 && len(allPayloads) > maxRequests {
			if target == targetURL {
				fmt.Printf("[!] Payload count %d exceeds budget %d, interleaving across modules\n", len(allPayloads), maxRequests)
			}
			allPayloads = interleaveByModule(allPayloads, maxRequests)
		}

		if target == targetURL {
			fmt.Printf("[*] Total payloads generated: %d (modules=%d, smartgen=%d/point, cve=%s)\n",
				len(allPayloads), len(modules), 500, cveProbe.ServerHeader)
			fmt.Println("[*] Starting fuzzing...")
		}

		// Execute fuzzing
		results := engine.FuzzContext(ctx, cfg, points, allPayloads, concurrency, delay, rateLimit, verbose)
		totalRequests += len(results)

		// Log all requests/responses
		if scanLog != nil {
			for _, r := range results {
				scanLog.Log(logger.LogEntry{
					Timestamp:      time.Now(),
					Method:         cfg.Method,
					URL:            cfg.URL,
					Body:           cfg.Body,
					ResponseStatus: r.Response.StatusCode,
					ResponseBody:   r.Response.Body,
					TimeMs:         r.Response.TimeMs,
					Payload:        r.Payload.Value,
					Module:         r.Payload.Module,
					Point:          r.Payload.Point.Name,
				})
			}
		}

		// Module-based analysis (pattern matching)
		findings := analyzer.Analyze(baseline, results, append(modules, cveProbe))

		// Behavioral analysis (anomaly detection - what makes this a fuzzer, not a scanner)
		behaviorFindings := analyzer.BehaviorAnalysis(baseline, results)
		findings = append(findings, behaviorFindings...)

		// Timing analysis (statistical outlier detection)
		timingFindings := analyzer.TimingAnalysis(baseline, results)
		if len(timingFindings) > 2 {
			timingFindings = timingFindings[:2]
		}
		findings = append(findings, timingFindings...)

		// Differential analysis (boolean oracle detection)
		diffFindings := analyzer.DifferentialPairs(results)
		findings = append(findings, diffFindings...)

		// Reflection scan
		reflectionFindings := analyzer.ReflectionScan(results, baseline.Body)
		findings = append(findings, reflectionFindings...)

		// Filter false positives (echoed payloads in error responses)
		findings = analyzer.FilterFalsePositives(baseline, findings, results)

		// WAF evasion: retry blocked payloads with encoding chains
		if wafEvade {
			var evasionFindings []*vulns.Finding
			for _, r := range results {
				if waf.IsBlocked(r.Response.StatusCode) {
					variants := waf.EvasionVariants(r.Payload.Value)
					for _, v := range variants {
						evPayloads := []mutator.Payload{{
							Value: v, Point: r.Payload.Point, Module: r.Payload.Module, Variant: "waf-evade",
						}}
						evResults := engine.Fuzz(cfg, points, evPayloads, 1, delay, rateLimit, false)
						totalRequests += len(evResults)
						for _, er := range evResults {
							if !waf.IsBlocked(er.Response.StatusCode) {
								evFindings := analyzer.Analyze(baseline, evResults, vulns.Select(parseTests(tests)))
								evasionFindings = append(evasionFindings, evFindings...)
								break
							}
						}
					}
				}
			}
			findings = append(findings, evasionFindings...)
		}

		// Statistical blind injection confirmation pass
		confirmer := confirm.NewBlindConfirmer(cfg)
		var confirmed []*vulns.Finding
		for _, f := range findings {
			if strings.Contains(f.Title, "Time-based") {
				p := mutator.Payload{Value: f.Payload, Point: f.Point, Module: f.Module}
				ok, _ := confirmer.ConfirmTimeBased(cfg, p, 5)
				if !ok {
					continue
				}
			} else if strings.Contains(f.Title, "Boolean") {
				trueP := mutator.Payload{Value: f.Payload, Point: f.Point, Module: f.Module}
				falseV := strings.Replace(f.Payload, "OR 1=1", "OR 1=2", 1)
				falseV = strings.Replace(falseV, "or 1=1", "or 1=2", 1)
				falseP := mutator.Payload{Value: falseV, Point: f.Point, Module: f.Module}
				if !confirmer.ConfirmBoolean(cfg, trueP, falseP) {
					continue
				}
			}
			confirmed = append(confirmed, f)
		}
		findings = confirmed

		allFindings = append(allFindings, findings...)
	}
	} // end else (standard mode)

	// --- Nuclei templates ---
	if nucleiDir != "" {
		fmt.Printf("[*] Loading nuclei templates from %s...\n", nucleiDir)
		templates, err := nuclei.LoadTemplates(nucleiDir, nucleiTags, nucleiSeverity)
		if err != nil {
			fmt.Printf("[-] Failed to load nuclei templates: %v\n", err)
		} else if len(templates) > 0 {
			fmt.Printf("[*] Running %d nuclei templates...\n", len(templates))
			skipped := 0
			for _, t := range templates {
				result := nuclei.Execute(t, targetURL, timeout, proxy)
				if result.Skipped {
					skipped++
					if nucleiReportSkipped || verbose {
						fmt.Printf("    [skip] %s: %s\n", result.TemplateID, result.SkipReason)
					}
					if nucleiStrict {
						allFindings = append(allFindings, &vulns.Finding{
							Module: "nuclei", Severity: "info", Confidence: "low",
							Title:    fmt.Sprintf("[SKIPPED] %s", result.TemplateID),
							Evidence: "Unsupported feature: " + result.SkipReason,
							OWASP:    "N/A", CWE: "N/A",
						})
					}
					continue
				}
				if result.Matched {
					owasp := "A06:2021 Vulnerable and Outdated Components"
					cwe := "CWE-1035"
					if result.CWEID != "" {
						cwe = result.CWEID
					}
					title := fmt.Sprintf("[%s] %s", result.TemplateID, result.Name)
					if result.CVEID != "" {
						title = fmt.Sprintf("[%s] %s", result.CVEID, result.Name)
					}
					allFindings = append(allFindings, &vulns.Finding{
						Module:     "nuclei",
						Severity:   result.Severity,
						Confidence: "confirmed",
						Title:      title,
						Payload:    result.URL,
						Evidence:   result.MatchedAt,
						OWASP:      owasp,
						CWE:        cwe,
					})
				}
			}
			if skipped > 0 {
				fmt.Printf("[*] Nuclei: %d template(s) skipped (unsupported features). Use --nuclei-report-skipped to list.\n", skipped)
			}
		}
	}

	// --- OOB callbacks ---
	if oobManager != nil {
		fmt.Printf("[*] Waiting for OOB callbacks (%ds)...\n", oobWait)
		time.Sleep(time.Duration(oobWait) * time.Second)
		callbacks := oobManager.GetCallbacks()
		if len(callbacks) > 0 {
			fmt.Printf("[+] %d OOB callback(s) received!\n", len(callbacks))
			for _, cb := range callbacks {
				allFindings = append(allFindings, &vulns.Finding{
					Module:     cb.Module,
					Severity:   "critical",
					Confidence: "confirmed",
					Title:      "OOB Callback confirmado - " + cb.Module,
					Payload:    cb.Payload,
					Evidence:   fmt.Sprintf("Callback received from %s at %s: %s %s", cb.RemoteIP, cb.Timestamp.Format(time.RFC3339), cb.Method, cb.Path),
					OWASP:      "A10:2021 SSRF",
					CWE:        "CWE-918",
				})
			}
		}
	}

	// --- Taint/Canary scan ---
	if taintScan || mode == "taint" {
		fmt.Println("[*] Running canary propagation scan (inject + scan)...")
		tracker := taint.NewTracker()
		// Propagate auth/session into the tracker
		if session != nil {
			hdrMap := map[string]string{}
			for _, h := range session.GetAuthHeaders(nil) {
				if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
					hdrMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
			if cookies != "" {
				hdrMap["Cookie"] = cookies
			}
			tracker.SetHeaders(hdrMap)
		} else if cookies != "" {
			tracker.SetHeaders(map[string]string{"Cookie": cookies})
		}

		// Build injection targets from the target's injection points
		points, _ := input.Parse(targetURL, method, body, headers, cookies)
		var injTargets []taint.InjectionTarget
		var params []taint.ParamRef
		for _, p := range points {
			loc := "query"
			switch p.Location {
			case input.LocFormBody:
				loc = "form"
			case input.LocJSONBody:
				loc = "json"
			case input.LocQueryParam:
				loc = "query"
			default:
				continue // skip path/header/cookie for canary injection
			}
			params = append(params, taint.ParamRef{Name: p.Name, Location: loc})
		}
		if len(params) > 0 {
			injTargets = append(injTargets, taint.InjectionTarget{
				URL: targetURL, Method: method, Body: body, Params: params,
			})
		}

		// Scan all crawled targets (plus the target) for resurfaced canaries
		scanTargets := append([]string{targetURL}, targets...)
		if len(crawlTargets) > 0 {
			scanTargets = append(scanTargets, crawlTargets...)
		}
		client := engine.NewAuthedClient(timeout, staticAuthHeaders(), cookies, proxy, followRedir)
		matches := tracker.InjectAndScan(ctx, client, injTargets, scanTargets)
		for _, m := range matches {
			allFindings = append(allFindings, &vulns.Finding{
				Module:     "taint",
				Severity:   "critical",
				Confidence: "confirmed",
				Title:      fmt.Sprintf("Stored/Second-Order Injection: canary from %s/%s found at %s", m.Source.Endpoint, m.Source.Param, m.FoundAt),
				Payload:    m.Source.Canary,
				Evidence:   m.Context,
				OWASP:      "A03:2021 Injection",
				CWE:        "CWE-79",
			})
		}
		if len(matches) > 0 {
			fmt.Printf("[+] Canary propagation: %d stored injection(s) found!\n", len(matches))
		} else {
			fmt.Println("[*] Canary propagation: no stored injections detected")
		}
	}

	// --- CSWSH (Cross-Site WebSocket Hijacking) ---
	if testSelected("ws") || autoMode {
		wsURL := wscheck.NormalizeWSURL(targetURL)
		fmt.Printf("[*] Checking WebSocket Origin validation (CSWSH) on %s...\n", wsURL)
		hdrMap := map[string]string{}
		for _, h := range staticAuthHeaders() {
			if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
				hdrMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
		if cookies != "" {
			hdrMap["Cookie"] = cookies
		}
		res, err := wscheck.Check(wsURL, hdrMap, time.Duration(timeout)*time.Second)
		if err == nil && res != nil && res.Accepted {
			allFindings = append(allFindings, &vulns.Finding{
				Module:     "ws",
				Severity:   "high",
				Confidence: "high",
				Title:      "Cross-Site WebSocket Hijacking (CSWSH)",
				Description: "The WebSocket endpoint completed the handshake for a forged cross-origin Origin, indicating no Origin validation.",
				Payload:    res.ForgedOrigin,
				Evidence:   res.Detail,
				OWASP:      "A05:2021 Security Misconfiguration",
				CWE:        "CWE-346",
			})
			fmt.Println("[+] CSWSH: WebSocket accepted forged Origin!")
		}
	}

	// --- HTTP Request Smuggling (raw-socket time-based CL.TE / TE.CL) ---
	if testSelected("smuggling") || autoMode {
		fmt.Println("[*] Checking HTTP request smuggling (CL.TE / TE.CL, time-based)...")
		smResults, err := smuggle.Check(targetURL, time.Duration(timeout)*time.Second)
		if err == nil {
			for _, r := range smResults {
				if r.Delayed {
					allFindings = append(allFindings, &vulns.Finding{
						Module:      "smuggling",
						Severity:    "high",
						Confidence:  "medium",
						Title:       "HTTP Request Smuggling - " + r.Variant + " desync (unconfirmed)",
						Description: "A crafted request with conflicting Content-Length/Transfer-Encoding caused a delay, indicating a " + r.Variant + " desync. Confirm manually to avoid false positives.",
						Payload:     r.Variant,
						Evidence:    r.Detail,
						OWASP:       "A03:2021 Injection",
						CWE:         "CWE-444",
					})
					fmt.Printf("[+] Smuggling: %s desync signal detected\n", r.Variant)
				}
			}
		}
	}

	// --- Differential Authorization Testing ---
	if mode == "authz" || len(authzIdentities) > 0 {
		fmt.Println("[*] Running differential authorization testing...")
		var identities []authz.Identity
		for _, raw := range authzIdentities {
			parts := strings.SplitN(raw, ":", 3)
			if len(parts) != 3 {
				continue
			}
			identities = append(identities, authz.Identity{
				Name:    parts[0],
				Headers: map[string]string{parts[1]: parts[2]},
			})
		}
		if len(identities) >= 2 {
			client := engine.NewAuthedClient(timeout, staticAuthHeaders(), cookies, proxy, followRedir)
			testTargets := targets
			for _, t := range testTargets {
				azFindings := authz.TestEndpoint(ctx, client, method, t, body, identities)
				for _, af := range azFindings {
					allFindings = append(allFindings, &vulns.Finding{
						Module:     "authz",
						Severity:   "high",
						Confidence: "high",
						Title:      fmt.Sprintf("Authorization bypass (%s): %s accessed as %s", af.Type, af.URL, af.LowPriv),
						Evidence:   af.Evidence,
						OWASP:      "A01:2021 Broken Access Control",
						CWE:        "CWE-862",
					})
				}
			}
		} else {
			fmt.Println("[-] Need at least 2 identities for authz testing")
		}
	}

doReport:
	// --- LLM Triage ---
	if llmSpec != "" && llmTriage && len(allFindings) > 0 {
		llmClient, err := llm.NewClient(llmSpec)
		if err != nil {
			fmt.Printf("[!] LLM init failed: %v (skipping triage)\n", err)
		} else {
			fmt.Printf("[*] Running LLM triage on %d findings...\n", len(allFindings))
			var triaged []*vulns.Finding
			for _, f := range allFindings {
				isReal, conf, reason := llmClient.TriageFinding(f.Request, f.Response, f.Title)
				if !isReal {
					if verbose {
						fmt.Printf("    [-] FP filtered: %s (%s: %s)\n", f.Title, conf, reason)
					}
					continue
				}
				if conf != "" {
					f.Confidence = conf
				}
				triaged = append(triaged, f)
			}
			fmt.Printf("[+] LLM triage: %d/%d findings kept\n", len(triaged), len(allFindings))
			allFindings = triaged
		}
	}

	// --- Browser DOM XSS ---
	if browserScan {
		if !browser.Available() {
			fmt.Println("[!] Chromium not found or not accessible, skipping browser scan")
		} else {
			fmt.Println("[*] Running headless browser DOM XSS scan...")
			scanner := &browser.DOMScanner{}
			scanner.SetAuth(staticAuthHeaders(), cookies)
			scanTargets := targets
			for _, t := range scanTargets {
				points, err := input.Parse(t, method, body, headers, cookies)
				if err != nil {
					continue
				}
				var paramNames []string
				for _, p := range points {
					paramNames = append(paramNames, p.Name)
				}
				if len(paramNames) == 0 {
					continue
				}
				domFindings := scanner.ScanDOMXSS(t, paramNames)
				for _, df := range domFindings {
					allFindings = append(allFindings, &vulns.Finding{
						Module:     "dom",
						Severity:   browser.FormatSeverity(df.Executed),
						Confidence: browser.FormatConfidence(df.Executed),
						Title:      fmt.Sprintf("DOM XSS via %s (sink: %s)", df.Param, df.Sink),
						Payload:    df.Payload,
						Evidence:   fmt.Sprintf("URL: %s, Executed: %v", df.URL, df.Executed),
						OWASP:      "A03:2021 Injection",
						CWE:        "CWE-79",
					})
				}
				if len(domFindings) > 0 {
					fmt.Printf("[+] DOM XSS: %d finding(s) on %s\n", len(domFindings), t)
				}

				// Client-Side Template Injection
				for _, df := range scanner.ScanCSTI(t, paramNames) {
					allFindings = append(allFindings, &vulns.Finding{
						Module: "csti", Severity: "high", Confidence: "high",
						Title:    fmt.Sprintf("Client-Side Template Injection via %s (%s)", df.Param, df.Sink),
						Payload:  df.Payload,
						Evidence: "URL: " + df.URL,
						OWASP:    "A03:2021 Injection", CWE: "CWE-1336",
					})
				}
				// DOM Clobbering
				for _, df := range scanner.ScanDOMClobbering(t, paramNames) {
					allFindings = append(allFindings, &vulns.Finding{
						Module: "domclob", Severity: "medium", Confidence: "high",
						Title:    fmt.Sprintf("DOM Clobbering via %s", df.Param),
						Payload:  df.Payload,
						Evidence: "URL: " + df.URL,
						OWASP:    "A03:2021 Injection", CWE: "CWE-79",
					})
				}
				// Client-Side Path Traversal
				for _, df := range scanner.ScanCSPT(t, paramNames) {
					allFindings = append(allFindings, &vulns.Finding{
						Module: "cspt", Severity: "high", Confidence: "medium",
						Title:    fmt.Sprintf("Client-Side Path Traversal via %s", df.Param),
						Payload:  df.Payload,
						Evidence: df.Sink + " (URL: " + df.URL + ")",
						OWASP:    "A01:2021 Broken Access Control", CWE: "CWE-22",
					})
				}
			}

			// postMessage handlers (per target, not per param)
			for _, t := range scanTargets {
				for _, df := range scanner.ScanPostMessage(t) {
					sev := "medium"
					conf := "low"
					if df.Executed {
						sev = "high"
						conf = "high"
					}
					allFindings = append(allFindings, &vulns.Finding{
						Module: "postmsg", Severity: sev, Confidence: conf,
						Title:    fmt.Sprintf("postMessage without origin validation (%s)", df.Sink),
						Payload:  df.Payload,
						Evidence: "URL: " + df.URL,
						OWASP:    "A08:2021 Software and Data Integrity Failures", CWE: "CWE-346",
					})
				}
			}
		}
	}

	// --- Chain detection ---
	chainFindings := chain.Detect(allFindings)
	allFindings = append(allFindings, chainFindings...)

	// --- Report ---
	duration := time.Since(startTime)
	fmt.Printf("\n[+] Findings: %d (in %s, %d requests)\n", len(allFindings), duration.Round(time.Second), totalRequests)

	switch format {
	case "html":
		meta := reporter.ReportMeta{
			Target:        targetURL,
			StartTime:     startTime,
			Duration:      duration,
			TotalRequests: totalRequests,
			Version:       appVersion,
		}
		outFile := outputFile
		if outFile == "" {
			outFile = "ryofuzz_report.html"
		}
		if err := reporter.ReportHTML(allFindings, meta, outFile); err != nil {
			fmt.Printf("[-] Failed to generate HTML: %v\n", err)
		} else {
			fmt.Printf("[+] HTML report saved: %s\n", outFile)
		}
	case "sarif":
		outFile := outputFile
		if outFile == "" {
			outFile = "ryofuzz_report.sarif"
		}
		if err := reporter.ReportSARIF(allFindings, outFile); err != nil {
			fmt.Printf("[-] Failed to generate SARIF: %v\n", err)
		} else {
			fmt.Printf("[+] SARIF report saved: %s\n", outFile)
		}
	default:
		reporter.Report(allFindings, format, outputFile, verbose)
	}

	return nil
}

func banner() {
	fmt.Printf(`
  ╔═══════════════════════════════════════════╗
  ║             ryofuzz %-21s ║
  ║    Offensive Web Vulnerability Fuzzer     ║
  ║    github.com/renansj/ryofuzz             ║
  ╚═══════════════════════════════════════════╝`+"\n\n", appVersion)
}

func parseTests(t string) []string {
	if t == "all" {
		return []string{"all"}
	}
	return strings.Split(t, ",")
}

// staticAuthHeaders returns auth headers derivable from flags without a login
// round-trip (bearer/custom token). Used by early modes (workflow, authz, race,
// taint) so they inherit authentication. Form-based auth is not covered here.
func staticAuthHeaders() []string {
	var hdrs []string
	hdrs = append(hdrs, headers...) // user-supplied -H
	switch authMethod {
	case "bearer":
		if authToken != "" {
			prefix := authPrefix
			if prefix == "" {
				prefix = "Bearer"
			}
			hdrs = append(hdrs, "Authorization: "+prefix+" "+authToken)
		}
	case "custom":
		if authToken != "" {
			hn := authHeader
			if hn == "" {
				hn = "Authorization"
			}
			hdrs = append(hdrs, hn+": "+authToken)
		}
	}
	return hdrs
}

// interactshAdapter bridges the OOB manager to the nuclei interactsh provider.
type interactshAdapter struct {
	m *oob.Manager
}

func (a *interactshAdapter) NewURL() (string, string) {
	token := a.m.GenerateToken("interactsh", "nuclei", "")
	// Return host/path form (no scheme); templates prepend their own scheme.
	return token, a.m.Domain() + "/t/" + token
}

func (a *interactshAdapter) Poll(id string) (string, string, bool) {
	cbs := a.m.GetCallbacksForToken(id)
	if len(cbs) == 0 {
		return "", "", false
	}
	cb := cbs[0]
	proto := "http"
	if strings.EqualFold(cb.Method, "DNS") {
		proto = "dns"
	}
	return proto, cb.Method + " " + cb.Path, true
}
// interleaveByModule distributes a request budget fairly across modules by
// round-robin, so a large early module does not starve later ones.
func interleaveByModule(payloads []mutator.Payload, limit int) []mutator.Payload {
	groups := map[string][]mutator.Payload{}
	var order []string
	for _, p := range payloads {
		if _, ok := groups[p.Module]; !ok {
			order = append(order, p.Module)
		}
		groups[p.Module] = append(groups[p.Module], p)
	}
	var out []mutator.Payload
	idx := map[string]int{}
	for len(out) < limit {
		progressed := false
		for _, m := range order {
			if idx[m] < len(groups[m]) {
				out = append(out, groups[m][idx[m]])
				idx[m]++
				progressed = true
				if len(out) >= limit {
					break
				}
			}
		}
		if !progressed {
			break
		}
	}
	return out
}


// testSelected reports whether a module name is in the active test selection.
func testSelected(name string) bool {
	if tests == "all" || tests == "" {
		return true
	}
	for _, t := range strings.Split(tests, ",") {
		if strings.TrimSpace(t) == name {
			return true
		}
	}
	return false
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "/tmp"
		}
		return home + path[1:]
	}
	return path
}

func runProxyMode() error {
	addr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	p, err := proxymod.NewProxy(addr)
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}

	if err := p.ExportCA(proxyCA); err != nil {
		return fmt.Errorf("failed to export CA: %w", err)
	}

	if len(proxyScope) > 0 {
		p.SetScope(proxyScope)
		fmt.Printf("[*] Active fuzzing scoped to: %s\n", strings.Join(proxyScope, ", "))
	}

	// Live finding output
	p.OnFinding = func(f *vulns.Finding) {
		sevColors := map[string]string{
			"critical": "\033[91m[CRITICAL]\033[0m",
			"high":     "\033[31m[HIGH]\033[0m",
			"medium":   "\033[33m[MEDIUM]\033[0m",
			"low":      "\033[34m[LOW]\033[0m",
			"info":     "\033[36m[INFO]\033[0m",
		}
		sev := sevColors[f.Severity]
		if sev == "" {
			sev = "[" + strings.ToUpper(f.Severity) + "]"
		}
		fmt.Printf("  %s %s | %s\n", sev, f.Title, f.Evidence)
	}

	fmt.Println("[*] Live Proxy Fuzzing Mode")
	fmt.Printf("[*] Listening on %s\n", addr)
	fmt.Printf("[*] CA certificate exported to: %s\n", proxyCA)
	fmt.Println("")
	fmt.Println("  Configure your browser proxy to: 127.0.0.1:" + fmt.Sprint(proxyPort))
	fmt.Printf("  Install %s as a trusted CA in your browser/OS\n", proxyCA)
	fmt.Println("  Then browse normally. Findings stream below, endpoints are mapped passively.")
	fmt.Println("")
	fmt.Println("[*] Press Ctrl+C to stop, show summary, and export endpoint spec.")
	fmt.Println("")

	// Signal handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := p.Start(); err != nil {
			fmt.Printf("[-] Proxy error: %v\n", err)
			sig <- syscall.SIGTERM
		}
	}()

	<-sig
	fmt.Println("\n[*] Shutting down proxy...")

	// Export discovered endpoints as OpenAPI spec for reuse
	epCount := p.EndpointCount()
	if epCount > 0 && proxyEndpoints != "" {
		if err := p.ExportEndpoints(proxyEndpoints); err != nil {
			fmt.Printf("[-] Failed to export endpoints: %v\n", err)
		} else {
			fmt.Printf("[+] Mapped %d endpoints, exported to: %s\n", epCount, proxyEndpoints)
			fmt.Printf("    Reuse with: ryofuzz --openapi %s -t all\n", proxyEndpoints)
		}
	}

	findings := p.Findings()
	reporter.Report(findings, format, outputFile, verbose)
	return nil
}
