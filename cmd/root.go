package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/renansj/ryofuzz/internal/analyzer"
	"github.com/renansj/ryofuzz/internal/auth"
	"github.com/renansj/ryofuzz/internal/crawler"
	"github.com/renansj/ryofuzz/internal/engine"
	"github.com/renansj/ryofuzz/internal/fuzzer"
	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
	"github.com/renansj/ryofuzz/internal/oob"
	"github.com/renansj/ryofuzz/internal/plugins"
	"github.com/renansj/ryofuzz/internal/reporter"
	"github.com/renansj/ryofuzz/internal/vulns"
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

	// Output
	outputFile string
	format     string

	// OOB
	oobDomain string
	oobListen int
	oobMode   string

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
         deser, ldapi, xpathi, logic, ratelimit, verb, hostheader, cache, ws, prompt

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
	rootCmd.Flags().StringVar(&mode, "mode", "smart", "Mode: smart, payloads, mutate, guided (AFL++ style)")
	rootCmd.Flags().IntVarP(&mutations, "mutations", "n", 0, "Number of radamsa-style mutations (0=auto)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolVar(&followRedir, "follow", false, "Follow redirects")
	rootCmd.Flags().IntVar(&rateLimit, "rate", 0, "Rate limit (requests/segundo, 0=ilimitado)")

	// Output
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file")
	rootCmd.Flags().StringVar(&format, "format", "text", "Format: text, json, markdown, html")

	// OOB callback
	rootCmd.Flags().StringVar(&oobDomain, "oob", "", "OOB domain/IP for callbacks (SSRF, XXE, blind)")
	rootCmd.Flags().IntVar(&oobListen, "oob-listen", 8888, "OOB listener port")
	rootCmd.Flags().StringVar(&oobMode, "oob-mode", "local", "OOB mode: local, ngrok, private")

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

	rootCmd.MarkFlagRequired("url")
}

func Execute() error {
	return rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) error {
	startTime := time.Now()
	banner()

	// --- OOB Server ---
	var oobManager *oob.Manager
	if oobDomain != "" {
		fmt.Printf("[*] Starting OOB callback server (mode=%s)...\n", oobMode)
		oobCfg := oob.Config{
			Listen: fmt.Sprintf(":%d", oobListen),
			Domain: oobDomain,
			Mode:   oobMode,
		}
		oobManager = oob.NewManager(oobCfg)
		go oobManager.Start()
		fmt.Printf("[+] OOB server listening on %s (domain: %s)\n", oobCfg.Listen, oobManager.Domain())
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
		result, err := crawler.Crawl(crawlCfg)
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
	if err == nil && len(loaded) > 0 {
		pluginModules = loaded
		fmt.Printf("[*] Plugins loaded: %d\n", len(pluginModules))
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
		baseline, err := engine.CaptureBaseline(cfg)
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

		if target == targetURL {
			fmt.Printf("[*] Total payloads generated: %d (modules=%d, smartgen=%d/point, cve=%s)\n",
				len(allPayloads), len(modules), 500, cveProbe.ServerHeader)
			fmt.Println("[*] Starting fuzzing...")
		}

		// Execute fuzzing
		results := engine.Fuzz(cfg, points, allPayloads, concurrency, delay, rateLimit, verbose)
		totalRequests += len(results)

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

		allFindings = append(allFindings, findings...)
	}
	} // end else (standard mode)

	// --- OOB callbacks ---
	if oobManager != nil {
		fmt.Println("[*] Waiting for OOB callbacks (3s)...")
		time.Sleep(3 * time.Second)
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
			Version:       "0.1.0",
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
	default:
		reporter.Report(allFindings, format, outputFile, verbose)
	}

	return nil
}

func banner() {
	fmt.Println(`
  ╔═══════════════════════════════════════════╗
  ║             ryofuzz v0.1.0                ║
  ║    Offensive Web Vulnerability Fuzzer     ║
  ║    github.com/renansj/ryofuzz             ║
  ╚═══════════════════════════════════════════╝`)
	fmt.Println()
}

func parseTests(t string) []string {
	if t == "all" {
		return []string{"all"}
	}
	return strings.Split(t, ",")
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home := "/home/kali"
		return home + path[1:]
	}
	return path
}
