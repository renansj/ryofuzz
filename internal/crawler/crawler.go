package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/renansj/ryofuzz/internal/httpx"
)

// CrawlConfig holds crawler configuration.
type CrawlConfig struct {
	SeedURL      string
	MaxDepth     int
	Concurrency  int
	Timeout      int
	Proxy        string
	IgnoreRobots bool
	Headers      []string
	Cookies      string
}

// CrawlResult holds all discovered resources.
type CrawlResult struct {
	URLs      []DiscoveredURL
	Forms     []DiscoveredForm
	APIRoutes []string
	JSFiles   []string
}

// DiscoveredURL represents a found URL.
type DiscoveredURL struct {
	URL    string
	Method string
	Source string
	Params []string
}

// DiscoveredForm represents a found HTML form.
type DiscoveredForm struct {
	Action string
	Method string
	Inputs []FormInput
}

// FormInput represents a form input field.
type FormInput struct {
	Name  string
	Type  string
	Value string
}

type crawlTask struct {
	url   string
	depth int
}

type crawler struct {
	config     CrawlConfig
	baseURL    *url.URL
	client     *http.Client
	ctx        context.Context
	enqueue    func(crawlTask)
	visited    map[string]bool
	mu         sync.Mutex
	result     *CrawlResult
	disallowed []string
}

// Crawl performs web crawling starting from the seed URL.
func Crawl(config CrawlConfig) (*CrawlResult, error) {
	return CrawlContext(context.Background(), config)
}

// CrawlContext is the cancellable form of Crawl. When ctx is cancelled the
// workers stop pulling new URLs and in-flight fetches are aborted (review B1).
func CrawlContext(ctx context.Context, config CrawlConfig) (*CrawlResult, error) {
	parsed, err := url.Parse(config.SeedURL)
	if err != nil {
		return nil, fmt.Errorf("invalid seed URL: %w", err)
	}

	c := &crawler{
		config:  config,
		baseURL: parsed,
		ctx:     ctx,
		client: httpx.New(httpx.Options{
			TimeoutSec: config.Timeout,
			Proxy:      config.Proxy,
			// Crawler follows links, so redirects are followed by default.
			FollowRedirects:    true,
			InsecureSkipVerify: true,
		}),
		visited: make(map[string]bool),
		result:  &CrawlResult{},
	}

	if !config.IgnoreRobots {
		c.parseRobotsTxt()
	}
	c.parseSitemap()

	queue := make(chan crawlTask, 4096)
	done := make(chan struct{})
	var pending sync.WaitGroup // counts tasks not yet processed
	var closeOnce sync.Once
	stop := func() { closeOnce.Do(func() { close(done) }) }

	concurrency := config.Concurrency
	if concurrency < 1 {
		concurrency = 5
	}

	// enqueue adds a task, tracking it as outstanding work. It never blocks on a
	// full queue or a cancelled scan, so workers can't deadlock.
	c.enqueue = func(task crawlTask) {
		if c.ctx.Err() != nil {
			return
		}
		pending.Add(1)
		select {
		case queue <- task:
		default:
			// Queue full: drop the task but keep the counter balanced.
			pending.Done()
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				case task := <-queue:
					if c.ctx.Err() == nil {
						c.processURL(task)
					}
					pending.Done()
				}
			}
		}()
	}

	// Seed.
	c.markVisited(config.SeedURL)
	c.enqueue(crawlTask{url: config.SeedURL, depth: 0})

	// Closer: stop the workers once all work is drained or the scan is cancelled.
	go func() {
		drained := make(chan struct{})
		go func() { pending.Wait(); close(drained) }()
		select {
		case <-drained:
		case <-c.ctx.Done():
		}
		stop()
	}()

	wg.Wait()
	return c.result, nil
}

func (c *crawler) markVisited(u string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.visited[u] {
		return false
	}
	c.visited[u] = true
	return true
}

func (c *crawler) isInScope(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	return parsed.Host == c.baseURL.Host
}

func (c *crawler) isDisallowed(path string) bool {
	for _, d := range c.disallowed {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	return false
}

func (c *crawler) fetch(targetURL string) (string, int, error) {
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "RyoFuzz/1.0")
	for _, h := range c.config.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	if c.config.Cookies != "" {
		req.Header.Set("Cookie", c.config.Cookies)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

func (c *crawler) processURL(task crawlTask) {
	if task.depth > c.config.MaxDepth {
		return
	}

	parsed, err := url.Parse(task.url)
	if err != nil {
		return
	}
	if !c.config.IgnoreRobots && c.isDisallowed(parsed.Path) {
		return
	}

	body, status, err := c.fetch(task.url)
	if err != nil || status >= 400 {
		return
	}

	// Extract and enqueue links
	urls := c.extractURLs(body, task.url)
	for _, u := range urls {
		if c.isInScope(u.URL) && c.markVisited(u.URL) {
			c.mu.Lock()
			c.result.URLs = append(c.result.URLs, u)
			c.mu.Unlock()
			if task.depth+1 <= c.config.MaxDepth {
				c.enqueue(crawlTask{url: u.URL, depth: task.depth + 1})
			}
		}
	}

	// Extract forms
	forms := c.extractForms(body, task.url)
	if len(forms) > 0 {
		c.mu.Lock()
		c.result.Forms = append(c.result.Forms, forms...)
		c.mu.Unlock()
	}

	// Extract JS files and API routes
	jsFiles := c.extractJSFiles(body, task.url)
	if len(jsFiles) > 0 {
		c.mu.Lock()
		c.result.JSFiles = append(c.result.JSFiles, jsFiles...)
		c.mu.Unlock()
		for _, js := range jsFiles {
			if c.markVisited(js) {
				c.processJS(js)
			}
		}
	}

	// Extract API endpoints from inline scripts
	apis := c.extractAPIEndpoints(body)
	if len(apis) > 0 {
		c.mu.Lock()
		c.result.APIRoutes = append(c.result.APIRoutes, apis...)
		c.mu.Unlock()
	}
}

var (
	reHref       = regexp.MustCompile(`(?i)href\s*=\s*["']([^"'#]+)["']`)
	reSrc        = regexp.MustCompile(`(?i)src\s*=\s*["']([^"']+)["']`)
	reAction     = regexp.MustCompile(`(?i)action\s*=\s*["']([^"']+)["']`)
	reComment    = regexp.MustCompile(`<!--([\s\S]*?)-->`)
	reCommentURL = regexp.MustCompile(`(?i)(https?://[^\s<>"']+|/[a-zA-Z0-9_/\-\.]+)`)
)

func (c *crawler) extractURLs(body, sourceURL string) []DiscoveredURL {
	var results []DiscoveredURL
	seen := make(map[string]bool)

	addURL := func(raw, source string) {
		resolved := c.resolveURL(raw, sourceURL)
		if resolved == "" || seen[resolved] {
			return
		}
		seen[resolved] = true
		parsed, err := url.Parse(resolved)
		if err != nil {
			return
		}
		var params []string
		for k := range parsed.Query() {
			params = append(params, k)
		}
		results = append(results, DiscoveredURL{URL: resolved, Method: "GET", Source: source, Params: params})
	}

	for _, m := range reHref.FindAllStringSubmatch(body, -1) {
		addURL(m[1], "href")
	}
	for _, m := range reSrc.FindAllStringSubmatch(body, -1) {
		addURL(m[1], "src")
	}
	for _, m := range reAction.FindAllStringSubmatch(body, -1) {
		addURL(m[1], "form-action")
	}
	// URLs in HTML comments
	for _, cm := range reComment.FindAllStringSubmatch(body, -1) {
		for _, um := range reCommentURL.FindAllString(cm[1], -1) {
			addURL(um, "comment")
		}
	}
	return results
}

var (
	reForm   = regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	reInput  = regexp.MustCompile(`(?is)<input([^>]*)>`)
	reMethod = regexp.MustCompile(`(?i)method\s*=\s*["']([^"']+)["']`)
	reName   = regexp.MustCompile(`(?i)name\s*=\s*["']([^"']+)["']`)
	reType   = regexp.MustCompile(`(?i)type\s*=\s*["']([^"']+)["']`)
	reValue  = regexp.MustCompile(`(?i)value\s*=\s*["']([^"']*?)["']`)
)

func (c *crawler) extractForms(body, sourceURL string) []DiscoveredForm {
	var forms []DiscoveredForm
	for _, m := range reForm.FindAllStringSubmatch(body, -1) {
		attrs, content := m[1], m[2]

		action := ""
		if am := reAction.FindStringSubmatch(attrs); am != nil {
			action = c.resolveURL(am[1], sourceURL)
		} else {
			action = sourceURL
		}

		method := "GET"
		if mm := reMethod.FindStringSubmatch(attrs); mm != nil {
			method = strings.ToUpper(mm[1])
		}

		var inputs []FormInput
		for _, im := range reInput.FindAllStringSubmatch(content, -1) {
			ia := im[1]
			name, typ, val := "", "text", ""
			if nm := reName.FindStringSubmatch(ia); nm != nil {
				name = nm[1]
			}
			if tm := reType.FindStringSubmatch(ia); tm != nil {
				typ = tm[1]
			}
			if vm := reValue.FindStringSubmatch(ia); vm != nil {
				val = vm[1]
			}
			if name != "" {
				inputs = append(inputs, FormInput{Name: name, Type: typ, Value: val})
			}
		}
		forms = append(forms, DiscoveredForm{Action: action, Method: method, Inputs: inputs})
	}
	return forms
}

var reJSSrc = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+\.js[^"']*)["']`)

func (c *crawler) extractJSFiles(body, sourceURL string) []string {
	var files []string
	seen := make(map[string]bool)
	for _, m := range reJSSrc.FindAllStringSubmatch(body, -1) {
		resolved := c.resolveURL(m[1], sourceURL)
		if resolved != "" && !seen[resolved] {
			seen[resolved] = true
			files = append(files, resolved)
		}
	}
	return files
}

var (
	reAPIPath = regexp.MustCompile(`["'](/(?:api|v[0-9]+)/[a-zA-Z0-9_/\-\.]+)["']`)
	reFetch   = regexp.MustCompile(`(?i)fetch\s*\(\s*["']([^"']+)["']`)
	reAxios   = regexp.MustCompile(`(?i)axios\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`)
	reXHROpen = regexp.MustCompile(`(?i)\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']`)
	reFullURL = regexp.MustCompile(`["'](https?://[^\s"'<>]+)["']`)
)

func (c *crawler) extractAPIEndpoints(body string) []string {
	seen := make(map[string]bool)
	var apis []string

	add := func(s string) {
		s = strings.TrimSpace(s)
		if !seen[s] {
			seen[s] = true
			apis = append(apis, s)
		}
	}

	for _, m := range reAPIPath.FindAllStringSubmatch(body, -1) {
		add(m[1])
	}
	for _, m := range reFetch.FindAllStringSubmatch(body, -1) {
		add(m[1])
	}
	for _, m := range reAxios.FindAllStringSubmatch(body, -1) {
		add(m[1])
	}
	for _, m := range reXHROpen.FindAllStringSubmatch(body, -1) {
		add(m[1])
	}
	for _, m := range reFullURL.FindAllStringSubmatch(body, -1) {
		if c.isInScope(m[1]) {
			add(m[1])
		}
	}
	return apis
}

func (c *crawler) processJS(jsURL string) {
	body, _, err := c.fetch(jsURL)
	if err != nil {
		return
	}
	apis := c.extractAPIEndpoints(body)
	if len(apis) > 0 {
		c.mu.Lock()
		c.result.APIRoutes = append(c.result.APIRoutes, apis...)
		c.mu.Unlock()
	}
}

func (c *crawler) parseRobotsTxt() {
	robotsURL := fmt.Sprintf("%s://%s/robots.txt", c.baseURL.Scheme, c.baseURL.Host)
	body, status, err := c.fetch(robotsURL)
	if err != nil || status != 200 {
		return
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path := strings.TrimSpace(strings.TrimPrefix(line, line[:len("Disallow:")]))
			if path != "" {
				c.disallowed = append(c.disallowed, path)
			}
		}
		// Also discover allowed paths as potential endpoints
		if strings.HasPrefix(strings.ToLower(line), "allow:") {
			path := strings.TrimSpace(line[len("Allow:"):])
			if path != "" {
				resolved := fmt.Sprintf("%s://%s%s", c.baseURL.Scheme, c.baseURL.Host, path)
				c.mu.Lock()
				c.result.URLs = append(c.result.URLs, DiscoveredURL{URL: resolved, Method: "GET", Source: "robots.txt"})
				c.mu.Unlock()
			}
		}
	}
}

var reSitemapLoc = regexp.MustCompile(`<loc>\s*([^<]+)\s*</loc>`)

func (c *crawler) parseSitemap() {
	sitemapURL := fmt.Sprintf("%s://%s/sitemap.xml", c.baseURL.Scheme, c.baseURL.Host)
	body, status, err := c.fetch(sitemapURL)
	if err != nil || status != 200 {
		return
	}
	for _, m := range reSitemapLoc.FindAllStringSubmatch(body, -1) {
		u := strings.TrimSpace(m[1])
		if c.isInScope(u) {
			c.markVisited(u)
			c.mu.Lock()
			c.result.URLs = append(c.result.URLs, DiscoveredURL{URL: u, Method: "GET", Source: "sitemap.xml"})
			c.mu.Unlock()
		}
	}
}

func (c *crawler) resolveURL(raw, base string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "data:") {
		return ""
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	resolved := baseURL.ResolveReference(ref)
	resolved.Fragment = ""
	return resolved.String()
}
