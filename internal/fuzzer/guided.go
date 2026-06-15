package fuzzer

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

// CoverageGuidedFuzzer is the AFL++-equivalent for web applications.
// Since we can't instrument the server binary, we use response characteristics
// as a coverage proxy: unique (status, body_hash, body_size_bucket, timing_bucket, error_class)
// tuples represent "new edges" in the server's behavior.
type CoverageGuidedFuzzer struct {
	Target      string
	Method      string
	Body        string
	Headers     []string
	Cookies     string
	Proxy       string
	Timeout     int
	Points      []input.InjectionPoint
	Concurrency int

	// AFL++ internals
	corpus       []CorpusEntry     // inputs that found new coverage
	coverageMap  map[string]bool   // seen response fingerprints (our "bitmap")
	queue        []CorpusEntry     // current mutation queue
	stats        FuzzStats
	mu           sync.Mutex
	client       *http.Client
	rng          *rand.Rand

	// Callbacks
	OnNewCoverage func(entry CorpusEntry)
	OnCrash       func(entry CorpusEntry)
}

// CorpusEntry is a single input in the corpus (like AFL's queue entry)
type CorpusEntry struct {
	Value       string
	Point       input.InjectionPoint
	Fingerprint string
	Response    ResponseInfo
	Energy      int   // how many more mutations to generate from this
	Depth       int   // mutation depth from seed
	Parent      int   // index of parent in corpus (-1 for seeds)
	FoundAt     time.Time
}

// ResponseInfo captures the server's behavior for an input
type ResponseInfo struct {
	StatusCode    int
	BodyLength    int
	BodyHash      string
	TimingMs      int64
	ErrorClass    string
	Headers       map[string]string
	Interesting   bool
}

// FuzzStats tracks fuzzer performance
type FuzzStats struct {
	TotalExecs     int64
	TotalCoverage  int
	CorpusSize     int
	CrashCount     int
	LastNewCov     time.Time
	ExecsPerSec    float64
	StartTime      time.Time
	CyclesDone     int
}

// Config for the coverage-guided fuzzer
type Config struct {
	Target      string
	Method      string
	Body        string
	Headers     []string
	Cookies     string
	Proxy       string
	Timeout     int
	Points      []input.InjectionPoint
	Concurrency int
	MaxExecs    int64  // 0 = unlimited
	MaxTime     time.Duration // 0 = unlimited
	MaxDepth    int    // max mutation chain depth
}

func New(cfg Config) *CoverageGuidedFuzzer {
	return &CoverageGuidedFuzzer{
		Target:      cfg.Target,
		Method:      cfg.Method,
		Body:        cfg.Body,
		Headers:     cfg.Headers,
		Cookies:     cfg.Cookies,
		Proxy:       cfg.Proxy,
		Timeout:     cfg.Timeout,
		Points:      cfg.Points,
		Concurrency: cfg.Concurrency,
		corpus:      make([]CorpusEntry, 0),
		coverageMap: make(map[string]bool),
		queue:       make([]CorpusEntry, 0),
		stats:       FuzzStats{StartTime: time.Now()},
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// TestConnection verifies the target is reachable before fuzzing.
func (f *CoverageGuidedFuzzer) TestConnection() ResponseInfo {
	if len(f.Points) == 0 {
		return ResponseInfo{StatusCode: -1, ErrorClass: "no injection points"}
	}
	return f.execute(f.Points[0].OriginalValue, f.Points[0])
}

// Fuzz runs the coverage-guided evolutionary fuzzing loop.
// This is the core loop equivalent to AFL's fuzz_one().
func (f *CoverageGuidedFuzzer) Fuzz(maxExecs int64, maxTime time.Duration) []CorpusEntry {
	f.stats.StartTime = time.Now()

	// Load persisted corpus if available
	if _, err := os.Stat(defaultCorpusPath); err == nil {
		_ = f.LoadCorpus(defaultCorpusPath)
	}

	// Phase 1: Seed with original values and initial mutations
	f.seedCorpus()

	// Phase 2: Evolutionary loop
	for {
		// Check termination conditions
		if maxExecs > 0 && f.stats.TotalExecs >= maxExecs {
			break
		}
		if maxTime > 0 && time.Since(f.stats.StartTime) >= maxTime {
			break
		}
		// If no new coverage in 30s with large corpus, slow down
		if f.stats.TotalCoverage > 50 && time.Since(f.stats.LastNewCov) > 30*time.Second {
			break
		}

		// Select entry from corpus (favor those with higher energy / newer)
		entry := f.selectEntry()
		if entry == nil {
			break
		}

		// Mutate and execute
		f.fuzzOne(*entry)
		f.stats.CyclesDone++

		// Print stats periodically
		if f.stats.TotalExecs%100 == 0 {
			elapsed := time.Since(f.stats.StartTime).Seconds()
			if elapsed > 0 {
				f.stats.ExecsPerSec = float64(f.stats.TotalExecs) / elapsed
			}
			fmt.Printf("\r[fuzzer] execs: %d | coverage: %d | corpus: %d | crashes: %d | speed: %.0f/s",
				f.stats.TotalExecs, f.stats.TotalCoverage, f.stats.CorpusSize, f.stats.CrashCount, f.stats.ExecsPerSec)
		}
	}
	fmt.Println()

	// Persist corpus for next run
	_ = f.SaveCorpus(defaultCorpusPath)

	return f.corpus
}

// GetStats returns current fuzzer statistics
func (f *CoverageGuidedFuzzer) GetStats() FuzzStats {
	return f.stats
}

const defaultCorpusPath = ".ryofuzz-corpus.json"

// SaveCorpus serializes the corpus to a JSON file
func (f *CoverageGuidedFuzzer) SaveCorpus(path string) error {
	f.mu.Lock()
	data, err := json.Marshal(f.corpus)
	f.mu.Unlock()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadCorpus deserializes corpus entries from a JSON file
func (f *CoverageGuidedFuzzer) LoadCorpus(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var entries []CorpusEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	f.mu.Lock()
	for _, e := range entries {
		fp := f.responseFingerprint(e.Response)
		if !f.coverageMap[fp] {
			f.coverageMap[fp] = true
			f.corpus = append(f.corpus, e)
			f.stats.CorpusSize++
			f.stats.TotalCoverage++
		}
	}
	f.mu.Unlock()
	return nil
}

// seedCorpus initializes the corpus with seed inputs
func (f *CoverageGuidedFuzzer) seedCorpus() {
	seeds := f.generateSeeds()
	for _, seed := range seeds {
		resp := f.execute(seed.Value, seed.Point)
		fp := f.responseFingerprint(resp)

		f.mu.Lock()
		if !f.coverageMap[fp] {
			f.coverageMap[fp] = true
			f.stats.TotalCoverage++
			entry := CorpusEntry{
				Value:       seed.Value,
				Point:       seed.Point,
				Fingerprint: fp,
				Response:    resp,
				Energy:      calcEnergy(resp),
				Depth:       0,
				Parent:      -1,
				FoundAt:     time.Now(),
			}
			f.corpus = append(f.corpus, entry)
			f.stats.CorpusSize++
			f.stats.LastNewCov = time.Now()
		}
		f.mu.Unlock()
		f.stats.TotalExecs++
	}
}

// fuzzOne mutates a single corpus entry and executes the mutations
func (f *CoverageGuidedFuzzer) fuzzOne(entry CorpusEntry) {
	// Generate mutations based on the entry's energy
	numMutations := entry.Energy
	if numMutations < 10 {
		numMutations = 10
	}
	if numMutations > 200 {
		numMutations = 200
	}

	mutations := f.havoc(entry.Value, numMutations)

	for _, mutated := range mutations {
		resp := f.execute(mutated, entry.Point)
		fp := f.responseFingerprint(resp)
		f.stats.TotalExecs++

		f.mu.Lock()
		isNew := !f.coverageMap[fp]
		if isNew {
			f.coverageMap[fp] = true
			f.stats.TotalCoverage++
			f.stats.LastNewCov = time.Now()

			newEntry := CorpusEntry{
				Value:       mutated,
				Point:       entry.Point,
				Fingerprint: fp,
				Response:    resp,
				Energy:      calcEnergy(resp),
				Depth:       entry.Depth + 1,
				Parent:      len(f.corpus) - 1,
				FoundAt:     time.Now(),
			}
			f.corpus = append(f.corpus, newEntry)
			f.stats.CorpusSize++

			if resp.StatusCode == 500 || resp.StatusCode == 502 {
				f.stats.CrashCount++
				if f.OnCrash != nil {
					f.OnCrash(newEntry)
				}
			}
			if f.OnNewCoverage != nil {
				f.OnNewCoverage(newEntry)
			}
		}
		f.mu.Unlock()
	}

	// Decrease energy after processing
	f.mu.Lock()
	for i := range f.corpus {
		if f.corpus[i].Value == entry.Value && f.corpus[i].Point.Name == entry.Point.Name {
			f.corpus[i].Energy--
			break
		}
	}
	f.mu.Unlock()
}

// selectEntry picks the next corpus entry to mutate (power schedule).
// Returns a copy of the entry so callers can use it without holding the lock.
func (f *CoverageGuidedFuzzer) selectEntry() *CorpusEntry {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.corpus) == 0 {
		return nil
	}

	// Favor entries with: high energy, recent discovery, lower depth (exploit schedule)
	// This mimics AFL++'s MOpt/explore schedule
	candidates := make([]int, 0)
	for i, e := range f.corpus {
		if e.Energy > 0 {
			candidates = append(candidates, i)
		}
	}

	if len(candidates) == 0 {
		// Reset energy for all entries (new cycle)
		for i := range f.corpus {
			f.corpus[i].Energy = calcEnergy(f.corpus[i].Response)
		}
		idx := f.rng.Intn(len(f.corpus))
		entry := f.corpus[idx]
		return &entry
	}

	// Weighted random: prefer higher energy
	sort.Slice(candidates, func(i, j int) bool {
		return f.corpus[candidates[i]].Energy > f.corpus[candidates[j]].Energy
	})

	// Top 25% get selected more often
	topN := len(candidates) / 4
	if topN < 1 {
		topN = 1
	}
	idx := candidates[f.rng.Intn(topN)]
	entry := f.corpus[idx]
	return &entry
}

// havoc applies random mutations (AFL's havoc stage)
func (f *CoverageGuidedFuzzer) havoc(value string, count int) []string {
	results := make([]string, 0, count)

	for i := 0; i < count; i++ {
		mutated := value
		// Apply 1-5 stacked mutations (like AFL's havoc)
		numOps := f.rng.Intn(5) + 1
		for op := 0; op < numOps; op++ {
			strategy := f.rng.Intn(20)
			switch {
			case strategy < 4:
				mutated = mutator.Mutate(mutated, 1)[0]
			case strategy < 8:
				// Splice with another corpus entry
				if len(f.corpus) > 1 {
					other := f.corpus[f.rng.Intn(len(f.corpus))]
						mutated = f.splice(mutated, other.Value)
				}
			case strategy < 12:
				// Insert interesting token
				token := interestingTokens[f.rng.Intn(len(interestingTokens))]
				pos := f.rng.Intn(len(mutated) + 1)
				mutated = mutated[:pos] + token + mutated[pos:]
			case strategy < 15:
				// Replace with interesting value at random position
				if len(mutated) > 2 {
					pos := f.rng.Intn(len(mutated))
					end := pos + f.rng.Intn(min(10, len(mutated)-pos)) + 1
					token := interestingTokens[f.rng.Intn(len(interestingTokens))]
					mutated = mutated[:pos] + token + mutated[end:]
				}
			case strategy < 17:
				// Delete random chunk
				if len(mutated) > 5 {
					pos := f.rng.Intn(len(mutated))
					end := pos + f.rng.Intn(min(20, len(mutated)-pos)) + 1
					mutated = mutated[:pos] + mutated[end:]
				}
			case strategy < 19:
				// Repeat random chunk
				if len(mutated) > 2 {
					pos := f.rng.Intn(len(mutated))
					end := pos + f.rng.Intn(min(10, len(mutated)-pos)) + 1
					chunk := mutated[pos:end]
					reps := f.rng.Intn(20) + 2
					mutated = mutated[:pos] + strings.Repeat(chunk, reps) + mutated[end:]
				}
			default:
				// Flip random bytes
				if len(mutated) > 0 {
					bytes := []byte(mutated)
					pos := f.rng.Intn(len(bytes))
					bytes[pos] ^= byte(1 << uint(f.rng.Intn(8)))
					mutated = string(bytes)
				}
			}
		}
		if mutated != value && mutated != "" {
			results = append(results, mutated)
		}
	}
	return results
}

// execute sends a fuzzed request and captures the response
func (f *CoverageGuidedFuzzer) execute(value string, point input.InjectionPoint) ResponseInfo {
	// Build request with the mutated value injected
	req := f.buildRequest(value, point)
	if req == nil {
		return ResponseInfo{StatusCode: -1}
	}

	client := f.getClient()
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		return ResponseInfo{StatusCode: -1, TimingMs: elapsed, ErrorClass: classifyError(err)}
	}
	defer resp.Body.Close()

	// Read limited body (we don't need full body for fingerprinting)
	buf := make([]byte, 16384)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	return ResponseInfo{
		StatusCode: resp.StatusCode,
		BodyLength: n,
		BodyHash:   fmt.Sprintf("%x", md5.Sum(buf[:n])),
		TimingMs:   elapsed,
		ErrorClass: extractErrorClass(body),
		Interesting: resp.StatusCode == 500 || elapsed > 5000,
	}
}

// responseFingerprint creates a coverage-map key from a response.
// This is our equivalent of AFL's edge coverage bitmap.
// Two responses with the same fingerprint are considered "same behavior".
func (f *CoverageGuidedFuzzer) responseFingerprint(resp ResponseInfo) string {
	// Bucket body length (reduces noise from dynamic content)
	sizeBucket := resp.BodyLength / 50 * 50
	// Bucket timing
	timeBucket := int64(0)
	switch {
	case resp.TimingMs < 100:
		timeBucket = 0
	case resp.TimingMs < 500:
		timeBucket = 1
	case resp.TimingMs < 1000:
		timeBucket = 2
	case resp.TimingMs < 3000:
		timeBucket = 3
	case resp.TimingMs < 5000:
		timeBucket = 4
	default:
		timeBucket = 5
	}

	// Simhash of normalized body for structural similarity
	sh := simhash(normalizeBody(resp.BodyHash))
	top8 := sh >> 56

	return fmt.Sprintf("%d|%d|%d|%s|%02x", resp.StatusCode, sizeBucket, timeBucket, resp.ErrorClass, top8)
}

var (
	reUUID      = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	reISO8601   = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`)
	reUnixTS    = regexp.MustCompile(`\b1[0-9]{9}\b`)
	reCSRF      = regexp.MustCompile(`name="_token"\s+value="[^"]*"`)
	reHex32     = regexp.MustCompile(`[0-9a-fA-F]{32,}`)
)

func normalizeBody(body string) string {
	body = reUUID.ReplaceAllString(body, "")
	body = reISO8601.ReplaceAllString(body, "")
	body = reUnixTS.ReplaceAllString(body, "")
	body = reCSRF.ReplaceAllString(body, "")
	body = reHex32.ReplaceAllString(body, "")
	return body
}

func simhash(text string) uint64 {
	var v [64]int
	for i := 0; i+3 <= len(text); i++ {
		h := fnv.New64a()
		h.Write([]byte(text[i : i+3]))
		hash := h.Sum64()
		for bit := 0; bit < 64; bit++ {
			if hash&(1<<uint(bit)) != 0 {
				v[bit]++
			} else {
				v[bit]--
			}
		}
	}
	var result uint64
	for bit := 0; bit < 64; bit++ {
		if v[bit] > 0 {
			result |= 1 << uint(bit)
		}
	}
	return result
}

func (f *CoverageGuidedFuzzer) buildRequest(value string, point input.InjectionPoint) *http.Request {
	url := f.Target
	body := f.Body
	method := f.Method
	if method == "" {
		if body != "" {
			method = "POST"
		} else {
			method = "GET"
		}
	}

	// Inject value based on point location
	switch point.Location {
	case input.LocQueryParam:
		if strings.Contains(url, point.Name+"=") {
			// Replace existing param value
			parts := strings.SplitN(url, "?", 2)
			if len(parts) == 2 {
				params := strings.Split(parts[1], "&")
				for i, p := range params {
					if strings.HasPrefix(p, point.Name+"=") {
						params[i] = point.Name + "=" + value
					}
				}
				url = parts[0] + "?" + strings.Join(params, "&")
			}
		}
	case input.LocJSONBody:
		// Simple replacement in JSON body
		if point.OriginalValue != "" {
			body = strings.Replace(body, `"`+point.OriginalValue+`"`, `"`+value+`"`, 1)
			body = strings.Replace(body, point.OriginalValue, value, 1)
		}
	case input.LocFormBody:
		if strings.Contains(body, point.Name+"=") {
			parts := strings.Split(body, "&")
			for i, p := range parts {
				if strings.HasPrefix(p, point.Name+"=") {
					parts[i] = point.Name + "=" + value
				}
			}
			body = strings.Join(parts, "&")
		}
	}

	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequest(method, url, bodyReader)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "ryofuzz/1.0.0")
	if body != "" {
		if strings.HasPrefix(strings.TrimSpace(body), "{") {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	for _, h := range f.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	if f.Cookies != "" {
		req.Header.Set("Cookie", f.Cookies)
	}
	return req
}

func (f *CoverageGuidedFuzzer) getClient() *http.Client {
	if f.client != nil {
		return f.client
	}
	f.client = &http.Client{
		Timeout: time.Duration(f.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return f.client
}

func (f *CoverageGuidedFuzzer) generateSeeds() []struct {
	Value string
	Point input.InjectionPoint
} {
	var seeds []struct {
		Value string
		Point input.InjectionPoint
	}

	for _, point := range f.Points {
		// Original value always
		seeds = append(seeds, struct {
			Value string
			Point input.InjectionPoint
		}{point.OriginalValue, point})

		// Type-aware seeds based on the original value
		typeSeeds := seedsForValue(point.OriginalValue)
		for _, s := range typeSeeds {
			seeds = append(seeds, struct {
				Value string
				Point input.InjectionPoint
			}{s, point})
		}

		// Generic seeds always
		for _, s := range initialSeeds {
			seeds = append(seeds, struct {
				Value string
				Point input.InjectionPoint
			}{s, point})
		}
	}
	return seeds
}

func seedsForValue(val string) []string {
	// URL parameter - needs URL-shaped seeds to hit different code paths
	if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.Contains(val, "://") {
		return []string{
			// Internal network
			"http://127.0.0.1/", "http://localhost/", "http://0.0.0.0/",
			"http://[::1]/", "http://0/", "http://127.1/",
			// Cloud metadata
			"http://169.254.169.254/latest/meta-data/",
			"http://0xA9FEA9FE/latest/meta-data/",
			"http://2852039166/latest/meta-data/",
			"http://0251.0376.0251.0376/latest/meta-data/",
			"http://[::ffff:169.254.169.254]/",
			// Internal services
			"http://127.0.0.1:6379/", "http://127.0.0.1:3000/",
			"http://127.0.0.1:8080/", "http://127.0.0.1:9200/",
			// Protocol smuggling
			"file:///etc/passwd", "gopher://127.0.0.1:6379/",
			"dict://127.0.0.1:6379/INFO",
			// Bypass patterns
			"http://evil.com@127.0.0.1/", "http://127.0.0.1#@evil.com",
			// Malformed
			"http://", "://", "//127.0.0.1/",
			// Very long URL
			"http://" + strings.Repeat("a", 5000) + ".com",
		}
	}
	// Numeric
	if _, err := fmt.Sscanf(val, "%d", new(int)); err == nil {
		return []string{"0", "-1", "1", "99999999", "2147483647", "-2147483648", "NaN"}
	}
	// Email-like
	if strings.Contains(val, "@") {
		return []string{"test@evil.com", "a]@evil.com", `"@evil.com`, "test@127.0.0.1"}
	}
	return nil
}

// calcEnergy determines how many mutations to generate from this entry.
// Higher energy = more interesting = gets more CPU time (power schedule).
func calcEnergy(resp ResponseInfo) int {
	energy := 10 // base

	// 500 errors are very interesting (possible crash)
	if resp.StatusCode == 500 {
		energy += 50
	}
	// Slow responses might indicate injection
	if resp.TimingMs > 2000 {
		energy += 30
	}
	// Error messages in body
	if resp.ErrorClass != "" {
		energy += 20
	}
	// Unusual status codes
	if resp.StatusCode != 200 && resp.StatusCode != 404 && resp.StatusCode != 403 {
		energy += 10
	}
	return energy
}

func classifyError(err error) string {
	s := err.Error()
	if strings.Contains(s, "timeout") {
		return "timeout"
	}
	if strings.Contains(s, "refused") {
		return "refused"
	}
	if strings.Contains(s, "reset") {
		return "reset"
	}
	return "network"
}

func extractErrorClass(body string) string {
	lower := strings.ToLower(body)
	switch {
	case strings.Contains(lower, "sql") || strings.Contains(lower, "syntax"):
		return "sql_error"
	case strings.Contains(lower, "traceback") || strings.Contains(lower, "exception"):
		return "exception"
	case strings.Contains(lower, "template") || strings.Contains(lower, "jinja"):
		return "template_error"
	case strings.Contains(lower, "null") && strings.Contains(lower, "pointer"):
		return "null_deref"
	case strings.Contains(lower, "stack overflow") || strings.Contains(lower, "recursion"):
		return "stack_overflow"
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "timed out"):
		return "timeout"
	case strings.Contains(lower, "memory") || strings.Contains(lower, "allocation"):
		return "memory"
	default:
		return ""
	}
}

func (f *CoverageGuidedFuzzer) splice(a, b string) string {
	if len(a) < 2 || len(b) < 2 {
		return a + b
	}
	splitA := f.rng.Intn(len(a))
	splitB := f.rng.Intn(len(b))
	return a[:splitA] + b[splitB:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Interesting tokens that often trigger bugs when injected
var interestingTokens = []string{
	"'", "\"", "`", "\\", "\n", "\r\n", "\x00",
	"<", ">", "&", "|", ";", "$", "(", ")",
	"{", "}", "[", "]", "{{", "}}", "${", "<%",
	"../", "..\\", "%00", "%0a", "%0d",
	"' OR '1'='1", "{{7*7}}", "${7*7}", "<script>",
	"-1", "0", "99999999", "NaN", "null", "undefined",
	"true", "false", "[]", "{}", "Array(99999).join('A')",
	"__proto__", "constructor", "prototype",
	"\ufeff", "\u200b", "\u202e",
	"AAAA" + strings.Repeat("A", 256),
}

// Initial seeds - small set that covers basic behavior discovery
var initialSeeds = []string{
	"", " ", "null", "undefined", "true", "false",
	"0", "1", "-1", "999999999",
	"'", "\"", "<", ">", "\\",
	"{{7*7}}", "${7*7}", "<%=7*7%>",
	"../../../etc/passwd", "/etc/passwd",
	"http://127.0.0.1", "http://169.254.169.254/",
	";sleep 5", "| id", "$(id)",
	"' OR 1=1--", "' AND SLEEP(5)--",
	"%00", "%0a", "\r\n",
	strings.Repeat("A", 1000),
	`{"__proto__":{"x":1}}`,
}
