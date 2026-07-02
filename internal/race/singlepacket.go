package race

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/renansj/ryofuzz/internal/httpx"
	"github.com/renansj/ryofuzz/internal/util"
)

type SinglePacketAttack struct{}

type RaceResult struct {
	Index      int
	StatusCode int
	BodyHash   string
	TimeMs     int64
}

// Attack performs a synchronized burst race attack using a barrier pattern.
// All N goroutines prepare requests and fire simultaneously after barrier release.
func (s *SinglePacketAttack) Attack(targetURL string, method string, body string, headers map[string]string, count int) []RaceResult {
	results := make([]RaceResult, count)
	var wg sync.WaitGroup
	var barrier sync.WaitGroup

	barrier.Add(1) // single barrier for all goroutines

	tr := httpx.NewTransport(httpx.Options{InsecureSkipVerify: true})
	// Single-packet race needs one warm idle conn per parallel request.
	tr.MaxIdleConns = count
	tr.MaxIdleConnsPerHost = count
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	// Warm up connections
	for i := 0; i < count; i++ {
		req, _ := http.NewRequest("HEAD", targetURL, nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var bodyReader io.Reader
			if body != "" {
				bodyReader = strings.NewReader(body)
			}
			req, err := http.NewRequest(method, targetURL, bodyReader)
			if err != nil {
				results[idx] = RaceResult{Index: idx, StatusCode: -1}
				return
			}
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			if body != "" && req.Header.Get("Content-Type") == "" {
				req.Header.Set("Content-Type", "application/json")
			}

			// Wait at barrier
			barrier.Wait()

			start := time.Now()
			resp, err := client.Do(req)
			elapsed := time.Since(start).Milliseconds()
			if err != nil {
				results[idx] = RaceResult{Index: idx, StatusCode: -1, TimeMs: elapsed}
				return
			}
			defer resp.Body.Close()
			b, _ := util.ReadBodyLimited(resp.Body, 0)
			h := sha256.Sum256(b)
			results[idx] = RaceResult{
				Index:      idx,
				StatusCode: resp.StatusCode,
				BodyHash:   fmt.Sprintf("%x", h[:8]),
				TimeMs:     elapsed,
			}
		}(i)
	}

	// Small sleep to let all goroutines reach the barrier
	time.Sleep(50 * time.Millisecond)
	// Release all at once
	barrier.Done()
	wg.Wait()
	return results
}

// DetectDivergence checks if race results indicate a vulnerability.
// Returns true + evidence string if responses diverge.
func DetectDivergence(results []RaceResult) (bool, string) {
	statusMap := make(map[int]int)
	hashMap := make(map[string]int)
	successCount := 0

	for _, r := range results {
		if r.StatusCode > 0 {
			statusMap[r.StatusCode]++
			hashMap[r.BodyHash]++
			if r.StatusCode < 400 {
				successCount++
			}
		}
	}

	if len(statusMap) > 1 || len(hashMap) > 1 {
		evidence := fmt.Sprintf("response divergence: %d unique statuses, %d unique bodies, %d/%d succeeded",
			len(statusMap), len(hashMap), successCount, len(results))
		return true, evidence
	}
	return false, ""
}
