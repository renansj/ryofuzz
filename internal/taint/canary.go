package taint

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CanarySource tracks where a canary was injected
type CanarySource struct {
	Endpoint string
	Param    string
	Location string
	Canary   string
	Injected time.Time
}

// CanaryMatch records where a canary was found
type CanaryMatch struct {
	Source  CanarySource
	FoundAt string
	Context string
}

// Tracker manages canary injection and detection
type Tracker struct {
	mu       sync.Mutex
	canaries []CanarySource
	prefix   string
}

func NewTracker() *Tracker {
	return &Tracker{prefix: "ryofz"}
}

// Generate creates a unique canary string
func (t *Tracker) Generate(endpoint, param, location string) string {
	b := make([]byte, 8)
	rand.Read(b)
	canary := t.prefix + hex.EncodeToString(b)
	t.mu.Lock()
	t.canaries = append(t.canaries, CanarySource{
		Endpoint: endpoint,
		Param:    param,
		Location: location,
		Canary:   canary,
		Injected: time.Now(),
	})
	t.mu.Unlock()
	return canary
}

// Scan checks a response body for any previously injected canaries
func (t *Tracker) Scan(responseBody, foundAtURL string) []CanaryMatch {
	t.mu.Lock()
	defer t.mu.Unlock()
	var matches []CanaryMatch
	for _, src := range t.canaries {
		if idx := strings.Index(responseBody, src.Canary); idx >= 0 {
			if src.Endpoint == foundAtURL {
				continue
			}
			start := idx - 50
			if start < 0 {
				start = 0
			}
			end := idx + len(src.Canary) + 50
			if end > len(responseBody) {
				end = len(responseBody)
			}
			matches = append(matches, CanaryMatch{
				Source:  src,
				FoundAt: foundAtURL,
				Context: responseBody[start:end],
			})
		}
	}
	return matches
}

// InjectAndScan visits all endpoints and checks for canaries
func (t *Tracker) InjectAndScan(client *http.Client, endpoints []string) []CanaryMatch {
	var allMatches []CanaryMatch
	for _, ep := range endpoints {
		resp, err := client.Get(ep)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		matches := t.Scan(string(body), ep)
		allMatches = append(allMatches, matches...)
	}
	return allMatches
}
