package authz

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/renansj/ryofuzz/internal/util"
)

type Identity struct {
	Name    string
	Headers map[string]string
}

type AccessResult struct {
	Identity   string
	StatusCode int
	BodyLength int
	TimeMs     int64
	HasData    bool
}

type AuthzFinding struct {
	URL      string
	Method   string
	Type     string // "idor", "broken-auth", "privilege-escalation"
	LowPriv  string
	HighPriv string
	Evidence string
}

// TestEndpoint sends the same request with each identity and compares
func TestEndpoint(ctx context.Context, client *http.Client, method, url string, body string, identities []Identity) []AuthzFinding {
	var results []AccessResult
	var findings []AuthzFinding

	for _, id := range identities {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
		if err != nil {
			continue
		}
		for k, v := range id.Headers {
			req.Header.Set(k, v)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}

		start := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(start).Milliseconds()
		if err != nil {
			results = append(results, AccessResult{Identity: id.Name, StatusCode: 0})
			continue
		}
		respBody, _ := util.ReadBodyLimited(resp.Body, 0)
		resp.Body.Close()

		hasData := len(respBody) > 100 && resp.StatusCode < 400
		results = append(results, AccessResult{
			Identity:   id.Name,
			StatusCode: resp.StatusCode,
			BodyLength: len(respBody),
			TimeMs:     elapsed,
			HasData:    hasData,
		})
	}

	for i, low := range results {
		if low.Identity == "admin" || !low.HasData {
			continue
		}
		for j, high := range results {
			if i == j || high.Identity == low.Identity {
				continue
			}
			if low.HasData && high.HasData && low.StatusCode == high.StatusCode {
				fType := "idor"
				if low.Identity == "anon" {
					fType = "broken-auth"
				} else if high.Identity == "admin" {
					fType = "privilege-escalation"
				}
				findings = append(findings, AuthzFinding{
					URL:      url,
					Method:   method,
					Type:     fType,
					LowPriv:  low.Identity,
					HighPriv: high.Identity,
					Evidence: fmt.Sprintf("%s got %d (%d bytes) same as %s", low.Identity, low.StatusCode, low.BodyLength, high.Identity),
				})
			}
		}
	}
	return findings
}
