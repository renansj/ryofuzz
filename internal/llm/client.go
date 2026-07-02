package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/renansj/ryofuzz/internal/httpx"
)

// Client for LLM inference via Ollama local API
type Client struct {
	provider   string
	model      string
	baseURL    string
	httpClient *http.Client
}

// NewClient parses spec like "ollama:llama3" and returns a configured client
func NewClient(spec string) (*Client, error) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 || parts[0] != "ollama" {
		return nil, fmt.Errorf("unsupported LLM spec %q (expected ollama:<model>)", spec)
	}
	return &Client{
		provider:   parts[0],
		model:      parts[1],
		baseURL:    "http://localhost:11434",
		httpClient: httpx.New(httpx.Options{TimeoutSec: 120}),
	}, nil
}

// Generate sends a prompt to the LLM and returns the text response
func (c *Client) Generate(prompt string) (string, error) {
	payload := map[string]interface{}{
		"model":  c.model,
		"prompt": prompt,
		"stream": false,
	}
	body, _ := json.Marshal(payload)
	resp, err := c.httpClient.Post(c.baseURL+"/api/generate", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}
	var result struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Response, nil
}

// GeneratePayloads asks the LLM to generate attack payloads for a given context
func (c *Client) GeneratePayloads(endpoint, paramType, vulnClass string) []string {
	prompt := fmt.Sprintf(
		"Generate 10 unique attack payloads for testing %s vulnerability on endpoint %s with parameter type %s. "+
			"Output only the payloads, one per line, no numbering or explanation.",
		vulnClass, endpoint, paramType)
	resp, err := c.Generate(prompt)
	if err != nil {
		return nil
	}
	var payloads []string
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			payloads = append(payloads, line)
		}
	}
	return payloads
}

// TriageFinding asks the LLM to classify whether a finding is a true or false positive
func (c *Client) TriageFinding(request, response, vulnTitle string) (isReal bool, confidence string, reason string) {
	prompt := fmt.Sprintf(
		"Analyze this potential vulnerability finding and determine if it is a true positive or false positive.\n\n"+
			"Vulnerability: %s\nRequest: %s\nResponse: %s\n\n"+
			"Reply in exactly this format:\n"+
			"VERDICT: TRUE_POSITIVE or FALSE_POSITIVE\nCONFIDENCE: high, medium, or low\nREASON: one sentence explanation",
		vulnTitle, request, response)
	resp, err := c.Generate(prompt)
	if err != nil {
		return true, "low", "LLM unavailable"
	}
	lines := strings.Split(resp, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "VERDICT:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "VERDICT:"))
			if strings.Contains(strings.ToUpper(v), "FALSE") {
				isReal = false
			} else {
				isReal = true
			}
		} else if strings.HasPrefix(line, "CONFIDENCE:") {
			confidence = strings.TrimSpace(strings.TrimPrefix(line, "CONFIDENCE:"))
		} else if strings.HasPrefix(line, "REASON:") {
			reason = strings.TrimSpace(strings.TrimPrefix(line, "REASON:"))
		}
	}
	if confidence == "" {
		confidence = "low"
	}
	return
}
