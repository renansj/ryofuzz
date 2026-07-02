package oob

import (
	"encoding/json"
	"fmt"

	"github.com/renansj/ryofuzz/internal/httpx"
)

const ngrokAPIURL = "http://127.0.0.1:4040/api/tunnels"

type ngrokTunnels struct {
	Tunnels []struct {
		PublicURL string `json:"public_url"`
		Proto     string `json:"proto"`
	} `json:"tunnels"`
}

// GetNgrokURL queries the local ngrok API and returns the public tunnel URL.
func GetNgrokURL() (string, error) {
	client := httpx.New(httpx.Options{TimeoutSec: 3})
	resp, err := client.Get(ngrokAPIURL)
	if err != nil {
		return "", fmt.Errorf("cannot connect to ngrok API at %s: %w\nStart ngrok with: ngrok http <port>", ngrokAPIURL, err)
	}
	defer resp.Body.Close()

	var tunnels ngrokTunnels
	if err := json.NewDecoder(resp.Body).Decode(&tunnels); err != nil {
		return "", fmt.Errorf("failed to parse ngrok API response: %w", err)
	}

	if len(tunnels.Tunnels) == 0 {
		return "", fmt.Errorf("no active ngrok tunnels found")
	}

	// Prefer https tunnel
	for _, t := range tunnels.Tunnels {
		if t.Proto == "https" {
			return t.PublicURL, nil
		}
	}
	return tunnels.Tunnels[0].PublicURL, nil
}
