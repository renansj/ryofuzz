package waf

import "testing"

func TestIsBlocked(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   bool
	}{
		{"403 blocked", 403, true},
		{"406 blocked", 406, true},
		{"200 not blocked", 200, false},
		{"429 not blocked", 429, false},
		{"500 not blocked", 500, false},
		{"401 not blocked", 401, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsBlocked(tc.status)
			if got != tc.want {
				t.Fatalf("IsBlocked(%d) = %v, want %v", tc.status, got, tc.want)
			}
		})
	}
}

func TestEvasionVariants(t *testing.T) {
	// Use a payload with special chars that will be transformed by all chains
	payload := "' OR 1=1--"
	variants := EvasionVariants(payload)

	if len(variants) == 0 {
		t.Fatal("expected evasion variants, got none")
	}

	// Should have as many variants as evasion chains
	chains := EvasionChains()
	if len(variants) != len(chains) {
		t.Fatalf("expected %d variants, got %d", len(chains), len(variants))
	}

	// At least some variants should differ from original (caseRandomize may match by chance)
	diffCount := 0
	for _, v := range variants {
		if v != payload {
			diffCount++
		}
		if v == "" {
			t.Fatal("got empty variant")
		}
	}
	// doubleURLEncode, unicodeEscape, inlineComments, htmlEntityEncode, mixedURLEncode
	// will all differ. caseRandomize might match rarely. At least 4 should differ.
	if diffCount < 4 {
		t.Fatalf("expected at least 4 different variants, got %d", diffCount)
	}
}

func TestApplyEvasion(t *testing.T) {
	payload := "SELECT * FROM users"

	// Valid index
	v := ApplyEvasion(payload, 0)
	if v == payload {
		t.Fatal("expected transformed payload for index 0")
	}

	// Out of range returns original
	v2 := ApplyEvasion(payload, -1)
	if v2 != payload {
		t.Fatalf("expected original for index -1, got %s", v2)
	}
	v3 := ApplyEvasion(payload, 999)
	if v3 != payload {
		t.Fatalf("expected original for out of range, got %s", v3)
	}
}

func TestDetectWAF(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		body    string
		status  int
		want    string
	}{
		{"cloudflare", map[string][]string{"Cf-Ray": {"abc123"}}, "", 403, "cloudflare"},
		{"aws-waf", map[string][]string{"X-Amzn-Requestid": {"123"}}, "", 403, "aws-waf"},
		{"modsecurity", map[string][]string{}, "ModSecurity - Access Denied", 403, "modsecurity"},
		{"imperva", map[string][]string{}, "Protected by Imperva Incapsula", 403, "imperva"},
		{"none detected", map[string][]string{}, "normal page", 200, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectWAF(tc.headers, tc.body, tc.status)
			if got != tc.want {
				t.Fatalf("DetectWAF() = %q, want %q", got, tc.want)
			}
		})
	}
}
