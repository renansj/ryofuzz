package httpx

import "testing"

func TestValidateTarget(t *testing.T) {
	valid := []string{"http://a.com", "https://a.com:8080/x?y=1"}
	for _, u := range valid {
		if err := ValidateTarget(u); err != nil {
			t.Errorf("ValidateTarget(%q) unexpected error: %v", u, err)
		}
	}
	invalid := []string{"", "not-a-url", "ftp://a.com", "http://"}
	for _, u := range invalid {
		if err := ValidateTarget(u); err == nil {
			t.Errorf("ValidateTarget(%q) expected error, got nil", u)
		}
	}
}

func TestValidateProxy(t *testing.T) {
	if err := ValidateProxy(""); err != nil {
		t.Errorf("empty proxy should be allowed, got %v", err)
	}
	valid := []string{"http://127.0.0.1:8080", "socks5://127.0.0.1:1080"}
	for _, p := range valid {
		if err := ValidateProxy(p); err != nil {
			t.Errorf("ValidateProxy(%q) unexpected error: %v", p, err)
		}
	}
	invalid := []string{"haha:bad", "ftp://p", "http://"}
	for _, p := range invalid {
		if err := ValidateProxy(p); err == nil {
			t.Errorf("ValidateProxy(%q) expected error, got nil", p)
		}
	}
}
