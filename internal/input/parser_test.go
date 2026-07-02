package input

import (
	"testing"
)

func hasPoint(points []InjectionPoint, name string, loc Location) bool {
	for _, p := range points {
		if p.Name == name && p.Location == loc {
			return true
		}
	}
	return false
}

func TestParseQueryParams(t *testing.T) {
	points, err := Parse("http://t/api?id=1&name=bob", "", "", nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasPoint(points, "id", LocQueryParam) {
		t.Error("expected query point id")
	}
	if !hasPoint(points, "name", LocQueryParam) {
		t.Error("expected query point name")
	}
}

func TestParseJSONBodyNested(t *testing.T) {
	body := `{"user":"alice","profile":{"role":"admin"}}`
	points, err := Parse("http://t/api", "POST", body, nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasPoint(points, "user", LocJSONBody) {
		t.Error("expected json point user")
	}
	// nested field should be detected with JSONPath
	found := false
	for _, p := range points {
		if p.Location == LocJSONBody && p.JSONPath == "profile.role" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected nested json point profile.role, got %+v", points)
	}
}

func TestParseFormBody(t *testing.T) {
	points, err := Parse("http://t/api", "POST", "a=1&b=2", nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasPoint(points, "a", LocFormBody) || !hasPoint(points, "b", LocFormBody) {
		t.Errorf("expected form points a and b, got %+v", points)
	}
}

func TestParseHeadersAndCookies(t *testing.T) {
	points, err := Parse("http://t/api", "GET", "",
		[]string{"X-Custom: v", "Content-Type: application/json"}, "sid=abc; theme=dark")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasPoint(points, "X-Custom", LocHeader) {
		t.Error("expected header point X-Custom")
	}
	// structural headers must not be fuzzed
	if hasPoint(points, "Content-Type", LocHeader) {
		t.Error("Content-Type should not be an injection point")
	}
	if !hasPoint(points, "sid", LocCookie) || !hasPoint(points, "theme", LocCookie) {
		t.Errorf("expected cookie points sid and theme, got %+v", points)
	}
}

func TestParseInvalidURL(t *testing.T) {
	_, err := Parse("://bad url", "GET", "", nil, "")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestParseNoPointsReturnsEmptyNotError(t *testing.T) {
	// A bare URL with no params yields an empty slice so host-level modules run.
	points, err := Parse("http://t/", "GET", "", nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if points == nil {
		t.Error("expected non-nil empty slice")
	}
}

func TestLooksLikeParam(t *testing.T) {
	cases := map[string]bool{
		"123":                                  true,
		"550e8400-e29b-41d4-a716-446655440000": true, // uuid
		"deadbeefdeadbeef":                     true, // long hex
		"products":                             false,
		"about":                                false,
	}
	for seg, want := range cases {
		if got := looksLikeParam(seg); got != want {
			t.Errorf("looksLikeParam(%q) = %v, want %v", seg, got, want)
		}
	}
}
