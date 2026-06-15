package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestLDAPiDetect(t *testing.T) {
	m := &LDAPiModule{}
	point := input.InjectionPoint{Name: "user", Location: input.LocQueryParam}

	tests := []struct {
		name         string
		payload      mutator.Payload
		respBody     string
		respStatus   int
		respTime     int64
		baseBody     string
		baseStatus   int
		baseTime     int64
		respHeaders  map[string][]string
		wantFinding  bool
		wantSeverity string
	}{
		// === TRUE POSITIVES ===
		{
			name:         "ldap_search error",
			payload:      mutator.Payload{Value: "*)(&", Point: point, Module: "ldapi", Variant: "basic"},
			respBody:     "Fatal: ldap_search: Bad search filter",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name:         "invalid dn syntax error",
			payload:      mutator.Payload{Value: "*)(|(&", Point: point, Module: "ldapi", Variant: "basic"},
			respBody:     "Error: Invalid DN Syntax in query",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name:         "bad search filter error",
			payload:      mutator.Payload{Value: "*", Point: point, Module: "ldapi", Variant: "basic"},
			respBody:     "LDAP error: bad search filter (0x2207)",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name:         "javax.naming error",
			payload:      mutator.Payload{Value: "admin)(&)", Point: point, Module: "ldapi", Variant: "basic"},
			respBody:     "javax.naming.NamingException: LDAP filter error",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		// === FALSE POSITIVE GUARDS ===
		{
			name:         "FP: generic unrelated error",
			payload:      mutator.Payload{Value: "*)(&", Point: point, Module: "ldapi", Variant: "basic"},
			respBody:     "Error: File not found on the server",
			respStatus:   404,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: clean response",
			payload:      mutator.Payload{Value: "*", Point: point, Module: "ldapi", Variant: "basic"},
			respBody:     "Welcome, user authenticated successfully",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Welcome, user authenticated successfully",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := m.Detect(tt.payload, tt.baseBody, tt.baseStatus, tt.baseTime, tt.respBody, tt.respStatus, tt.respTime, tt.respHeaders)
			if tt.wantFinding && f == nil {
				t.Fatal("expected finding, got nil")
			}
			if !tt.wantFinding && f != nil {
				t.Fatalf("expected nil, got finding: %s", f.Title)
			}
			if tt.wantFinding && f.Severity != tt.wantSeverity {
				t.Fatalf("expected severity %s, got %s", tt.wantSeverity, f.Severity)
			}
		})
	}
}

func TestXPathiDetect(t *testing.T) {
	m := &XPathiModule{}
	point := input.InjectionPoint{Name: "id", Location: input.LocQueryParam}

	tests := []struct {
		name         string
		payload      mutator.Payload
		respBody     string
		respStatus   int
		respTime     int64
		baseBody     string
		baseStatus   int
		baseTime     int64
		respHeaders  map[string][]string
		wantFinding  bool
		wantSeverity string
	}{
		// === TRUE POSITIVES ===
		{
			name:         "xpath error in response",
			payload:      mutator.Payload{Value: "' or '1'='1", Point: point, Module: "xpathi", Variant: "basic"},
			respBody:     "XPathException: Invalid XPath expression",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal page",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name:         "xmldomelement error",
			payload:      mutator.Payload{Value: "'] | //* | //['", Point: point, Module: "xpathi", Variant: "basic"},
			respBody:     "Error: XMLDOMElement parse failure at position 4",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal page",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name:         "invalid predicate error",
			payload:      mutator.Payload{Value: "' and count(/*)=1 and '1'='1", Point: point, Module: "xpathi", Variant: "basic"},
			respBody:     "Error: Invalid predicate in XPath expression",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal page",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name:         "expression is not valid error",
			payload:      mutator.Payload{Value: "' or ''='", Point: point, Module: "xpathi", Variant: "basic"},
			respBody:     "Error: expression is not valid for this context",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal page",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		// === FALSE POSITIVE GUARDS ===
		{
			name:         "FP: generic unrelated error",
			payload:      mutator.Payload{Value: "' or '1'='1", Point: point, Module: "xpathi", Variant: "basic"},
			respBody:     "Internal server error: database connection timeout",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal page",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: xpath in baseline already",
			payload:      mutator.Payload{Value: "' or '1'='1", Point: point, Module: "xpathi", Variant: "basic"},
			respBody:     "Use XPath to query XML documents",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Use XPath to query XML documents",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: clean response",
			payload:      mutator.Payload{Value: "' or '1'='1", Point: point, Module: "xpathi", Variant: "basic"},
			respBody:     "Results: item1, item2, item3",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Results: item1, item2",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := m.Detect(tt.payload, tt.baseBody, tt.baseStatus, tt.baseTime, tt.respBody, tt.respStatus, tt.respTime, tt.respHeaders)
			if tt.wantFinding && f == nil {
				t.Fatal("expected finding, got nil")
			}
			if !tt.wantFinding && f != nil {
				t.Fatalf("expected nil, got finding: %s", f.Title)
			}
			if tt.wantFinding && f.Severity != tt.wantSeverity {
				t.Fatalf("expected severity %s, got %s", tt.wantSeverity, f.Severity)
			}
		})
	}
}
