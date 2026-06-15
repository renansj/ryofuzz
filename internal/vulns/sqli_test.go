package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestSQLiDetect(t *testing.T) {
	m := &SQLiModule{}
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
		// === TRUE POSITIVES: Error-based ===
		{
			name:         "error-based mysql syntax",
			payload:      mutator.Payload{Value: "' OR 1=1--", Point: point, Module: "sqli", Variant: "error"},
			respBody:     "You have an error in your SQL syntax near '1'",
			respStatus:   500,
			respTime:     120,
			baseBody:     "normal page",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name:         "error-based warning mysql",
			payload:      mutator.Payload{Value: "'", Point: point, Module: "sqli", Variant: "error"},
			respBody:     "Warning: mysql_fetch_array() expects parameter",
			respStatus:   200,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name:         "error-based postgres pg_query",
			payload:      mutator.Payload{Value: "'", Point: point, Module: "sqli", Variant: "error"},
			respBody:     "Fatal error: pg_query(): Query failed",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name:         "error-based mssql oledb",
			payload:      mutator.Payload{Value: "'", Point: point, Module: "sqli", Variant: "error"},
			respBody:     "Microsoft OLE DB Provider for SQL Server error '80040e14'",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name:         "error-based oracle ora-00933",
			payload:      mutator.Payload{Value: "'", Point: point, Module: "sqli", Variant: "error"},
			respBody:     "ORA-00933: SQL command not properly ended",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name:         "error-based sqlite operationalerror",
			payload:      mutator.Payload{Value: "'", Point: point, Module: "sqli", Variant: "error"},
			respBody:     "sqlite3.OperationalError: near syntax",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name:         "error-based unclosed quotation mark",
			payload:      mutator.Payload{Value: "'", Point: point, Module: "sqli", Variant: "error"},
			respBody:     "Unclosed quotation mark after the character string",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name:         "error-based java.sql.sqlexception",
			payload:      mutator.Payload{Value: "'", Point: point, Module: "sqli", Variant: "error"},
			respBody:     "Exception: java.sql.SQLException: Syntax error",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name:         "error-based hibernate",
			payload:      mutator.Payload{Value: "'", Point: point, Module: "sqli", Variant: "error"},
			respBody:     "org.hibernate.QueryException: unexpected token",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		// === TRUE POSITIVES: Time-based ===
		{
			name:         "time-based delta > 4500",
			payload:      mutator.Payload{Value: "' OR SLEEP(5)--", Point: point, Module: "sqli", Variant: "time"},
			respBody:     "normal",
			respStatus:   200,
			respTime:     5000,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name:         "time-based pg_sleep",
			payload:      mutator.Payload{Value: "' OR pg_sleep(5)--", Point: point, Module: "sqli", Variant: "time"},
			respBody:     "normal",
			respStatus:   200,
			respTime:     6000,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		// === TRUE POSITIVES: Boolean-based ===
		{
			name:         "boolean-based significant diff",
			payload:      mutator.Payload{Value: "' AND '1'='1", Point: point, Module: "sqli", Variant: "boolean"},
			respBody:     "This is a much longer response body that differs significantly from the base, extra content padding here to make it bigger than 50 chars difference",
			respStatus:   200,
			respTime:     110,
			baseBody:     "short",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "medium",
		},
		// === PAYLOAD DIVERSITY (encoded/case-varied) ===
		{
			name:         "encoded payload still triggers error-based",
			payload:      mutator.Payload{Value: "%27%20OR%201%3D1--", Point: point, Module: "sqli", Variant: "error"},
			respBody:     "you have an error in your sql syntax near '1'",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name:         "case-varied payload triggers error-based",
			payload:      mutator.Payload{Value: "' oR 1=1--", Point: point, Module: "sqli", Variant: "error"},
			respBody:     "SQLSTATE[42000]: Syntax error or access violation",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		// === FALSE POSITIVE GUARDS ===
		{
			name:         "FP: benign response no SQL errors",
			payload:      mutator.Payload{Value: "' OR 1=1--", Point: point, Module: "sqli", Variant: "error"},
			respBody:     "Welcome to the site. Nothing unusual here.",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Welcome to the site. Nothing unusual here.",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: time variant but no delay",
			payload:      mutator.Payload{Value: "' OR SLEEP(5)--", Point: point, Module: "sqli", Variant: "time"},
			respBody:     "normal response",
			respStatus:   200,
			respTime:     200,
			baseBody:     "normal response",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: boolean variant but diff < 50",
			payload:      mutator.Payload{Value: "' AND 1=1--", Point: point, Module: "sqli", Variant: "boolean"},
			respBody:     "response that is nearly the same as base",
			respStatus:   200,
			respTime:     110,
			baseBody:     "response that is nearly same as base ok",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: boolean variant diff exists but status differs",
			payload:      mutator.Payload{Value: "' AND 1=1--", Point: point, Module: "sqli", Variant: "boolean"},
			respBody:     "This is a much much much longer response body that is very different in size from the baseline, padding padding padding padding",
			respStatus:   404,
			respTime:     110,
			baseBody:     "short",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: non-time variant with delay (no trigger)",
			payload:      mutator.Payload{Value: "' OR 1=1--", Point: point, Module: "sqli", Variant: "error"},
			respBody:     "normal response",
			respStatus:   200,
			respTime:     6000,
			baseBody:     "normal response",
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
