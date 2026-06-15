package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestCMDiDetect(t *testing.T) {
	m := &CMDiModule{}
	point := input.InjectionPoint{Name: "cmd", Location: input.LocQueryParam}

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
		// === TRUE POSITIVES: Output detection ===
		{
			name: "uid= output detected",
			payload: mutator.Payload{Value: ";id", Point: point, Module: "cmdi", Variant: "linux-semicolon",
				Metadata: map[string]string{"expected": "uid="}},
			respBody:     "uid=1000(kali) gid=1000(kali) groups=1000(kali)",
			respStatus:   200,
			respTime:     110,
			baseBody:     "normal output",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name: "root:x:0:0 output from cat /etc/passwd",
			payload: mutator.Payload{Value: ";cat /etc/passwd", Point: point, Module: "cmdi", Variant: "linux-passwd",
				Metadata: map[string]string{"expected": "root:x:0:0"}},
			respBody:     "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon",
			respStatus:   200,
			respTime:     110,
			baseBody:     "normal output",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		// === TRUE POSITIVES: Time-based ===
		{
			name: "time-based sleep detection",
			payload: mutator.Payload{Value: ";sleep 5", Point: point, Module: "cmdi", Variant: "time-linux",
				Metadata: map[string]string{"expected": ""}},
			respBody:     "normal",
			respStatus:   200,
			respTime:     5500,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name: "time-based subshell",
			payload: mutator.Payload{Value: "$(sleep 5)", Point: point, Module: "cmdi", Variant: "time-linux-sub",
				Metadata: map[string]string{"expected": ""}},
			respBody:     "response",
			respStatus:   200,
			respTime:     6000,
			baseBody:     "response",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		// === FALSE POSITIVE GUARDS ===
		{
			name: "FP: uid in normal content but not expected pattern",
			payload: mutator.Payload{Value: ";id", Point: point, Module: "cmdi", Variant: "linux-semicolon",
				Metadata: map[string]string{"expected": "uid="}},
			respBody:     "User uid is the unique identifier for your account",
			respStatus:   200,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name: "FP: expected output already in baseline",
			payload: mutator.Payload{Value: ";id", Point: point, Module: "cmdi", Variant: "linux-semicolon",
				Metadata: map[string]string{"expected": "uid="}},
			respBody:     "uid=1000(user) gid=1000(user)",
			respStatus:   200,
			respTime:     110,
			baseBody:     "uid=1000(user) gid=1000(user)",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name: "FP: time variant but no delay",
			payload: mutator.Payload{Value: ";sleep 5", Point: point, Module: "cmdi", Variant: "time-linux",
				Metadata: map[string]string{"expected": ""}},
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
			name: "FP: empty expected no output match",
			payload: mutator.Payload{Value: "$(sleep 5)", Point: point, Module: "cmdi", Variant: "time-linux-sub",
				Metadata: map[string]string{"expected": ""}},
			respBody:     "normal response",
			respStatus:   200,
			respTime:     200,
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
