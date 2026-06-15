package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestELInjectDetect(t *testing.T) {
	m := &ELInjectModule{}
	point := input.InjectionPoint{Name: "input", Location: input.LocQueryParam}

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
		// === TRUE POSITIVES: Arithmetic (49) ===
		{
			name: "el-dollar 7*7=49",
			payload: mutator.Payload{Value: "${7*7}", Point: point, Module: "el", Variant: "el-dollar",
				Metadata: map[string]string{"check": "49"}},
			respBody:     "Result: 49",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Result: hello",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name: "el-hash 7*7=49",
			payload: mutator.Payload{Value: "#{7*7}", Point: point, Module: "el", Variant: "el-hash",
				Metadata: map[string]string{"check": "49"}},
			respBody:     "Value is 49 here",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Value is empty here",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name: "el-percent 7*7=49",
			payload: mutator.Payload{Value: "%{7*7}", Point: point, Module: "el", Variant: "el-percent",
				Metadata: map[string]string{"check": "49"}},
			respBody:     "Output: 49",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Output: none",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name: "el-at 7*7=49",
			payload: mutator.Payload{Value: "@{7*7}", Point: point, Module: "el", Variant: "el-at",
				Metadata: map[string]string{"check": "49"}},
			respBody:     "Computed: 49",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Computed: nothing",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		// === TRUE POSITIVES: Complex expression 343 ===
		{
			name: "el-dollar-343 7*7*7=343",
			payload: mutator.Payload{Value: "${7*7*7}", Point: point, Module: "el", Variant: "el-dollar-343",
				Metadata: map[string]string{"check": "49"}},
			respBody:     "Deep eval: 343",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Deep eval: nothing",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		// === TRUE POSITIVES: Runtime/code execution ===
		{
			name: "java.lang.Runtime in response",
			payload: mutator.Payload{Value: "${T(java.lang.Runtime).getRuntime()}", Point: point, Module: "el", Variant: "el-runtime",
				Metadata: map[string]string{"check": "49"}},
			respBody:     "java.lang.Runtime@1a2b3c4d",
			respStatus:   200,
			respTime:     110,
			baseBody:     "normal page",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name: "uid= from exec payload",
			payload: mutator.Payload{Value: "*{T(java.lang.Runtime).getRuntime().exec('id')}", Point: point, Module: "el", Variant: "el-star-exec",
				Metadata: map[string]string{"check": "49"}},
			respBody:     "uid=1000(user) gid=1000(user)",
			respStatus:   200,
			respTime:     110,
			baseBody:     "normal page",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name: "PATH= env leak",
			payload: mutator.Payload{Value: "${T(java.lang.System).getenv()}", Point: point, Module: "el", Variant: "el-env",
				Metadata: map[string]string{"check": "49"}},
			respBody:     "PATH=/usr/local/bin:/usr/bin HOME=/root",
			respStatus:   200,
			respTime:     110,
			baseBody:     "normal page",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		// === FALSE POSITIVE GUARDS ===
		{
			name: "FP: 49 already in baseline",
			payload: mutator.Payload{Value: "${7*7}", Point: point, Module: "el", Variant: "el-dollar",
				Metadata: map[string]string{"check": "49"}},
			respBody:     "Item #49 available",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Item #49 available",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name: "FP: expression echoed without eval",
			payload: mutator.Payload{Value: "${7*7}", Point: point, Module: "el", Variant: "el-dollar",
				Metadata: map[string]string{"check": "49"}},
			respBody:     "You entered: ${7*7}",
			respStatus:   200,
			respTime:     110,
			baseBody:     "You entered: hello",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name: "FP: runtime variant but no indicator in response",
			payload: mutator.Payload{Value: "${T(java.lang.Runtime).getRuntime()}", Point: point, Module: "el", Variant: "el-runtime",
				Metadata: map[string]string{"check": "49"}},
			respBody:     "Error 500: something went wrong",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal page",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name: "FP: java.lang.Runtime already in baseline",
			payload: mutator.Payload{Value: "${T(java.lang.Runtime).getRuntime()}", Point: point, Module: "el", Variant: "el-runtime",
				Metadata: map[string]string{"check": "49"}},
			respBody:     "Docs: java.lang.Runtime class reference",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Docs: java.lang.Runtime class reference",
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
