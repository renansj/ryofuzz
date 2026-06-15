package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestSSTIDetect(t *testing.T) {
	m := &SSTIModule{}
	point := input.InjectionPoint{Name: "name", Location: input.LocQueryParam}

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
		// === TRUE POSITIVES: Expected result detection ===
		{
			name: "49 from 7*7 jinja2",
			payload: mutator.Payload{Value: "{{7*7}}", Point: point, Module: "ssti", Variant: "jinja2/twig",
				Metadata: map[string]string{"expected": "49"}},
			respBody:     "Hello 49 user",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Hello user",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name: "7777777 from 7*'7' jinja2-confirm",
			payload: mutator.Payload{Value: "{{7*'7'}}", Point: point, Module: "ssti", Variant: "jinja2-confirm",
				Metadata: map[string]string{"expected": "7777777"}},
			respBody:     "Result: 7777777",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Result: nothing",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name: "49 from ${7*7} freemarker",
			payload: mutator.Payload{Value: "${7*7}", Point: point, Module: "ssti", Variant: "freemarker/mvel",
				Metadata: map[string]string{"expected": "49"}},
			respBody:     "Output is 49 here",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Output is nothing here",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name: "uid= from jinja2-rce",
			payload: mutator.Payload{Value: "{{config.__class__}}", Point: point, Module: "ssti", Variant: "jinja2-rce",
				Metadata: map[string]string{"expected": "uid="}},
			respBody:     "uid=1000(user) gid=1000(user)",
			respStatus:   200,
			respTime:     110,
			baseBody:     "normal page",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		// === TRUE POSITIVES: Engine error detection ===
		{
			name: "engine error jinja2.exceptions",
			payload: mutator.Payload{Value: "{{7*7}}", Point: point, Module: "ssti", Variant: "jinja2/twig",
				Metadata: map[string]string{"expected": "49"}},
			respBody:     "jinja2.exceptions.UndefinedError: 'x' is undefined",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal page",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name: "engine error freemarker.core",
			payload: mutator.Payload{Value: "${7*7}", Point: point, Module: "ssti", Variant: "freemarker/mvel",
				Metadata: map[string]string{"expected": "49"}},
			respBody:     "freemarker.core.InvalidReferenceException",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal page",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name: "engine error template syntax error",
			payload: mutator.Payload{Value: "{{7*7}}", Point: point, Module: "ssti", Variant: "jinja2/twig",
				Metadata: map[string]string{"expected": "49"}},
			respBody:     "Template syntax error at line 5",
			respStatus:   500,
			respTime:     110,
			baseBody:     "normal page",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name: "engine error django.template",
			payload: mutator.Payload{Value: "{{7*7}}", Point: point, Module: "ssti", Variant: "jinja2/twig",
				Metadata: map[string]string{"expected": "49"}},
			respBody:     "django.template.exceptions.TemplateSyntaxError",
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
			name: "FP: 49 already in baseline",
			payload: mutator.Payload{Value: "{{7*7}}", Point: point, Module: "ssti", Variant: "jinja2/twig",
				Metadata: map[string]string{"expected": "49"}},
			respBody:     "Product #49 is available",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Product #49 is available",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name: "FP: literal {{7*7}} echoed no eval",
			payload: mutator.Payload{Value: "{{7*7}}", Point: point, Module: "ssti", Variant: "jinja2/twig",
				Metadata: map[string]string{"expected": "49"}},
			respBody:     "You searched for: {{7*7}}",
			respStatus:   200,
			respTime:     110,
			baseBody:     "You searched for: hello",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name: "FP: clean response no expected output",
			payload: mutator.Payload{Value: "{{7*7}}", Point: point, Module: "ssti", Variant: "jinja2/twig",
				Metadata: map[string]string{"expected": "49"}},
			respBody:     "Hello user, welcome back!",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Hello user, welcome back!",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name: "FP: engine error already in baseline",
			payload: mutator.Payload{Value: "{{7*7}}", Point: point, Module: "ssti", Variant: "jinja2/twig",
				Metadata: map[string]string{"expected": "49"}},
			respBody:     "jinja2.exceptions.UndefinedError: 'x' is undefined",
			respStatus:   500,
			respTime:     110,
			baseBody:     "jinja2.exceptions.UndefinedError: 'x' is undefined",
			baseStatus:   500,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name: "FP: no metadata expected empty",
			payload: mutator.Payload{Value: "{{7*7}}", Point: point, Module: "ssti", Variant: "jinja2/twig",
				Metadata: map[string]string{"expected": ""}},
			respBody:     "Hello user",
			respStatus:   200,
			respTime:     110,
			baseBody:     "Hello user",
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
