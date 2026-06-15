package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestSmokeAllModules_NoPanic(t *testing.T) {
	modules := Select([]string{"all"})
	if len(modules) == 0 {
		t.Fatal("Select('all') returned no modules")
	}

	point := input.InjectionPoint{
		Name:          "test_param",
		Location:      input.LocQueryParam,
		OriginalValue: "value123",
		Method:        "GET",
	}

	for _, mod := range modules {
		t.Run(mod.Name(), func(t *testing.T) {
			// GeneratePayloads must not panic
			payloads := mod.GeneratePayloads([]input.InjectionPoint{point}, "normal", 1)

			// Detect must not panic with empty inputs
			f := mod.Detect(
				mutator.Payload{Value: "test", Point: point, Module: mod.Name(), Variant: "smoke"},
				"", 200, 100,
				"", 200, 100,
				map[string][]string{},
			)
			// Result can be nil (no finding) - that is fine
			_ = f
			_ = payloads
		})
	}
}

func TestSmokeAllModules_DetectWithPayloads(t *testing.T) {
	modules := Select([]string{"all"})

	point := input.InjectionPoint{
		Name:          "id",
		Location:      input.LocQueryParam,
		OriginalValue: "1",
		Method:        "POST",
	}

	for _, mod := range modules {
		t.Run(mod.Name()+"_payloads", func(t *testing.T) {
			payloads := mod.GeneratePayloads([]input.InjectionPoint{point}, "normal", 1)
			for _, p := range payloads {
				// Must not panic
				_ = mod.Detect(p, "baseline body", 200, 100, "response body", 200, 100, nil)
			}
		})
	}
}
