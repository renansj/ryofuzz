package nuclei

import "fmt"

// Capability reports whether a template can be fully evaluated by this engine.
// Per G9, unsupported templates must be skipped loudly, never silently, and
// never produce a half-evaluated (possibly wrong) match.

// SupportedDSLOnly is set false until the DSL engine covers a template's needs;
// the engine checks individual functions at evaluation time.

// CheckCapability returns ("", true) if the template is fully supported, or a
// reason and false if it must be skipped.
func (t *Template) CheckCapability() (string, bool) {
	// Protocols not implemented as executable (parsed only for gating).
	if len(t.Code) > 0 {
		return "code: protocol not supported (local code execution)", false
	}
	if len(t.JavaScript) > 0 {
		return "javascript: protocol not supported (goja network scripts)", false
	}
	if t.Flow != "" {
		return "flow: JS orchestration not supported", false
	}
	if len(t.Headless) > 0 {
		return "headless: protocol not supported in nuclei engine", false
	}
	if len(t.DNS) > 0 || len(t.TCP) > 0 || len(t.SSL) > 0 || len(t.File) > 0 {
		return "non-http protocol (dns/tcp/ssl/file) not yet supported", false
	}
	if len(t.AllRequests()) == 0 {
		return "no http request block", false
	}

	// Per-request feature gating.
	for _, r := range t.AllRequests() {
		if r.Pipeline {
			return "http pipelining not supported", false
		}
		// raw + unsafe is supported (byte fidelity); plain unsafe alone is ok.
		for _, m := range r.Matchers {
			switch m.Type {
			case "word", "regex", "status", "size", "binary", "dsl", "xpath", "":
				// supported
			default:
				return fmt.Sprintf("matcher type %q not supported", m.Type), false
			}
			// DSL matchers: verify all referenced helper functions exist.
			if m.Type == "dsl" {
				for _, expr := range m.DSL {
					if fn, ok := unknownDSLFunction(expr); !ok {
						return fmt.Sprintf("dsl function %q not implemented", fn), false
					}
				}
			}
		}
		for _, e := range r.Extractors {
			switch e.Type {
			case "regex", "kval", "json", "xpath", "dsl", "":
				// supported
			default:
				return fmt.Sprintf("extractor type %q not supported", e.Type), false
			}
		}
	}
	return "", true
}
