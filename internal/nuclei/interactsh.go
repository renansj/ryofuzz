package nuclei

// InteractshProvider abstracts the OOB server so the nuclei engine can mint
// unique interactsh URLs and correlate callbacks without importing the oob
// package directly (avoids tight coupling; wired in cmd).
type InteractshProvider interface {
	// NewURL returns a correlation id and the full callback host/URL to embed.
	NewURL() (id string, fullURL string)
	// Poll reports whether a callback was received for id and its protocol
	// ("http"/"dns"), request text, and response text.
	Poll(id string) (proto string, request string, got bool)
}

// oobProvider is the optional, process-wide interactsh provider. When nil,
// {{interactsh-url}} templates are skipped loudly (G9).
var oobProvider InteractshProvider

// SetInteractshProvider wires an OOB provider into the nuclei engine.
func SetInteractshProvider(p InteractshProvider) { oobProvider = p }

// templateUsesInteractsh reports whether any request references interactsh.
func (t *Template) templateUsesInteractsh() bool {
	for _, r := range t.AllRequests() {
		blob := r.Body + strings_join(r.Path) + strings_join(r.Raw)
		for k, v := range r.Headers {
			blob += k + v
		}
		if containsInteractsh(blob) {
			return true
		}
		for _, m := range r.Matchers {
			for _, w := range m.Words {
				blob += w
			}
			for _, d := range m.DSL {
				blob += d
			}
			if m.Part == "interactsh_protocol" || m.Part == "interactsh_request" {
				return true
			}
		}
		if containsInteractsh(blob) {
			return true
		}
	}
	return false
}

func containsInteractsh(s string) bool {
	return indexOfStr(s, "interactsh-url") >= 0 || indexOfStr(s, "interactsh_") >= 0
}

func strings_join(arr []string) string {
	out := ""
	for _, a := range arr {
		out += a
	}
	return out
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
