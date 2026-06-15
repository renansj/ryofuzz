package browser

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// DOMFinding represents a client-side XSS finding
type DOMFinding struct {
	URL      string
	Param    string
	Sink     string
	Payload  string
	Executed bool
}

// DOMScanner performs headless browser DOM XSS detection
type DOMScanner struct {
	// extraHeaders are applied to every navigation (auth/session propagation)
	extraHeaders map[string]interface{}
}

// SetAuth configures headers and cookies propagated into the browser so DOM
// scanning works against authenticated pages.
func (s *DOMScanner) SetAuth(headers []string, cookies string) {
	if s.extraHeaders == nil {
		s.extraHeaders = make(map[string]interface{})
	}
	for _, h := range headers {
		parts := splitHeader(h)
		if parts != nil {
			s.extraHeaders[parts[0]] = parts[1]
		}
	}
	if cookies != "" {
		s.extraHeaders["Cookie"] = cookies
	}
}

func splitHeader(h string) []string {
	for i := 0; i < len(h); i++ {
		if h[i] == ':' {
			name := h[:i]
			val := h[i+1:]
			for len(val) > 0 && (val[0] == ' ' || val[0] == '\t') {
				val = val[1:]
			}
			return []string{name, val}
		}
	}
	return nil
}

// ScanDOMXSS launches headless chromium and tests for DOM-based XSS
func (s *DOMScanner) ScanDOMXSS(targetURL string, params []string) []DOMFinding {
	var findings []DOMFinding

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	// Canary payload that sets window.RYOXSS=true
	canaryScript := `<img src=x onerror="window.RYOXSS=true">`

	for _, param := range params {
		// Test in query param
		for _, inFragment := range []bool{false, true} {
			payload := canaryScript
			testURL := injectPayload(targetURL, param, payload, inFragment)

			ctx, cancel := chromedp.NewContext(allocCtx)
			tCtx, tCancel := context.WithTimeout(ctx, 10*time.Second)

			// Hook script to intercept sinks
			hookJS := `
				window.RYOXSS = false;
				window.__ryoSinks = [];
				(function(){
					var origAlert = window.alert;
					window.alert = function(m){ window.RYOXSS = true; window.__ryoSinks.push('alert'); };
					var origEval = window.eval;
					window.eval = function(s){ window.RYOXSS = true; window.__ryoSinks.push('eval'); return origEval(s); };
					var origWrite = document.write;
					document.write = function(s){
						if(s && s.indexOf('RYOXSS')!==-1){ window.RYOXSS = true; window.__ryoSinks.push('document.write'); }
						return origWrite.call(document, s);
					};
				})();
			`

			var executed bool
			var sinks string
			err := chromedp.Run(tCtx,
				chromedp.ActionFunc(func(ctx context.Context) error {
					if len(s.extraHeaders) > 0 {
						_ = network.Enable().Do(ctx)
						_ = network.SetExtraHTTPHeaders(network.Headers(s.extraHeaders)).Do(ctx)
					}
					return nil
				}),
				chromedp.ActionFunc(func(ctx context.Context) error {
					_, exp, err := runtime_evaluate(ctx, hookJS)
					_ = exp
					return err
				}),
				chromedp.Navigate(testURL),
				chromedp.Sleep(2*time.Second),
				chromedp.Evaluate(`window.RYOXSS === true`, &executed),
				chromedp.Evaluate(`(window.__ryoSinks || []).join(',')`, &sinks),
			)

			tCancel()
			cancel()

			if err != nil {
				continue
			}

			if executed {
				sink := "dom"
				if sinks != "" {
					sink = sinks
				}
				loc := "query"
				if inFragment {
					loc = "fragment"
				}
				findings = append(findings, DOMFinding{
					URL:      testURL,
					Param:    param + " (" + loc + ")",
					Sink:     sink,
					Payload:  payload,
					Executed: true,
				})
			} else {
				// Check if payload reached innerHTML (DOM sink without execution)
				var inDOM bool
				ctx2, cancel2 := chromedp.NewContext(allocCtx)
				tCtx2, tCancel2 := context.WithTimeout(ctx2, 10*time.Second)
				err := chromedp.Run(tCtx2,
					chromedp.Navigate(testURL),
					chromedp.Sleep(2*time.Second),
					chromedp.Evaluate(`document.body.innerHTML.indexOf('RYOXSS') !== -1`, &inDOM),
				)
				tCancel2()
				cancel2()
				if err == nil && inDOM {
					loc := "query"
					if inFragment {
						loc = "fragment"
					}
					findings = append(findings, DOMFinding{
						URL:      testURL,
						Param:    param + " (" + loc + ")",
						Sink:     "innerHTML",
						Payload:  payload,
						Executed: false,
					})
				}
			}
		}
	}

	return findings
}

func injectPayload(targetURL, param, payload string, fragment bool) string {
	if fragment {
		return targetURL + "#" + param + "=" + url.QueryEscape(payload)
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

func runtime_evaluate(ctx context.Context, expr string) (interface{}, interface{}, error) {
	var res interface{}
	err := chromedp.Evaluate(expr, &res).Do(ctx)
	return res, nil, err
}

// Available checks if chromium is accessible
func Available() bool {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),
	)
	ctx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	bCtx, bCancel := chromedp.NewContext(ctx)
	defer bCancel()
	tCtx, tCancel := context.WithTimeout(bCtx, 5*time.Second)
	defer tCancel()
	err := chromedp.Run(tCtx, chromedp.Navigate("about:blank"))
	return err == nil
}

// FormatSeverity returns severity based on whether XSS executed
func FormatSeverity(executed bool) string {
	if executed {
		return "critical"
	}
	return "high"
}

// FormatConfidence returns confidence string
func FormatConfidence(executed bool) string {
	if executed {
		return "confirmed"
	}
	return "high"
}

// init prints nothing - scanner is opt-in via --browser
func init() {
	_ = fmt.Sprintf // ensure fmt is used
}
