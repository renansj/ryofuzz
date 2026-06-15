package browser

import (
	"context"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// allocFor builds an exec allocator with auth headers applied.
func (s *DOMScanner) newAllocator() (context.Context, context.CancelFunc) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
	)
	return chromedp.NewExecAllocator(context.Background(), opts...)
}

func (s *DOMScanner) authAction() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		if len(s.extraHeaders) > 0 {
			_ = network.Enable().Do(ctx)
			_ = network.SetExtraHTTPHeaders(network.Headers(s.extraHeaders)).Do(ctx)
		}
		return nil
	})
}

// ScanCSTI tests for Client-Side Template Injection (AngularJS, Vue mustache).
// It injects template expressions and checks whether they are evaluated in the
// rendered DOM (49 from 7*7) or whether sandbox-escape execution fires.
func (s *DOMScanner) ScanCSTI(targetURL string, params []string) []DOMFinding {
	var findings []DOMFinding
	allocCtx, allocCancel := s.newAllocator()
	defer allocCancel()

	payloads := []struct {
		value  string
		marker string
		exec   bool
	}{
		{"{{7*7}}", "49", false},
		{"{{constructor.constructor('window.RYOCSTI=true')()}}", "", true},
		{"{{$on.constructor('window.RYOCSTI=true')()}}", "", true},
		{"${7*7}", "49", false},
	}

	for _, param := range params {
		for _, p := range payloads {
			testURL := injectPayload(targetURL, param, p.value, false)
			ctx, cancel := chromedp.NewContext(allocCtx)
			tCtx, tCancel := context.WithTimeout(ctx, 10*time.Second)

			var executed bool
			var domText string
			err := chromedp.Run(tCtx,
				s.authAction(),
				chromedp.ActionFunc(func(ctx context.Context) error {
					_, _, e := runtime_evaluate(ctx, `window.RYOCSTI=false;`)
					return e
				}),
				chromedp.Navigate(testURL),
				chromedp.Sleep(2*time.Second),
				chromedp.Evaluate(`window.RYOCSTI === true`, &executed),
				chromedp.Evaluate(`document.body ? document.body.innerText : ""`, &domText),
			)
			tCancel()
			cancel()
			if err != nil {
				continue
			}

			hit := false
			sink := "template-eval"
			if p.exec && executed {
				hit = true
				sink = "sandbox-escape"
			} else if !p.exec && p.marker != "" && containsRendered(domText, p.marker, p.value) {
				hit = true
			}
			if hit {
				findings = append(findings, DOMFinding{
					URL: testURL, Param: param, Sink: sink, Payload: p.value, Executed: p.exec && executed,
				})
			}
		}
	}
	return findings
}

// ScanDOMClobbering tests whether injected HTML id/name attributes can clobber
// JavaScript global variables (a sanitizer-bypass primitive).
func (s *DOMScanner) ScanDOMClobbering(targetURL string, params []string) []DOMFinding {
	var findings []DOMFinding
	allocCtx, allocCancel := s.newAllocator()
	defer allocCancel()

	for _, param := range params {
		payload := `<a id=RYOCLOB name=RYOCLOB href="ryo"></a>`
		testURL := injectPayload(targetURL, param, payload, false)
		ctx, cancel := chromedp.NewContext(allocCtx)
		tCtx, tCancel := context.WithTimeout(ctx, 10*time.Second)

		var clobbered bool
		err := chromedp.Run(tCtx,
			s.authAction(),
			chromedp.Navigate(testURL),
			chromedp.Sleep(2*time.Second),
			// If window.RYOCLOB is an element, the global was clobbered by our markup
			chromedp.Evaluate(`(function(){var x=window.RYOCLOB; return x && (x instanceof Element || (x.length && x[0] instanceof Element));})()`, &clobbered),
		)
		tCancel()
		cancel()
		if err == nil && clobbered {
			findings = append(findings, DOMFinding{
				URL: testURL, Param: param, Sink: "dom-clobbering", Payload: payload, Executed: false,
			})
		}
	}
	return findings
}

// ScanPostMessage tests for postMessage handlers that do not validate origin.
// It dispatches a forged-origin message and observes whether a sink fires.
func (s *DOMScanner) ScanPostMessage(targetURL string) []DOMFinding {
	var findings []DOMFinding
	allocCtx, allocCancel := s.newAllocator()
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	tCtx, tCancel := context.WithTimeout(ctx, 12*time.Second)
	defer tCancel()
	defer cancel()

	hookJS := `
		window.RYOPM = false;
		window.__ryoHadListener = false;
		var origAdd = window.addEventListener;
		window.addEventListener = function(type, fn, opts){
			if(type === 'message'){ window.__ryoHadListener = true; }
			return origAdd.call(window, type, fn, opts);
		};
		var origAlert = window.alert;
		window.alert = function(){ window.RYOPM = true; };
		var d = document.write;
		document.write = function(s){ if(s && (''+s).indexOf('RYOPM')!==-1){ window.RYOPM = true; } return d.call(document, s); };
	`
	sendForged := `window.postMessage('RYOPM_<img src=x onerror=alert(1)>', '*');`

	var hadListener, fired bool
	err := chromedp.Run(tCtx,
		s.authAction(),
		chromedp.ActionFunc(func(ctx context.Context) error { _, _, e := runtime_evaluate(ctx, hookJS); return e }),
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2*time.Second),
		chromedp.Evaluate(`window.__ryoHadListener === true`, &hadListener),
		chromedp.ActionFunc(func(ctx context.Context) error { _, _, e := runtime_evaluate(ctx, sendForged); return e }),
		chromedp.Sleep(1*time.Second),
		chromedp.Evaluate(`window.RYOPM === true`, &fired),
	)
	if err != nil {
		return findings
	}
	if fired {
		findings = append(findings, DOMFinding{
			URL: targetURL, Param: "postMessage", Sink: "postMessage-handler", Payload: "forged-origin message", Executed: true,
		})
	} else if hadListener {
		// Listener present but no origin check observed in our probe: report as low-confidence
		findings = append(findings, DOMFinding{
			URL: targetURL, Param: "postMessage", Sink: "message-listener (review origin check)", Payload: "listener present", Executed: false,
		})
	}
	return findings
}

// ScanCSPT tests for Client-Side Path Traversal: a ../ payload in a parameter
// that influences a client-side fetch/XHR URL.
func (s *DOMScanner) ScanCSPT(targetURL string, params []string) []DOMFinding {
	var findings []DOMFinding
	allocCtx, allocCancel := s.newAllocator()
	defer allocCancel()

	for _, param := range params {
		payload := "..%2f..%2fryocspt"
		testURL := injectPayload(targetURL, param, payload, false)
		ctx, cancel := chromedp.NewContext(allocCtx)
		tCtx, tCancel := context.WithTimeout(ctx, 10*time.Second)

		hookJS := `
			window.__ryoFetches = [];
			var of = window.fetch;
			window.fetch = function(u){ try{ window.__ryoFetches.push(''+u); }catch(e){} return of.apply(this, arguments); };
			var ox = window.XMLHttpRequest.prototype.open;
			window.XMLHttpRequest.prototype.open = function(m, u){ try{ window.__ryoFetches.push(''+u); }catch(e){} return ox.apply(this, arguments); };
		`
		var fetches []string
		err := chromedp.Run(tCtx,
			s.authAction(),
			chromedp.ActionFunc(func(ctx context.Context) error { _, _, e := runtime_evaluate(ctx, hookJS); return e }),
			chromedp.Navigate(testURL),
			chromedp.Sleep(2*time.Second),
			chromedp.Evaluate(`window.__ryoFetches || []`, &fetches),
		)
		tCancel()
		cancel()
		if err != nil {
			continue
		}
		for _, f := range fetches {
			if containsAny(f, "ryocspt", "../", "..%2f") {
				findings = append(findings, DOMFinding{
					URL: testURL, Param: param, Sink: "client-fetch: " + f, Payload: payload, Executed: false,
				})
				break
			}
		}
	}
	return findings
}

func containsRendered(domText, marker, rawPayload string) bool {
	// marker must appear in rendered text but the literal payload must NOT
	// (otherwise it is just reflected, not evaluated)
	return indexOf(domText, marker) >= 0 && indexOf(domText, rawPayload) < 0
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	if sub == "" {
		return 0
	}
	return -1
}

var _ = time.Second
