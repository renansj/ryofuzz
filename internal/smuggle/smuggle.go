// Package smuggle implements time-based HTTP request smuggling detection
// (CL.TE and TE.CL desync) using raw sockets, because net/http normalizes and
// forbids the conflicting Content-Length / Transfer-Encoding headers required.
//
// Method follows the standard time-based technique: a crafted request that
// desyncs a vulnerable front-end/back-end pair leaves the back-end waiting for
// more data, producing a measurable delay. A control request establishes the
// baseline latency.
package smuggle

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

type Result struct {
	URL      string
	Variant  string // "CL.TE" or "TE.CL"
	Delayed  bool
	BaseMs   int64
	ProbeMs  int64
	Detail   string
}

// dialRaw opens a raw TCP/TLS connection to the host of the URL.
func dialRaw(u *url.URL, timeout time.Duration) (net.Conn, error) {
	secure := u.Scheme == "https"
	host := u.Host
	if !strings.Contains(host, ":") {
		if secure {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	d := &net.Dialer{Timeout: timeout}
	if secure {
		return tls.DialWithDialer(d, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	}
	return d.Dial("tcp", host)
}

// sendRaw writes a raw request and times how long until first response bytes
// (or timeout). Returns elapsed milliseconds and whether it timed out.
func sendRaw(u *url.URL, raw string, timeout time.Duration) (int64, bool) {
	conn, err := dialRaw(u, timeout)
	if err != nil {
		return 0, false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	if _, err := conn.Write([]byte(raw)); err != nil {
		return 0, false
	}
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	elapsed := time.Since(start).Milliseconds()
	timedOut := false
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			timedOut = true
		}
	}
	return elapsed, timedOut
}

// Check runs CL.TE and TE.CL time-based probes against the target.
func Check(rawURL string, timeout time.Duration) ([]Result, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	host := u.Host

	// Baseline: a normal request latency
	baseReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	baseMs, _ := sendRaw(u, baseReq, timeout)

	var results []Result

	// CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding.
	// The back-end reads the chunked body, sees the "1\r\nA\r\n" chunk, then
	// waits for the next chunk that never arrives -> delay.
	clte := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nX",
		path, host)
	clteMs, clteTimeout := sendRaw(u, clte, timeout)
	if clteTimeout || clteMs > baseMs+4000 {
		results = append(results, Result{
			URL: rawURL, Variant: "CL.TE", Delayed: true, BaseMs: baseMs, ProbeMs: clteMs,
			Detail: fmt.Sprintf("CL.TE probe delayed (base %dms, probe %dms, timeout=%v)", baseMs, clteMs, clteTimeout),
		})
	}

	// TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length.
	tecl := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
		path, host)
	teclMs, teclTimeout := sendRaw(u, tecl, timeout)
	if teclTimeout || teclMs > baseMs+4000 {
		results = append(results, Result{
			URL: rawURL, Variant: "TE.CL", Delayed: true, BaseMs: baseMs, ProbeMs: teclMs,
			Detail: fmt.Sprintf("TE.CL probe delayed (base %dms, probe %dms, timeout=%v)", baseMs, teclMs, teclTimeout),
		})
	}

	return results, nil
}
