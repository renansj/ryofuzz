// Package wscheck implements a real WebSocket handshake to detect
// Cross-Site WebSocket Hijacking (CSWSH): a server that completes the
// upgrade handshake for a request bearing a forged cross-origin Origin
// header is not validating the Origin and may be hijackable.
package wscheck

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Result describes the outcome of a CSWSH probe.
type Result struct {
	URL          string
	ForgedOrigin string
	Accepted     bool   // server returned 101 Switching Protocols
	Detail       string
}

// Check performs a WebSocket handshake against wsURL (ws:// or wss://, or
// http(s):// which is upgraded) using a forged Origin and a legitimate-looking
// one, and reports whether the cross-origin handshake was accepted.
func Check(wsURL string, extraHeaders map[string]string, timeout time.Duration) (*Result, error) {
	u, err := url.Parse(wsURL)
	if err != nil {
		return nil, err
	}

	secure := u.Scheme == "wss" || u.Scheme == "https"
	host := u.Host
	if !strings.Contains(host, ":") {
		if secure {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	forgedOrigin := "https://evil.attacker.example"

	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	if secure {
		conn, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	keyBytes := make([]byte, 16)
	rand.Read(keyBytes)
	key := base64.StdEncoding.EncodeToString(keyBytes)

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Key: %s\r\n", key)
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(&b, "Origin: %s\r\n", forgedOrigin)
	for k, v := range extraHeaders {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")

	if _, err := conn.Write([]byte(b.String())); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	res := &Result{URL: wsURL, ForgedOrigin: forgedOrigin}
	if strings.Contains(statusLine, "101") {
		res.Accepted = true
		res.Detail = "Server completed WebSocket upgrade (101) for forged Origin " + forgedOrigin
	} else {
		res.Detail = "Handshake rejected: " + strings.TrimSpace(statusLine)
	}
	return res, nil
}

// NormalizeWSURL converts an http(s) URL to ws(s) scheme for handshake.
func NormalizeWSURL(raw string) string {
	if strings.HasPrefix(raw, "https://") {
		return "wss://" + strings.TrimPrefix(raw, "https://")
	}
	if strings.HasPrefix(raw, "http://") {
		return "ws://" + strings.TrimPrefix(raw, "http://")
	}
	return raw
}
