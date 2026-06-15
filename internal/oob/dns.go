package oob

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSServer captures DNS queries for OOB correlation.
type DNSServer struct {
	port    int
	domain  string
	manager *Manager
	server  *dns.Server
}

// NewDNSServer creates a DNS listener bound to the given manager.
func NewDNSServer(port int, domain string, manager *Manager) *DNSServer {
	return &DNSServer{port: port, domain: domain, manager: manager}
}

// Start begins listening for DNS queries on UDP.
func (d *DNSServer) Start() error {
	d.server = &dns.Server{
		Addr: fmt.Sprintf(":%d", d.port),
		Net:  "udp",
	}
	dns.HandleFunc(".", d.handleQuery)
	go d.server.ListenAndServe()
	return nil
}

// Stop shuts down the DNS server.
func (d *DNSServer) Stop() {
	if d.server != nil {
		d.server.Shutdown()
	}
}

func (d *DNSServer) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		name := strings.TrimSuffix(q.Name, ".")
		// Extract token: first label of token.domain
		token := ""
		if d.domain != "" {
			suffix := "." + d.domain
			if strings.HasSuffix(name, suffix) {
				token = strings.TrimSuffix(name, suffix)
			}
		}
		if token == "" {
			parts := strings.SplitN(name, ".", 2)
			token = parts[0]
		}

		// Correlate with token map
		d.manager.mu.RLock()
		info, exists := d.manager.tokens[token]
		d.manager.mu.RUnlock()

		cb := OOBCallback{
			Token:     token,
			Timestamp: time.Now(),
			RemoteIP:  w.RemoteAddr().String(),
			Method:    "DNS",
			Path:      name,
			Headers:   make(map[string]string),
		}
		cb.Headers["qtype"] = dns.TypeToString[q.Qtype]

		if exists {
			cb.Payload = info.Payload
			cb.Module = info.Module
			cb.Point = info.Point
		}

		d.manager.mu.Lock()
		d.manager.callbacks = append(d.manager.callbacks, cb)
		d.manager.mu.Unlock()

		// Reply with a dummy A record so the resolver is satisfied
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(127, 0, 0, 1),
			}
			m.Answer = append(m.Answer, rr)
		}
	}

	w.WriteMsg(m)
}
