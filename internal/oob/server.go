package oob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OOBCallback represents a received out-of-band callback.
type OOBCallback struct {
	Token     string            `json:"token"`
	Payload   string            `json:"payload"`
	Module    string            `json:"module"`
	Point     string            `json:"point"`
	Timestamp time.Time         `json:"timestamp"`
	RemoteIP  string            `json:"remote_ip"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
}

// TokenInfo holds metadata about a generated token.
type TokenInfo struct {
	Token   string
	Payload string
	Module  string
	Point   string
}

// Config holds OOB server configuration.
type Config struct {
	Listen string // listen address (default ":8888")
	Domain string // external domain/IP
	Mode   string // local, ngrok, private
}

// Manager manages OOB token generation, serving, and callback correlation.
type Manager struct {
	cfg       Config
	mu        sync.RWMutex
	tokens    map[string]*TokenInfo
	callbacks []OOBCallback
	server    *http.Server
	domain    string // resolved external domain (may differ from cfg.Domain for ngrok)
}

// NewManager creates a new OOB Manager with the given config.
func NewManager(cfg Config) *Manager {
	if cfg.Listen == "" {
		cfg.Listen = ":8888"
	}
	if cfg.Mode == "" {
		cfg.Mode = "local"
	}
	return &Manager{
		cfg:       cfg,
		tokens:    make(map[string]*TokenInfo),
		callbacks: make([]OOBCallback, 0),
	}
}

// Start starts the OOB HTTP server and resolves the external domain.
func (m *Manager) Start() error {
	if err := m.resolveDomain(); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", m.handleHealth)
	mux.HandleFunc("/callbacks", m.handleCallbacks)
	mux.HandleFunc("/t/", m.handleToken)

	m.server = &http.Server{
		Addr:    m.cfg.Listen,
		Handler: mux,
	}

	go m.server.ListenAndServe()
	return nil
}

// Stop gracefully shuts down the server.
func (m *Manager) Stop() {
	if m.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		m.server.Shutdown(ctx)
	}
}

// GenerateToken creates a unique token associated with a payload/module/point.
func (m *Manager) GenerateToken(payload, module, point string) string {
	b := make([]byte, 16)
	rand.Read(b)
	token := hex.EncodeToString(b)

	m.mu.Lock()
	m.tokens[token] = &TokenInfo{
		Token:   token,
		Payload: payload,
		Module:  module,
		Point:   point,
	}
	m.mu.Unlock()
	return token
}

// GenerateURL creates the full OOB callback URL for a token.
func (m *Manager) GenerateURL(payload, module, point string) string {
	token := m.GenerateToken(payload, module, point)
	return fmt.Sprintf("http://%s/t/%s", m.domain, token)
}

// GetCallbacks returns all received callbacks.
func (m *Manager) GetCallbacks() []OOBCallback {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]OOBCallback, len(m.callbacks))
	copy(result, m.callbacks)
	return result
}

// GetCallbacksForToken returns callbacks matching a specific token.
func (m *Manager) GetCallbacksForToken(token string) []OOBCallback {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []OOBCallback
	for _, cb := range m.callbacks {
		if cb.Token == token {
			result = append(result, cb)
		}
	}
	return result
}

// HasCallback checks if any callback was received for the given token.
func (m *Manager) HasCallback(token string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, cb := range m.callbacks {
		if cb.Token == token {
			return true
		}
	}
	return false
}

// Domain returns the resolved external domain.
func (m *Manager) Domain() string {
	return m.domain
}

func (m *Manager) resolveDomain() error {
	switch m.cfg.Mode {
	case "ngrok":
		url, err := GetNgrokURL()
		if err != nil {
			return fmt.Errorf("ngrok mode: %w\nEnsure ngrok is running: ngrok http %s", err, m.cfg.Listen)
		}
		m.domain = strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	case "private":
		if m.cfg.Domain == "" {
			return fmt.Errorf("private mode requires --oob-domain")
		}
		m.domain = m.cfg.Domain
	default: // local
		port := strings.TrimPrefix(m.cfg.Listen, ":")
		if strings.Contains(m.cfg.Listen, ":") && !strings.HasPrefix(m.cfg.Listen, ":") {
			m.domain = m.cfg.Listen
		} else {
			m.domain = "127.0.0.1:" + port
		}
	}
	return nil
}

func (m *Manager) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "domain": m.domain})
}

func (m *Manager) handleCallbacks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m.GetCallbacks())
}

func (m *Manager) handleToken(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/t/")
	if token == "" {
		http.NotFound(w, r)
		return
	}

	m.mu.RLock()
	info, exists := m.tokens[token]
	m.mu.RUnlock()

	cb := OOBCallback{
		Token:     token,
		Timestamp: time.Now(),
		RemoteIP:  r.RemoteAddr,
		Method:    r.Method,
		Path:      r.URL.Path,
		Headers:   make(map[string]string),
	}

	for k, v := range r.Header {
		cb.Headers[k] = strings.Join(v, ", ")
	}

	if r.Body != nil {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		cb.Body = string(body)
	}

	if exists {
		cb.Payload = info.Payload
		cb.Module = info.Module
		cb.Point = info.Point
	}

	m.mu.Lock()
	m.callbacks = append(m.callbacks, cb)
	m.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}
