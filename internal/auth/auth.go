package auth

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type AuthConfig struct {
	Method      string // basic, bearer, form, cookie, custom
	Username    string
	Password    string
	Token       string
	LoginURL    string
	LoginBody   string
	TokenField  string // campo no JSON de resposta que contém o token
	TokenHeader string // header onde enviar o token (default: Authorization)
	TokenPrefix string // prefixo (default: Bearer)
	CookieName  string
	RefreshURL  string
	RefreshBody string
}

type Session struct {
	Token     string
	Cookies   []*http.Cookie
	ExpiresAt time.Time
	Config    AuthConfig
	Client    *http.Client
	mu        sync.Mutex
}

// Login cria uma sessão autenticada baseada na configuração.
func Login(config AuthConfig) (*Session, error) {
	s := &Session{
		Config: config,
		Client: &http.Client{Timeout: 10 * time.Second},
	}

	switch config.Method {
	case "basic":
		s.Token = base64.StdEncoding.EncodeToString([]byte(config.Username + ":" + config.Password))
	case "bearer":
		s.Token = config.Token
	case "form":
		if err := s.doLogin(); err != nil {
			return nil, err
		}
	case "cookie":
		s.Cookies = []*http.Cookie{{Name: config.CookieName, Value: config.Token}}
	case "custom":
		s.Token = config.Token
	}

	return s, nil
}

func (s *Session) doLogin() error {
	req, err := http.NewRequest("POST", s.Config.LoginURL, strings.NewReader(s.Config.LoginBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Extrair cookies da resposta
	if len(resp.Cookies()) > 0 {
		s.Cookies = resp.Cookies()
	}

	// Extrair token do corpo JSON se TokenField configurado
	if s.Config.TokenField != "" {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err == nil {
			if val, ok := data[s.Config.TokenField]; ok {
				s.Token = val.(string)
			}
		}
	}

	s.ExpiresAt = time.Now().Add(30 * time.Minute)
	return nil
}

// ApplyAuth injeta autenticação no request.
func (s *Session) ApplyAuth(req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.Config.Method {
	case "basic":
		req.Header.Set("Authorization", "Basic "+s.Token)
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+s.Token)
	case "form":
		header := s.Config.TokenHeader
		if header == "" {
			header = "Authorization"
		}
		prefix := s.Config.TokenPrefix
		if prefix == "" {
			prefix = "Bearer"
		}
		if s.Token != "" {
			req.Header.Set(header, prefix+" "+s.Token)
		}
		for _, c := range s.Cookies {
			req.AddCookie(c)
		}
	case "cookie":
		for _, c := range s.Cookies {
			req.AddCookie(c)
		}
	case "custom":
		header := s.Config.TokenHeader
		if header == "" {
			header = "X-API-Key"
		}
		req.Header.Set(header, s.Token)
	}
}

// IsExpired detecta se a sessão expirou baseado na resposta.
func (s *Session) IsExpired(resp *http.Response) bool {
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return true
	}
	// Detectar redirect para login page
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, "login") || strings.Contains(loc, "signin") || strings.Contains(loc, "auth") {
			return true
		}
	}
	if !s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt) {
		return true
	}
	return false
}

// Refresh tenta renovar a sessão.
func (s *Session) Refresh() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Config.RefreshURL != "" {
		req, err := http.NewRequest("POST", s.Config.RefreshURL, strings.NewReader(s.Config.RefreshBody))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if s.Token != "" {
			prefix := s.Config.TokenPrefix
			if prefix == "" {
				prefix = "Bearer"
			}
			header := s.Config.TokenHeader
			if header == "" {
				header = "Authorization"
			}
			req.Header.Set(header, prefix+" "+s.Token)
		}
		for _, c := range s.Cookies {
			req.AddCookie(c)
		}

		resp, err := s.Client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if s.Config.TokenField != "" {
			body, _ := io.ReadAll(resp.Body)
			var data map[string]interface{}
			if err := json.Unmarshal(body, &data); err == nil {
				if val, ok := data[s.Config.TokenField]; ok {
					s.Token = val.(string)
				}
			}
		}
		if len(resp.Cookies()) > 0 {
			s.Cookies = resp.Cookies()
		}
		s.ExpiresAt = time.Now().Add(30 * time.Minute)
		return nil
	}

	// Fallback: re-login
	if s.Config.Method == "form" {
		return s.doLogin()
	}
	return nil
}

// AuthManager gerencia autenticação para o fuzzer.
type AuthManager struct {
	Session *Session
	mu      sync.Mutex
}

// NewAuthManager cria um manager autenticado.
func NewAuthManager(config AuthConfig) (*AuthManager, error) {
	session, err := Login(config)
	if err != nil {
		return nil, err
	}
	return &AuthManager{Session: session}, nil
}

// Apply injeta auth no request, com refresh automático se expirado.
func (am *AuthManager) Apply(req *http.Request) {
	am.Session.ApplyAuth(req)
}

// HandleResponse verifica expiração e faz refresh se necessário.
func (am *AuthManager) HandleResponse(resp *http.Response) error {
	if am.Session.IsExpired(resp) {
		am.mu.Lock()
		defer am.mu.Unlock()
		return am.Session.Refresh()
	}
	return nil
}

// GetCookieString retorna cookies formatados para uso em header Cookie.
func (s *Session) GetCookieString() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var parts []string
	for _, c := range s.Cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// GetAuthHeaders retorna headers com autenticação injetada.
func (s *Session) GetAuthHeaders(existing []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]string, len(existing))
	copy(result, existing)

	switch s.Config.Method {
	case "basic":
		result = append(result, "Authorization: Basic "+s.Token)
	case "bearer":
		prefix := s.Config.TokenPrefix
		if prefix == "" {
			prefix = "Bearer"
		}
		header := s.Config.TokenHeader
		if header == "" {
			header = "Authorization"
		}
		result = append(result, header+": "+prefix+" "+s.Token)
	case "custom":
		header := s.Config.TokenHeader
		if header == "" {
			header = "X-API-Key"
		}
		result = append(result, header+": "+s.Token)
	}
	return result
}
