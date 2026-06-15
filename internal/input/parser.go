package input

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Location indicates where the injection point is
type Location string

const (
	LocQueryParam Location = "query"
	LocJSONBody   Location = "json_body"
	LocFormBody   Location = "form_body"
	LocPath       Location = "path"
	LocHeader     Location = "header"
	LocCookie     Location = "cookie"
)

// InjectionPoint represents a detected injection point
type InjectionPoint struct {
	Name          string
	Location      Location
	OriginalValue string
	Method        string
	JSONPath      string // para nested JSON: "user.profile.name"
}

// Parse detecta automaticamente todos os injection points
func Parse(rawURL, method, body string, headers []string, cookies string) ([]InjectionPoint, error) {
	var points []InjectionPoint

	// Auto-detectar método
	if method == "" {
		if body != "" {
			method = "POST"
		} else {
			method = "GET"
		}
	}

	// 1. Query params
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("URL inválida: %w", err)
	}
	for key, values := range parsed.Query() {
		for _, val := range values {
			points = append(points, InjectionPoint{
				Name:          key,
				Location:      LocQueryParam,
				OriginalValue: val,
				Method:        method,
			})
		}
	}

	// 2. Path segments (detectar valores dinâmicos)
	segments := strings.Split(parsed.Path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		// Heurística: segmentos numéricos ou UUIDs são provavelmente parâmetros
		if looksLikeParam(seg) {
			points = append(points, InjectionPoint{
				Name:          fmt.Sprintf("path_segment_%d", i),
				Location:      LocPath,
				OriginalValue: seg,
				Method:        method,
			})
		}
	}

	// 3. Body
	if body != "" {
		bodyPoints := parseBody(body, method)
		points = append(points, bodyPoints...)
	}

	// 4. Headers customizados com valores
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			// Não fuzzear Content-Type e similares por default
			if !isStructuralHeader(name) {
				points = append(points, InjectionPoint{
					Name:          name,
					Location:      LocHeader,
					OriginalValue: val,
					Method:        method,
				})
			}
		}
	}

	// 5. Cookies
	if cookies != "" {
		cookiePairs := strings.Split(cookies, ";")
		for _, pair := range cookiePairs {
			parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(parts) == 2 {
				points = append(points, InjectionPoint{
					Name:          strings.TrimSpace(parts[0]),
					Location:      LocCookie,
					OriginalValue: strings.TrimSpace(parts[1]),
					Method:        method,
				})
			}
		}
	}

	if len(points) == 0 {
		// No per-parameter injection points. Return an empty slice (not an
		// error) so host-level modules (infoleak, csrf, takeover, clickjack,
		// session, headers) still run against the target.
		return []InjectionPoint{}, nil
	}

	return points, nil
}

func parseBody(body, method string) []InjectionPoint {
	var points []InjectionPoint

	// Tentar JSON primeiro
	body = strings.TrimSpace(body)
	if strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") {
		points = parseJSON(body, "", method)
		if len(points) > 0 {
			return points
		}
	}

	// URL-encoded
	values, err := url.ParseQuery(body)
	if err == nil && len(values) > 0 {
		for key, vals := range values {
			for _, val := range vals {
				points = append(points, InjectionPoint{
					Name:          key,
					Location:      LocFormBody,
					OriginalValue: val,
					Method:        method,
				})
			}
		}
		return points
	}

	// Body raw (tratar como valor único)
	points = append(points, InjectionPoint{
		Name:          "body",
		Location:      LocFormBody,
		OriginalValue: body,
		Method:        method,
	})
	return points
}

// parseJSON extrai todos os valores de um JSON recursivamente
func parseJSON(data string, prefix string, method string) []InjectionPoint {
	var points []InjectionPoint

	var obj interface{}
	if err := json.Unmarshal([]byte(data), &obj); err != nil {
		return nil
	}

	extractPoints(obj, prefix, method, &points)
	return points
}

func extractPoints(obj interface{}, prefix string, method string, points *[]InjectionPoint) {
	switch v := obj.(type) {
	case map[string]interface{}:
		for key, val := range v {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			switch val.(type) {
			case map[string]interface{}, []interface{}:
				extractPoints(val, path, method, points)
			default:
				*points = append(*points, InjectionPoint{
					Name:          key,
					Location:      LocJSONBody,
					OriginalValue: fmt.Sprintf("%v", val),
					Method:        method,
					JSONPath:      path,
				})
			}
		}
	case []interface{}:
		for i, val := range v {
			path := fmt.Sprintf("%s[%d]", prefix, i)
			switch val.(type) {
			case map[string]interface{}, []interface{}:
				extractPoints(val, path, method, points)
			default:
				*points = append(*points, InjectionPoint{
					Name:          path,
					Location:      LocJSONBody,
					OriginalValue: fmt.Sprintf("%v", val),
					Method:        method,
					JSONPath:      path,
				})
			}
		}
	}
}

func looksLikeParam(segment string) bool {
	// Numérico
	for _, c := range segment {
		if c < '0' || c > '9' {
			goto notNumeric
		}
	}
	return true
notNumeric:
	// UUID
	if len(segment) == 36 && strings.Count(segment, "-") == 4 {
		return true
	}
	// Hex longo (hash, token)
	if len(segment) >= 16 {
		allHex := true
		for _, c := range segment {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				allHex = false
				break
			}
		}
		if allHex {
			return true
		}
	}
	return false
}

func isStructuralHeader(name string) bool {
	lower := strings.ToLower(name)
	structural := []string{"content-type", "content-length", "host", "connection", "accept-encoding"}
	for _, s := range structural {
		if lower == s {
			return true
		}
	}
	return false
}
