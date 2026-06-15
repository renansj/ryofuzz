package proxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// EndpointRecorder accumulates observed endpoints from intercepted traffic
// and exports them as an OpenAPI 3.0 document for later reuse.
type EndpointRecorder struct {
	mu        sync.Mutex
	endpoints map[string]*ObservedEndpoint // key: METHOD + templated path
	servers   map[string]bool              // observed scheme://host
}

// ObservedEndpoint holds everything learned about one endpoint.
type ObservedEndpoint struct {
	Method       string
	Host         string
	Scheme       string
	RawPath      string              // first observed concrete path
	TemplatePath string              // path with dynamic segments replaced by {param}
	QueryParams  map[string]string   // param name -> sample value
	HeaderParams map[string]string   // non-standard request headers -> sample
	BodyType     string              // application/json, form, etc.
	BodySample   string              // a sanitized sample body
	BodyFields   map[string]string   // for JSON/form: field name -> inferred type
	StatusCodes  map[int]bool        // observed response status codes
	Hits         int                 // how many times seen
}

// uuidRe and numRe detect dynamic path segments to templatize.
var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRe  = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	numRe  = regexp.MustCompile(`^\d+$`)
)

// NewEndpointRecorder creates an empty recorder.
func NewEndpointRecorder() *EndpointRecorder {
	return &EndpointRecorder{
		endpoints: make(map[string]*ObservedEndpoint),
		servers:   make(map[string]bool),
	}
}

// Record ingests one observed request/response pair.
func (er *EndpointRecorder) Record(r *http.Request, reqBody []byte, statusCode int) {
	if r.URL == nil {
		return
	}
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}

	templatePath := templatize(r.URL.Path)
	key := r.Method + " " + templatePath

	er.mu.Lock()
	defer er.mu.Unlock()

	er.servers[scheme+"://"+host] = true

	ep, ok := er.endpoints[key]
	if !ok {
		ep = &ObservedEndpoint{
			Method:       r.Method,
			Host:         host,
			Scheme:       scheme,
			RawPath:      r.URL.Path,
			TemplatePath: templatePath,
			QueryParams:  make(map[string]string),
			HeaderParams: make(map[string]string),
			BodyFields:   make(map[string]string),
			StatusCodes:  make(map[int]bool),
		}
		er.endpoints[key] = ep
	}
	ep.Hits++
	if statusCode > 0 {
		ep.StatusCodes[statusCode] = true
	}

	// Query params
	for name, vals := range r.URL.Query() {
		if len(vals) > 0 {
			ep.QueryParams[name] = vals[0]
		} else {
			ep.QueryParams[name] = ""
		}
	}

	// Interesting request headers (skip standard browser noise)
	for name, vals := range r.Header {
		if isInterestingHeader(name) && len(vals) > 0 {
			ep.HeaderParams[name] = vals[0]
		}
	}

	// Body
	if len(reqBody) > 0 {
		ct := r.Header.Get("Content-Type")
		ep.BodyType = ct
		if strings.Contains(ct, "json") {
			er.recordJSONBody(ep, reqBody)
		} else if strings.Contains(ct, "x-www-form-urlencoded") {
			er.recordFormBody(ep, reqBody)
		}
		if ep.BodySample == "" && len(reqBody) < 2048 {
			ep.BodySample = string(reqBody)
		}
	}
}

func (er *EndpointRecorder) recordJSONBody(ep *ObservedEndpoint, body []byte) {
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return
	}
	for k, v := range obj {
		ep.BodyFields[k] = jsonType(v)
	}
}

func (er *EndpointRecorder) recordFormBody(ep *ObservedEndpoint, body []byte) {
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return
	}
	for k := range vals {
		ep.BodyFields[k] = "string"
	}
}

// Count returns how many distinct endpoints have been recorded.
func (er *EndpointRecorder) Count() int {
	er.mu.Lock()
	defer er.mu.Unlock()
	return len(er.endpoints)
}

// ExportOpenAPI writes an OpenAPI 3.0 document to the given path.
func (er *EndpointRecorder) ExportOpenAPI(path string) error {
	doc := er.buildOpenAPI()
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// buildOpenAPI converts recorded endpoints into an OpenAPI 3.0 structure.
func (er *EndpointRecorder) buildOpenAPI() map[string]interface{} {
	er.mu.Lock()
	defer er.mu.Unlock()

	var servers []map[string]string
	for s := range er.servers {
		servers = append(servers, map[string]string{"url": s})
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i]["url"] < servers[j]["url"] })

	paths := make(map[string]map[string]interface{})

	for _, ep := range er.endpoints {
		method := strings.ToLower(ep.Method)

		var params []map[string]interface{}

		// Path params from templated segments
		for _, seg := range pathParamNames(ep.TemplatePath) {
			params = append(params, map[string]interface{}{
				"name":     seg,
				"in":       "path",
				"required": true,
				"schema":   map[string]string{"type": "string"},
			})
		}

		// Query params
		qNames := sortedKeys(ep.QueryParams)
		for _, name := range qNames {
			params = append(params, map[string]interface{}{
				"name":     name,
				"in":       "query",
				"required": false,
				"schema":   map[string]string{"type": inferType(ep.QueryParams[name])},
				"example":  ep.QueryParams[name],
			})
		}

		// Header params
		hNames := sortedKeys(ep.HeaderParams)
		for _, name := range hNames {
			params = append(params, map[string]interface{}{
				"name":     name,
				"in":       "header",
				"required": false,
				"schema":   map[string]string{"type": "string"},
				"example":  ep.HeaderParams[name],
			})
		}

		operation := map[string]interface{}{
			"summary":     ep.Method + " " + ep.TemplatePath,
			"operationId": operationID(ep.Method, ep.TemplatePath),
			"x-ryofuzz-hits": ep.Hits,
		}
		if len(params) > 0 {
			operation["parameters"] = params
		}

		// Request body
		if len(ep.BodyFields) > 0 {
			props := make(map[string]interface{})
			for field, typ := range ep.BodyFields {
				props[field] = map[string]string{"type": typ}
			}
			mediaType := "application/json"
			if strings.Contains(ep.BodyType, "form") {
				mediaType = "application/x-www-form-urlencoded"
			}
			operation["requestBody"] = map[string]interface{}{
				"content": map[string]interface{}{
					mediaType: map[string]interface{}{
						"schema": map[string]interface{}{
							"type":       "object",
							"properties": props,
						},
					},
				},
			}
		}

		// Responses
		responses := make(map[string]interface{})
		if len(ep.StatusCodes) == 0 {
			responses["default"] = map[string]string{"description": "observed response"}
		} else {
			for code := range ep.StatusCodes {
				responses[strconv.Itoa(code)] = map[string]string{"description": "observed response"}
			}
		}
		operation["responses"] = responses

		if paths[ep.TemplatePath] == nil {
			paths[ep.TemplatePath] = make(map[string]interface{})
		}
		paths[ep.TemplatePath][method] = operation
	}

	doc := map[string]interface{}{
		"openapi": "3.0.0",
		"info": map[string]interface{}{
			"title":       "ryofuzz recon (passive endpoint discovery)",
			"description": "OpenAPI spec auto-generated from intercepted traffic by ryofuzz proxy mode. Reuse with: ryofuzz --openapi file.json",
			"version":     "1.0.0",
		},
		"paths": paths,
	}
	if len(servers) > 0 {
		doc["servers"] = servers
	}
	return doc
}

// templatize replaces dynamic path segments (IDs, UUIDs, hashes) with {param}.
func templatize(path string) string {
	segs := strings.Split(path, "/")
	paramCount := 0
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		if numRe.MatchString(seg) {
			paramCount++
			segs[i] = "{id" + itoaIf(paramCount) + "}"
		} else if uuidRe.MatchString(seg) {
			paramCount++
			segs[i] = "{uuid" + itoaIf(paramCount) + "}"
		} else if hexRe.MatchString(seg) {
			paramCount++
			segs[i] = "{hash" + itoaIf(paramCount) + "}"
		}
	}
	return strings.Join(segs, "/")
}

func itoaIf(n int) string {
	if n <= 1 {
		return ""
	}
	return strconv.Itoa(n)
}

// pathParamNames extracts {param} names from a templated path.
func pathParamNames(tmpl string) []string {
	var names []string
	for _, seg := range strings.Split(tmpl, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			names = append(names, strings.Trim(seg, "{}"))
		}
	}
	return names
}

func operationID(method, path string) string {
	clean := strings.NewReplacer("/", "_", "{", "", "}", "", "-", "_").Replace(path)
	return strings.ToLower(method) + clean
}

// isInterestingHeader filters out standard browser headers, keeping custom/auth ones.
func isInterestingHeader(name string) bool {
	lower := strings.ToLower(name)
	standard := map[string]bool{
		"host": true, "user-agent": true, "accept": true, "accept-encoding": true,
		"accept-language": true, "connection": true, "cache-control": true,
		"upgrade-insecure-requests": true, "sec-fetch-dest": true, "sec-fetch-mode": true,
		"sec-fetch-site": true, "sec-fetch-user": true, "sec-ch-ua": true,
		"sec-ch-ua-mobile": true, "sec-ch-ua-platform": true, "pragma": true,
		"referer": true, "origin": true, "content-length": true, "content-type": true,
		"cookie": true, "dnt": true, "te": true, "proxy-connection": true,
	}
	return !standard[lower]
}

func jsonType(v interface{}) string {
	switch v.(type) {
	case float64:
		return "number"
	case bool:
		return "boolean"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	case nil:
		return "null"
	default:
		return "string"
	}
}

func inferType(val string) string {
	if val == "" {
		return "string"
	}
	if numRe.MatchString(val) {
		return "integer"
	}
	if _, err := strconv.ParseFloat(val, 64); err == nil {
		return "number"
	}
	if val == "true" || val == "false" {
		return "boolean"
	}
	return "string"
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
