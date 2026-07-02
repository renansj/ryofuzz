package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newLabServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<a href="/products?id=1">products</a>
			<a href="/about">about</a>
		</body></html>`))
	})
	mux.HandleFunc("/products", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/detail?pid=9">detail</a></body></html>`))
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>about page</body></html>`))
	})
	mux.HandleFunc("/detail", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>detail</body></html>`))
	})
	return httptest.NewServer(mux)
}

func TestCrawlDiscoversLinks(t *testing.T) {
	srv := newLabServer()
	defer srv.Close()

	res, err := Crawl(CrawlConfig{
		SeedURL:      srv.URL + "/",
		MaxDepth:     3,
		Concurrency:  4,
		Timeout:      5,
		IgnoreRobots: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	all := ""
	for _, u := range res.URLs {
		all += u.URL + "\n"
	}
	if !strings.Contains(all, "/products") {
		t.Errorf("expected crawler to discover /products, got:\n%s", all)
	}
	if !strings.Contains(all, "/about") {
		t.Errorf("expected crawler to discover /about, got:\n%s", all)
	}
}

func TestCrawlContextCancel(t *testing.T) {
	// Slow server so cancellation happens mid-crawl.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/a?x=1">a</a><a href="/b?y=2">b</a><a href="/c?z=3">c</a>`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := CrawlContext(ctx, CrawlConfig{
		SeedURL: srv.URL + "/", MaxDepth: 5, Concurrency: 2, Timeout: 5, IgnoreRobots: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return promptly after cancellation, not hang.
	if time.Since(start) > 3*time.Second {
		t.Errorf("crawl did not stop promptly on cancel: %v", time.Since(start))
	}
}
