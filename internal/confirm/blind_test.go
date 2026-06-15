package confirm

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/renansj/ryofuzz/internal/engine"
	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestConfirmTimeBased_Positive(t *testing.T) {
	// Server sleeps 2s when it sees SLEEP(5), instant for SLEEP(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		if strings.Contains(q, "SLEEP") && !strings.Contains(q, "SLEEP%280%29") && !strings.Contains(q, "SLEEP(0)") {
			time.Sleep(2 * time.Second)
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cfg := engine.Config{URL: srv.URL + "?id=1", Timeout: 10}
	bc := &BlindConfirmer{Client: &http.Client{Timeout: 10 * time.Second}, Samples: 3, Cfg: cfg}

	payload := mutator.Payload{
		Value:   "' OR SLEEP(5)--",
		Point:   input.InjectionPoint{Name: "id", Location: input.LocQueryParam},
		Module:  "sqli",
		Variant: "time",
	}

	// sleepSec=1 so threshold ~ meanZero + 0 + 800ms; server delays 2000ms which exceeds it
	confirmed, _ := bc.ConfirmTimeBased(cfg, payload, 1)
	if !confirmed {
		t.Fatal("expected time-based to be confirmed")
	}
}

func TestConfirmTimeBased_Negative(t *testing.T) {
	// Server always responds instantly
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cfg := engine.Config{URL: srv.URL + "?id=1", Timeout: 10}
	bc := &BlindConfirmer{Client: &http.Client{Timeout: 10 * time.Second}, Samples: 3, Cfg: cfg}

	payload := mutator.Payload{
		Value:   "' OR SLEEP(5)--",
		Point:   input.InjectionPoint{Name: "id", Location: input.LocQueryParam},
		Module:  "sqli",
		Variant: "time",
	}

	confirmed, _ := bc.ConfirmTimeBased(cfg, payload, 5)
	if confirmed {
		t.Fatal("expected time-based NOT to be confirmed for instant server")
	}
}

func TestConfirmBoolean_Positive(t *testing.T) {
	// Server returns different sized bodies for true vs false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		if strings.Contains(q, "1%27+AND+%271%27%3D%271") || strings.Contains(q, "1'+AND+'1'='1") || strings.Contains(q, "AND+1%3D1") || strings.Contains(q, "AND 1=1") {
			w.Write([]byte(strings.Repeat("A", 200)))
		} else {
			w.Write([]byte("small"))
		}
	}))
	defer srv.Close()

	cfg := engine.Config{URL: srv.URL + "?id=1", Timeout: 10}
	bc := &BlindConfirmer{Client: &http.Client{Timeout: 10 * time.Second}, Samples: 3, Cfg: cfg}

	truePayload := mutator.Payload{
		Value:   "1' AND '1'='1",
		Point:   input.InjectionPoint{Name: "id", Location: input.LocQueryParam},
		Module:  "sqli",
		Variant: "boolean",
	}
	falsePayload := mutator.Payload{
		Value:   "1' AND '1'='2",
		Point:   input.InjectionPoint{Name: "id", Location: input.LocQueryParam},
		Module:  "sqli",
		Variant: "boolean",
	}

	confirmed := bc.ConfirmBoolean(cfg, truePayload, falsePayload)
	if !confirmed {
		t.Fatal("expected boolean to be confirmed")
	}
}

func TestConfirmBoolean_Negative(t *testing.T) {
	// Server returns identical responses
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("same response always"))
	}))
	defer srv.Close()

	cfg := engine.Config{URL: srv.URL + "?id=1", Timeout: 10}
	bc := &BlindConfirmer{Client: &http.Client{Timeout: 10 * time.Second}, Samples: 3, Cfg: cfg}

	truePayload := mutator.Payload{
		Value:   "1' AND '1'='1",
		Point:   input.InjectionPoint{Name: "id", Location: input.LocQueryParam},
		Module:  "sqli",
		Variant: "boolean",
	}
	falsePayload := mutator.Payload{
		Value:   "1' AND '1'='2",
		Point:   input.InjectionPoint{Name: "id", Location: input.LocQueryParam},
		Module:  "sqli",
		Variant: "boolean",
	}

	confirmed := bc.ConfirmBoolean(cfg, truePayload, falsePayload)
	if confirmed {
		t.Fatal("expected boolean NOT to be confirmed for identical responses")
	}
}
