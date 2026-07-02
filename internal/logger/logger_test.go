package logger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanLoggerWritesJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.jsonl")

	lg, err := NewScanLogger(path)
	if err != nil {
		t.Fatalf("NewScanLogger: %v", err)
	}
	lg.Log(LogEntry{Method: "GET", URL: "http://t/a", Module: "sqli", ResponseStatus: 200})
	lg.Log(LogEntry{Method: "POST", URL: "http://t/b", Module: "xss", ResponseStatus: 500})
	lg.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()

	var lines int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines++
		var e LogEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Errorf("line %d is not valid JSON: %v", lines, err)
		}
	}
	if lines != 2 {
		t.Errorf("expected 2 log lines, got %d", lines)
	}
}

func TestScanLoggerTruncatesLongBody(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.jsonl")
	lg, _ := NewScanLogger(path)
	lg.Log(LogEntry{ResponseBody: strings.Repeat("A", 5000)})
	lg.Close()

	data, _ := os.ReadFile(path)
	var e LogEntry
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(e.ResponseBody) > 2000 {
		t.Errorf("expected body truncated to 2000, got %d", len(e.ResponseBody))
	}
}

func TestScanLoggerAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.jsonl")
	lg1, _ := NewScanLogger(path)
	lg1.Log(LogEntry{Module: "a"})
	lg1.Close()
	// Reopen: should append, not truncate.
	lg2, _ := NewScanLogger(path)
	lg2.Log(LogEntry{Module: "b"})
	lg2.Close()

	data, _ := os.ReadFile(path)
	if strings.Count(string(data), "\n") != 2 {
		t.Errorf("expected 2 appended lines, got %q", string(data))
	}
}
