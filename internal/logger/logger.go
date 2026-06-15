package logger

import (
	"encoding/json"
	"os"
	"time"
)

// LogEntry represents a single request/response log line
type LogEntry struct {
	Timestamp      time.Time         `json:"timestamp"`
	Method         string            `json:"method"`
	URL            string            `json:"url"`
	Headers        map[string]string `json:"headers,omitempty"`
	Body           string            `json:"body,omitempty"`
	ResponseStatus int               `json:"response_status"`
	ResponseBody   string            `json:"response_body,omitempty"`
	TimeMs         int64             `json:"time_ms"`
	Payload        string            `json:"payload"`
	Module         string            `json:"module"`
	Point          string            `json:"point"`
}

// ScanLogger writes JSON lines to a file
type ScanLogger struct {
	file    *os.File
	encoder *json.Encoder
}

// NewScanLogger opens a file for append and returns a logger
func NewScanLogger(path string) (*ScanLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &ScanLogger{file: f, encoder: json.NewEncoder(f)}, nil
}

// Log writes one JSON line
func (l *ScanLogger) Log(entry LogEntry) {
	if len(entry.ResponseBody) > 2000 {
		entry.ResponseBody = entry.ResponseBody[:2000]
	}
	l.encoder.Encode(entry)
}

// Close closes the file
func (l *ScanLogger) Close() {
	l.file.Close()
}
