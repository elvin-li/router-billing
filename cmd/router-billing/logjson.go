package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// setupJSONLogger replaces the standard log writer with one that wraps each
// log line as a JSON object: {"ts":"…","msg":"…","svc":"router-billing","ver":"…"}.
// Designed so existing `log.Printf(...)` call sites keep working unchanged.
//
// Format choices:
//   - ts is RFC3339 with microseconds (matches the text format's precision)
//   - msg is the full line minus trailing newline
//   - HTTP access log lines are not specially parsed; consumers can grep msg.
//
// Concurrent log.Printf calls are serialized by the log package's own mutex,
// so we just need to be safe within Write() for partial writes.
func setupJSONLogger(version string) {
	log.SetFlags(0) // we'll provide the timestamp
	log.SetOutput(&jsonLogWriter{
		out:     os.Stderr,
		version: version,
	})
}

type jsonLogWriter struct {
	out     io.Writer
	version string
	mu      sync.Mutex
}

func (w *jsonLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Strip exactly one trailing newline if present (log package adds one).
	msg := strings.TrimSuffix(string(p), "\n")
	rec := map[string]string{
		"ts":  time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"),
		"svc": "router-billing",
		"ver": w.version,
		"msg": msg,
	}
	buf, err := json.Marshal(rec)
	if err != nil {
		return 0, err
	}
	buf = append(buf, '\n')
	if _, err := w.out.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}
