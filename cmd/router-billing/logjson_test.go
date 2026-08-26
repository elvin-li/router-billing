package main

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
)

func TestJSONLogWriterWrapsLine(t *testing.T) {
	var buf bytes.Buffer
	w := &jsonLogWriter{out: &buf, version: "v1.2.3"}

	line := []byte("payment ok order=B-1\n")
	n, err := w.Write(line)
	if err != nil {
		t.Fatal(err)
	}
	// The log package treats a short write as an error, so Write must report
	// len(p) even though the JSON envelope is longer.
	if n != len(line) {
		t.Errorf("Write returned %d, want len(p)=%d", n, len(line))
	}

	var rec map[string]string
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("output is not valid JSON: %v (%q)", err, buf.String())
	}
	if rec["msg"] != "payment ok order=B-1" {
		t.Errorf("msg should have exactly one trailing newline stripped: %q", rec["msg"])
	}
	if rec["svc"] != "router-billing" || rec["ver"] != "v1.2.3" {
		t.Errorf("svc/ver: %+v", rec)
	}
	if rec["ts"] == "" || !strings.HasSuffix(rec["ts"], "Z") {
		t.Errorf("ts should be UTC RFC3339-ish: %q", rec["ts"])
	}
	if !bytes.HasSuffix(buf.Bytes(), []byte("\n")) {
		t.Error("each record must end with a newline for line-based ingestion")
	}
}

func TestJSONLogWriterEscapesSpecials(t *testing.T) {
	var buf bytes.Buffer
	w := &jsonLogWriter{out: &buf, version: "dev"}
	msg := `user "alice" said: {"nested": true}` + "\nsecond line"
	if _, err := w.Write([]byte(msg + "\n")); err != nil {
		t.Fatal(err)
	}
	// Whatever the message contains, the output must stay one valid
	// JSON document per line.
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("embedded newline leaked into output: %d lines", len(lines))
	}
	var rec map[string]string
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("invalid JSON: %v (%q)", err, lines[0])
	}
	if rec["msg"] != msg {
		t.Errorf("msg round-trip failed:\n got  %q\n want %q", rec["msg"], msg)
	}
}

func TestJSONLogWriterThroughLogPackage(t *testing.T) {
	var buf bytes.Buffer
	l := log.New(&jsonLogWriter{out: &buf, version: "dev"}, "", 0)
	l.Printf("hello %d", 42)
	l.Printf("world")

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 records, got %d: %q", len(lines), buf.String())
	}
	for i, want := range []string{"hello 42", "world"} {
		var rec map[string]string
		if err := json.Unmarshal([]byte(lines[i]), &rec); err != nil {
			t.Fatalf("line %d invalid JSON: %v", i, err)
		}
		if rec["msg"] != want {
			t.Errorf("line %d msg = %q, want %q", i, rec["msg"], want)
		}
	}
}

func TestPrintASCIIQRSmoke(t *testing.T) {
	// Encodes a realistic otpauth URL; must not error and must print a
	// square-ish block (visual output goes to stdout — we only assert error).
	if err := printASCIIQR("otpauth://totp/router-billing:admin?secret=JBSWY3DPEHPK3PXP&issuer=router-billing"); err != nil {
		t.Errorf("printASCIIQR: %v", err)
	}
}
