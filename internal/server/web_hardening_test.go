package server

// Regression tests for the v0.112 web-handler hardening pass:
//
//  1. The site ships CSP `script-src 'self'` (no 'unsafe-inline'), which
//     makes browsers refuse inline <script> blocks and on*="" attributes.
//     Templates historically used both, so every confirm() guard on a
//     destructive admin action silently never ran, the orders-page refund
//     button did nothing, the /admin/macs bulk bar was dead, the portal
//     service worker never registered, etc. All behavior now lives in
//     /static/*.js keyed off data-* attributes; these tests pin that.
//
//  2. verifyCSRF parses the form (via r.FormValue) BEFORE any handler-level
//     http.MaxBytesReader could apply, and ParseMultipartForm has no
//     total-size limit of its own — so any client could stream an unbounded
//     multipart body at a form endpoint (spooled to temp files → disk-full
//     on a router). csrfMiddleware now caps bodies at 1 MiB, with the DB
//     restore upload keeping its advertised 256 MiB.
//
//  3. /admin/vouchers/print/qr served PNGs of live voucher codes with
//     Cache-Control: public.

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// stripTplComments removes {{/* ... */}} template comments so scanner
// regexes don't trip on prose that mentions "<script>" or "on*=".
var tplCommentRe = regexp.MustCompile(`(?s)\{\{-?/\*.*?\*/-?\}\}`)

// inlineHandlerRe matches on*="" attributes (onclick=, onsubmit=, ...).
var inlineHandlerRe = regexp.MustCompile(`\son[a-z]+\s*=`)

// scriptTagRe captures each opening <script ...> tag for src inspection.
var scriptTagRe = regexp.MustCompile(`(?i)<script\b[^>]*>`)

// staticSrcRe captures /static/*.js references so we can verify the files
// actually exist (a typo'd src would silently reintroduce the dead-button
// problem this pass fixed).
var staticSrcRe = regexp.MustCompile(`src="/static/([^"]+\.js)"`)

func TestTemplatesAreCSPCompatible(t *testing.T) {
	root := webRoot(t)
	tplDir := filepath.Join(root, "templates")
	staticDir := filepath.Join(root, "static")

	entries, err := os.ReadDir(tplDir)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(tplDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		src := tplCommentRe.ReplaceAllString(string(raw), "")

		// Every <script> must load from src — CSP blocks inline bodies.
		for _, tag := range scriptTagRe.FindAllString(src, -1) {
			if !strings.Contains(tag, "src=") {
				t.Errorf("%s: inline <script> block (%q) — blocked by CSP script-src 'self'", e.Name(), tag)
			}
		}
		// No inline event handlers — CSP blocks those too.
		if m := inlineHandlerRe.FindString(src); m != "" {
			t.Errorf("%s: inline event handler %q — blocked by CSP script-src 'self'; use data-* + ui.js", e.Name(), strings.TrimSpace(m))
		}
		// Every referenced static script must exist on disk.
		for _, m := range staticSrcRe.FindAllStringSubmatch(src, -1) {
			if _, err := os.Stat(filepath.Join(staticDir, m[1])); err != nil {
				t.Errorf("%s: references /static/%s which does not exist", e.Name(), m[1])
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no templates scanned")
	}

	// The static JS that injects markup (devices SSE stream) must not smuggle
	// inline handlers back in through innerHTML — those are blocked the same
	// way as template ones.
	jsFiles, err := filepath.Glob(filepath.Join(staticDir, "*.js"))
	if err != nil {
		t.Fatal(err)
	}
	genHandlerRe := regexp.MustCompile(`[\s<]on[a-z]+="`)
	for _, f := range jsFiles {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := genHandlerRe.FindString(string(raw)); m != "" {
			t.Errorf("%s: generates inline handler %q — blocked by CSP; use data-* + ui.js delegation", filepath.Base(f), m)
		}
	}
}

// TestConfirmGuardsSurviveAsDataAttributes renders a destructive-action page
// end-to-end and checks the confirmation prompt made it into the CSP-safe
// data-confirm shape (rather than being dropped along with onsubmit).
func TestConfirmGuardsSurviveAsDataAttributes(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:00:99", "csp-test", 30, nil); err != nil {
		t.Fatal(err)
	}
	h := app.Routes()
	jar := loginAdmin(t, h)

	res, body := do(t, h, "GET", "/admin/macs", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("/admin/macs: %d", res.StatusCode)
	}
	if !strings.Contains(body, `data-confirm="删除 AA:BB:CC:DD:00:99?"`) {
		t.Error("delete form lost its confirmation guard (data-confirm missing)")
	}
	if !strings.Contains(body, `/static/admin-macs.js`) || !strings.Contains(body, `/static/ui.js`) {
		t.Error("/admin/macs must load ui.js + admin-macs.js (bulk bar / confirm guards)")
	}
	if strings.Contains(body, "onsubmit=") || strings.Contains(body, "onclick=") {
		t.Error("/admin/macs still renders inline handlers (CSP blocks them)")
	}
}

