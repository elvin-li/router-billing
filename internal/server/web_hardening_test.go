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
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
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

// bigMultipart builds a multipart body that carries a valid _csrf field
// followed by `size` bytes of filler in field `field`.
func bigMultipart(t *testing.T, csrf, field string, size int) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("_csrf", csrf); err != nil {
		t.Fatal(err)
	}
	fw, err := mw.CreateFormFile(field, "filler.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(bytes.Repeat([]byte{'x'}, size)); err != nil {
		t.Fatal(err)
	}
	mw.Close()
	return &buf, mw.FormDataContentType()
}

func doRaw(t *testing.T, h http.Handler, method, path string, body io.Reader, contentType string, cookies map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", contentType)
	for k, v := range cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// TestOversizedMultipartRejectedOnUserEndpoint: before the middleware cap,
// this request was fully parsed (2 MiB spooled by ParseMultipartForm inside
// the CSRF check) and then processed normally (303). Now the cap trips the
// parse, the CSRF token never surfaces, and the request dies with 403 —
// nothing gets buffered to disk beyond the 1 MiB limit.
func TestOversizedMultipartRejectedOnUserEndpoint(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerAndLogin(t, h, "13800130271", "cap-test-pw")

	body, ct := bigMultipart(t, jar[csrfCookieName], "filler", 2<<20)
	rr := doRaw(t, h, "POST", "/user/password", body, ct, jar)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("oversized multipart to /user/password: got %d, want 403", rr.Code)
	}
}

// TestOversizedMultipartRejectedOnAdminEndpoint mirrors the user-side test
// for an admin form endpoint that is NOT the restore upload.
func TestOversizedMultipartRejectedOnAdminEndpoint(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)

	body, ct := bigMultipart(t, jar[csrfCookieName], "filler", 2<<20)
	rr := doRaw(t, h, "POST", "/admin/macs/import", body, ct, jar)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("oversized multipart to /admin/macs/import: got %d, want 403", rr.Code)
	}
}

// TestRestoreUploadExemptFromSmallBodyCap: the DB restore upload is the one
// endpoint that legitimately takes a big body. A 2 MiB upload must sail past
// the generic 1 MiB cap and reach the handler's own validation (which
// rejects the junk payload as not-SQLite → 400, not 403/413).
func TestRestoreUploadExemptFromSmallBodyCap(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)

	body, ct := bigMultipart(t, jar[csrfCookieName], "backup", 2<<20)
	rr := doRaw(t, h, "POST", "/admin/backup/restore", body, ct, jar)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("2MiB junk restore upload: got %d, want 400 (validation), not a size/CSRF rejection", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "SQLite") && !strings.Contains(rr.Body.String(), "magic") {
		t.Errorf("restore rejection should come from SQLite validation; body=%q", rr.Body.String())
	}
}
